import shellquote from 'shell-quote'
import { logForDebugging } from '../utils/debug.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  getMandatoryDenyWithinAllow,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import {
  generateSeccompFilter,
  cleanupSeccompFilter,
  hasSeccompDependenciesSync,
  hasPython3Sync,
  getApplySeccompExecPath,
} from './generate-seccomp-filter.js'

export interface LinuxNetworkBridgeContext {
  httpSocketPath: string
  socksSocketPath: string
  httpBridgeProcess: ChildProcess
  socksBridgeProcess: ChildProcess
  httpProxyPort: number
  socksProxyPort: number
}

export interface LinuxSandboxParams {
  command: string
  hasNetworkRestrictions: boolean
  hasFilesystemRestrictions: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  enableWeakerNestedSandbox?: boolean
  allowAllUnixSockets?: boolean
}

// Track generated seccomp filters for cleanup on process exit
const generatedSeccompFilters: Set<string> = new Set()
let exitHandlerRegistered = false

/**
 * Register cleanup handler for generated seccomp filters
 */
function registerSeccompCleanupHandler(): void {
  if (exitHandlerRegistered) {
    return
  }

  process.on('exit', () => {
    for (const filterPath of generatedSeccompFilters) {
      try {
        cleanupSeccompFilter(filterPath)
      } catch {
        // Ignore cleanup errors during exit
      }
    }
  })

  exitHandlerRegistered = true
}

/**
 * Check if Linux sandbox dependencies are available (synchronous)
 * Returns true if bwrap, socat, and python3 are installed.
 * Unless allowAllUnixSockets is enabled, also requires seccomp dependencies
 * (gcc/clang and libseccomp-dev for non-x64/arm64 architectures).
 */
export function hasLinuxSandboxDependenciesSync(allowAllUnixSockets = false): boolean {
  try {
    const bwrapResult = spawnSync('which', ['bwrap'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    const socatResult = spawnSync('which', ['socat'], {
      stdio: 'ignore',
      timeout: 1000,
    })

    const hasBasicDeps = bwrapResult.status === 0 && socatResult.status === 0

    // Python 3 is required for applying seccomp filters (unless Unix socket blocking is disabled)
    if (!allowAllUnixSockets && !hasPython3Sync()) {
      return false
    }

    // Also require seccomp dependencies unless allowAllUnixSockets is enabled
    // Note: On x64/arm64, pre-generated BPF filters are available, so gcc/clang are not required
    if (!allowAllUnixSockets) {
      return hasBasicDeps && hasSeccompDependenciesSync()
    }

    return hasBasicDeps
  } catch {
    return false
  }
}

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
export async function initializeLinuxNetworkBridge(
  httpProxyPort: number,
  socksProxyPort: number,
): Promise<LinuxNetworkBridgeContext> {
  const socketId = randomBytes(8).toString('hex')
  const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`)
  const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`)

  // Start HTTP bridge
  const httpSocatArgs = [
    `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
    `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting HTTP bridge: socat ${httpSocatArgs.join(' ')}`)

  const httpBridgeProcess = spawn('socat', httpSocatArgs, {
    stdio: 'ignore',
  })

  if (!httpBridgeProcess.pid) {
    throw new Error('Failed to start HTTP bridge process')
  }

  // Start SOCKS bridge
  const socksSocatArgs = [
    `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
    `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting SOCKS bridge: socat ${socksSocatArgs.join(' ')}`)

  const socksBridgeProcess = spawn('socat', socksSocatArgs, {
    stdio: 'ignore',
  })

  if (!socksBridgeProcess.pid) {
    // Clean up HTTP bridge
    if (httpBridgeProcess.pid) {
      try {
        process.kill(httpBridgeProcess.pid, 'SIGTERM')
      } catch {
        // Ignore errors
      }
    }
    throw new Error('Failed to start SOCKS bridge process')
  }

  // Wait for both sockets to be ready
  const maxAttempts = 5
  for (let i = 0; i < maxAttempts; i++) {
    if (
      !httpBridgeProcess.pid ||
      httpBridgeProcess.killed ||
      !socksBridgeProcess.pid ||
      socksBridgeProcess.killed
    ) {
      throw new Error('Linux bridge process died unexpectedly')
    }

    try {
      // fs already imported
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSocketPath)) {
        logForDebugging(`Linux bridges ready after ${i + 1} attempts`)
        break
      }
    } catch (err) {
      logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
        level: 'error',
      })
    }

    if (i === maxAttempts - 1) {
      // Clean up both processes
      if (httpBridgeProcess.pid) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      if (socksBridgeProcess.pid) {
        try {
          process.kill(socksBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      throw new Error(
        `Failed to create bridge sockets after ${maxAttempts} attempts`,
      )
    }

    await new Promise(resolve => setTimeout(resolve, i * 100))
  }

  return {
    httpSocketPath,
    socksSocketPath,
    httpBridgeProcess,
    socksBridgeProcess,
    httpProxyPort,
    socksProxyPort,
  }
}

/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 *
 * If seccomp parameters are provided, uses two-stage filtering:
 * 1. Start socat processes (without seccomp filter - they need Unix sockets)
 * 2. Apply seccomp filter using Python script (apply-seccomp-and-exec.py)
 * 3. Exec user command (with seccomp filter active)
 */
function buildSandboxCommand(
  httpSocketPath: string,
  socksSocketPath: string,
  userCommand: string,
  seccompFilterPath?: string,
): string {
  const socatCommands = [
    `socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
    `socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
  ]

  // If seccomp filter is provided, use Python script to apply it
  if (seccompFilterPath) {
    // Two-stage approach:
    // 1. Outer bwrap starts socat processes (can use Unix sockets)
    // 2. Python script applies seccomp filter via prctl and execs user command
    // 3. User command runs with seccomp active (Unix sockets blocked)
    //
    // Get the path to the apply-seccomp Python script
    const applySeccompScript = getApplySeccompExecPath()
    if (!applySeccompScript) {
      // Fail fast - seccomp filtering is required for security when enabled
      throw new Error(
        'Failed to get apply-seccomp-and-exec.py script. ' +
          'Python 3 is required for applying seccomp filters but is not available on this system. ' +
          'Please install Python 3 (e.g., "apt-get install python3" on Ubuntu/Debian). ' +
          'To disable Unix socket blocking entirely, set allowAllUnixSockets: true in your configuration.',
      )
    }

    // Build command: python3 apply-seccomp-and-exec.py <filterPath> -- <userCommand>
    const applySeccompCmd = shellquote.quote([
      'python3',
      applySeccompScript,
      seccompFilterPath,
      '--',
      'bash',
      '-c',
      userCommand,
    ])

    const innerScript = [...socatCommands, applySeccompCmd].join('\n')
    return `bash -c ${shellquote.quote([innerScript])}`
  } else {
    // No seccomp filter - run user command directly
    const innerScript = [
      ...socatCommands,
      `eval ${shellquote.quote([userCommand])}`,
    ].join('\n')

    return `bash -c ${shellquote.quote([innerScript])}`
  }
}

/**
 * Generate filesystem bind mount arguments for bwrap
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
): Promise<string[]> {
  const args: string[] = []
  // fs already imported

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')

    // Collect normalized allowed write paths for later checking
    const allowedWritePaths: string[] = []

    // Allow writes to specific paths
    for (const pathPattern of writeConfig.allowOnly || []) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      logForDebugging(
        `[Sandbox Linux] Processing write path: ${pathPattern} -> ${normalizedPath}`,
      )

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        logForDebugging(`[Sandbox Linux] Skipping /dev path: ${normalizedPath}`)
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent write path: ${normalizedPath}`,
        )
        continue
      }

      args.push('--bind', normalizedPath, normalizedPath)
      allowedWritePaths.push(normalizedPath)
    }

    // Deny writes within allowed paths (user-specified + mandatory denies)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await getMandatoryDenyWithinAllow()),
    ]

    for (const pathPattern of denyPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      // Skip non-existent paths
      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent deny path: ${normalizedPath}`,
        )
        continue
      }

      // Only add deny binding if this path is within an allowed write path
      // Otherwise it's already read-only from the initial --ro-bind / /
      const isWithinAllowedPath = allowedWritePaths.some(
        allowedPath =>
          normalizedPath.startsWith(allowedPath + '/') ||
          normalizedPath === allowedPath,
      )

      if (isWithinAllowedPath) {
        args.push('--ro-bind', normalizedPath, normalizedPath)
      } else {
        logForDebugging(
          `[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`,
        )
      }
    }
  } else {
    // No write restrictions: Allow all writes
    args.push('--bind', '/', '/')
  }

  // Handle read restrictions by mounting tmpfs over denied paths
  const readDenyPaths = [...(readConfig?.denyOnly || [])]

  // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
  // SSH is very strict about config file permissions and ownership, and they can
  // appear wrong inside the sandbox causing "Bad owner or permissions" errors
  if (fs.existsSync('/etc/ssh/ssh_config.d')) {
    readDenyPaths.push('/etc/ssh/ssh_config.d')
  }

  for (const pathPattern of readDenyPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern)
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`,
      )
      continue
    }

    const readDenyStat = fs.statSync(normalizedPath)
    if (readDenyStat.isDirectory()) {
      args.push('--tmpfs', normalizedPath)
    } else {
      // For files, bind /dev/null instead of tmpfs
      args.push('--ro-bind', '/dev/null', normalizedPath)
    }
  }

  return args
}

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (TWO-STAGE SECCOMP):
 * This implementation uses a two-stage seccomp approach to block Unix domain socket
 * creation for user commands while allowing network infrastructure to function:
 *
 * Stage 1: Network infrastructure setup (NO seccomp filter)
 *   - Bubblewrap starts with isolated network namespace (--unshare-net)
 *   - Bubblewrap applies PID namespace isolation (--unshare-pid and --proc)
 *   - Socat processes start and connect to Unix socket bridges
 *   - These bridges forward traffic to the host's proxy servers
 *
 * Stage 2: User command execution (WITH seccomp filter)
 *   - Python script (apply-seccomp-and-exec.py) applies the BPF filter using prctl
 *   - Python script execs the user command with seccomp filter active
 *   - User command inherits all sandbox restrictions from bwrap
 *   - User command cannot create Unix sockets
 *
 * This solves the conflict between:
 * - Security: Blocking arbitrary Unix socket access
 * - Functionality: Network sandboxing requires Unix sockets for the proxy bridge
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is still not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory. However, the two-stage
 * approach allows network functionality to work alongside Unix socket creation blocking.
 *
 * Requirements for seccomp filtering:
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Python 3 with ctypes (standard library) for applying the filter
 * - For other architectures: gcc or clang + libseccomp-dev for runtime BPF compilation
 * Dependencies are checked by hasLinuxSandboxDependenciesSync() before enabling the sandbox.
 */
export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  const {
    command,
    hasNetworkRestrictions,
    hasFilesystemRestrictions,
    httpSocketPath,
    socksSocketPath,
    httpProxyPort,
    socksProxyPort,
    readConfig,
    writeConfig,
    enableWeakerNestedSandbox,
    allowAllUnixSockets,
  } = params

  // Check if we need any sandboxing
  if (!hasNetworkRestrictions && !hasFilesystemRestrictions) {
    return command
  }

  const bwrapArgs: string[] = []
  let seccompFilterPath: string | undefined = undefined

  try {
    // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
    // Two-stage seccomp approach for network sandboxing using Python helper script:
    // 1. Generate the BPF filter that blocks Unix sockets
    // 2. Outer bwrap: starts socat processes (need Unix sockets for bridging)
    // 3. Python script: applies seccomp filter via prctl and execs user command
    // 4. User command runs with seccomp active (Unix sockets blocked)
    //
    // This allows network infrastructure to use Unix sockets while blocking them for user commands.
    //
    // NOTE: Seccomp filtering is only enabled when allowAllUnixSockets is false
    // (when true, Unix sockets are allowed)
    if (!allowAllUnixSockets) {
      seccompFilterPath = generateSeccompFilter() ?? undefined
      if (!seccompFilterPath) {
        // Fail loudly - seccomp filtering is required for security
        throw new Error(
          'Failed to generate seccomp filter for Unix socket blocking. ' +
            'This may occur on unsupported architectures or when required dependencies are unavailable. ' +
            'Required: Python 3 with ctypes (standard library), and for non-x64/arm64 architectures: gcc/clang + libseccomp-dev. ' +
            'To disable Unix socket blocking, set allowAllUnixSockets: true in your configuration.',
        )
      }

      // Track filter for cleanup and register exit handler
      // Only track runtime-generated filters (not pre-generated ones from vendor/)
      if (!seccompFilterPath.includes('/vendor/seccomp/')) {
        generatedSeccompFilters.add(seccompFilterPath)
        registerSeccompCleanupHandler()
      }

      logForDebugging(
        '[Sandbox Linux] Generated seccomp BPF filter for Unix socket blocking',
      )
    } else if (allowAllUnixSockets) {
      logForDebugging(
        '[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled',
      )
    }

    // By default, always unshare PID namespace and mount fresh /proc.
    // If we don't have --unshare-pid, it is possible to escape the sandbox.
    // If we don't have --proc, it is possible to read host /proc and leak information about code running
    // outside the sandbox. But, --proc is not available when running in unprivileged docker containers
    // so we support running without it if explicitly requested.
    bwrapArgs.push('--unshare-pid')
    if (!enableWeakerNestedSandbox) {
      // Mount fresh /proc if PID namespace is isolated (secure mode)
      bwrapArgs.push('--proc', '/proc')
    }

    // ========== NETWORK RESTRICTIONS ==========
    if (hasNetworkRestrictions) {
      // Only sandbox if we have network config and Linux bridges
      if (!httpSocketPath || !socksSocketPath) {
        throw new Error(
          'Linux network sandboxing was requested but bridge socket paths are not available',
        )
      }

      bwrapArgs.push('--unshare-net')

      // Bind both sockets into the sandbox
      bwrapArgs.push('--bind', httpSocketPath, httpSocketPath)
      bwrapArgs.push('--bind', socksSocketPath, socksSocketPath)

      // Add proxy environment variables
      // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
      // which forwards to the Unix socket that bridges to the host's proxy server
      const proxyEnv = generateProxyEnvVars(
        3128, // Internal HTTP listener port
        1080, // Internal SOCKS listener port
      )
      bwrapArgs.push(
        ...proxyEnv.flatMap((env: string) => {
          const firstEq = env.indexOf('=')
          const key = env.slice(0, firstEq)
          const value = env.slice(firstEq + 1)
          return ['--setenv', key, value]
        }),
      )

      // Add host proxy port environment variables for debugging/transparency
      // These show which host ports the Unix socket bridges connect to
      if (httpProxyPort !== undefined) {
        bwrapArgs.push(
          '--setenv',
          'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
          String(httpProxyPort),
        )
      }
      if (socksProxyPort !== undefined) {
        bwrapArgs.push(
          '--setenv',
          'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
          String(socksProxyPort),
        )
      }
    }

    // ========== FILESYSTEM RESTRICTIONS ==========
    const fsArgs = await generateFilesystemArgs(readConfig, writeConfig)
    bwrapArgs.push(...fsArgs)

    // Always bind /dev
    bwrapArgs.push('--dev', '/dev')

    // ========== COMMAND ==========
    bwrapArgs.push('--', 'bash', '-c')

    // If we have network restrictions, use the network bridge setup with two-stage seccomp
    // Otherwise, just run the command directly
    if (hasNetworkRestrictions && httpSocketPath && socksSocketPath) {
      // Pass seccomp filter to buildSandboxCommand for Python script application
      bwrapArgs.push(
        buildSandboxCommand(
          httpSocketPath,
          socksSocketPath,
          command,
          seccompFilterPath,
        ),
      )
    } else {
      bwrapArgs.push(command)
    }

    const wrappedCommand = shellquote.quote(['bwrap', ...bwrapArgs])

    const restrictions = []
    if (hasNetworkRestrictions) restrictions.push('network')
    if (hasFilesystemRestrictions) restrictions.push('filesystem')
    if (seccompFilterPath) restrictions.push('seccomp(unix-block)')

    logForDebugging(
      `[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)`,
    )

    return wrappedCommand
  } catch (error) {
    // Clean up seccomp filter on error
    if (seccompFilterPath && !seccompFilterPath.includes('/vendor/seccomp/')) {
      generatedSeccompFilters.delete(seccompFilterPath)
      try {
        cleanupSeccompFilter(seccompFilterPath)
      } catch (cleanupError) {
        logForDebugging(
          `[Sandbox Linux] Failed to clean up seccomp filter on error: ${cleanupError}`,
          { level: 'error' },
        )
      }
    }
    // Re-throw the original error
    throw error
  }
}
