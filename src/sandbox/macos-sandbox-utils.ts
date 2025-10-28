import shellquote from 'shell-quote'
import { spawn } from 'child_process'
import { logForDebugging } from '../utils/debug.js'
import { hasRipgrepSync } from '../utils/ripgrep.js'
import {
  normalizePathForSandbox,
  generateProxyEnvVars,
  getMandatoryDenyWithinAllow,
  encodeSandboxedCommand,
  decodeSandboxedCommand,
  containsGlobChars,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import type { IgnoreViolationsConfig } from './sandbox-config.js'

/**
 * Check if macOS sandbox dependencies are available (synchronous)
 * Returns true if rg (ripgrep) is installed, false otherwise
 * Cached to avoid repeated system calls
 */
export function hasMacOSSandboxDependenciesSync(): boolean {
  return hasRipgrepSync()
}

export interface MacOSSandboxParams {
  command: string
  httpProxyPort?: number
  socksProxyPort?: number
  needsNetworkRestriction: boolean
  allowUnixSockets?: string[]
  allowAllUnixSockets?: boolean
  allowLocalBinding?: boolean
  readConfig: FsReadRestrictionConfig | undefined
  writeConfig: FsWriteRestrictionConfig | undefined
  ignoreViolations?: IgnoreViolationsConfig | undefined
}

export interface SandboxViolationEvent {
  line: string
  command?: string
  encodedCommand?: string
  timestamp: Date
}

export type SandboxViolationCallback = (
  violation: SandboxViolationEvent,
) => void

const sessionSuffix = `_${Math.random().toString(36).slice(2, 11)}_SBX`

/**
 * Convert a glob pattern to a regular expression for macOS sandbox profiles
 *
 * This implements gitignore-style pattern matching to match the behavior of the
 * `ignore` library used by the permission system/
 *
 * Supported patterns:
 * - * matches any characters except / (e.g., *.ts matches foo.ts but not foo/bar.ts)
 * - ** matches any characters including / (e.g., src/** /*.ts matches all .ts files in src/)
 * - ? matches any single character except / (e.g., file?.txt matches file1.txt)
 * - [abc] matches any character in the set (e.g., file[0-9].txt matches file3.txt)
 *
 * Note: This is designed for macOS sandbox (regex ...) syntax. The resulting regex
 * will be used in sandbox profiles like: (deny file-write* (regex "pattern"))
 *
 * Exported for testing purposes.
 */
export function globToRegex(globPattern: string): string {
  return (
    '^' +
    globPattern
      // Escape regex special characters (except glob chars * ? [ ])
      .replace(/[.^$+{}()|\\]/g, '\\$&')
      // Escape unclosed brackets (no matching ])
      .replace(/\[([^\]]*?)$/g, '\\[$1')
      // Convert glob patterns to regex (order matters - ** before *)
      .replace(/\*\*\//g, '__GLOBSTAR_SLASH__') // Placeholder for **/
      .replace(/\*\*/g, '__GLOBSTAR__') // Placeholder for **
      .replace(/\*/g, '[^/]*') // * matches anything except /
      .replace(/\?/g, '[^/]') // ? matches single character except /
      // Restore placeholders
      .replace(/__GLOBSTAR_SLASH__/g, '(.*/)?') // **/ matches zero or more dirs
      .replace(/__GLOBSTAR__/g, '.*') + // ** matches anything including /
    '$'
  )
}

/**
 * Generate a unique log tag for sandbox monitoring
 * @param command - The command being executed (will be base64 encoded)
 */
function generateLogTag(command: string): string {
  const encodedCommand = encodeSandboxedCommand(command)
  return `CMD64_${encodedCommand}_END_${sessionSuffix}`
}

/**
 * Generate filesystem read rules for sandbox profile
 */
function generateReadRules(
  config: FsReadRestrictionConfig | undefined,
  logTag: string,
): string[] {
  if (!config) {
    return [`(allow file-read*)`]
  }

  const rules: string[] = []

  // Start by allowing everything
  rules.push(`(allow file-read*)`)

  // Then deny specific paths
  for (const pathPattern of config.denyOnly || []) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(deny file-read*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      // Use subpath matching for literal paths
      rules.push(
        `(deny file-read*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  return rules
}

/**
 * Generate filesystem write rules for sandbox profile
 */
async function generateWriteRules(
  config: FsWriteRestrictionConfig | undefined,
  logTag: string,
): Promise<string[]> {
  if (!config) {
    return [`(allow file-write*)`]
  }

  const rules: string[] = []

  // Automatically allow TMPDIR parent on macOS when write restrictions are enabled
  const tmpdirParents = getTmpdirParentIfMacOSPattern()
  for (const tmpdirParent of tmpdirParents) {
    const normalizedPath = normalizePathForSandbox(tmpdirParent)
    rules.push(
      `(allow file-write*`,
      `  (subpath ${escapePath(normalizedPath)})`,
      `  (with message "${logTag}"))`,
    )
  }

  // Generate allow rules
  for (const pathPattern of config.allowOnly || []) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(allow file-write*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      // Use subpath matching for literal paths
      rules.push(
        `(allow file-write*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  // Combine user-specified and mandatory deny rules
  const denyPaths = [
    ...(config.denyWithinAllow || []),
    ...(await getMandatoryDenyWithinAllow()),
  ]

  for (const pathPattern of denyPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(deny file-write*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      // Use subpath matching for literal paths
      rules.push(
        `(deny file-write*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  return rules
}

/**
 * Generate complete sandbox profile
 */
async function generateSandboxProfile({
  readConfig,
  writeConfig,
  httpProxyPort,
  socksProxyPort,
  needsNetworkRestriction,
  allowUnixSockets,
  allowAllUnixSockets,
  allowLocalBinding,
  logTag,
}: {
  readConfig: FsReadRestrictionConfig | undefined
  writeConfig: FsWriteRestrictionConfig | undefined
  httpProxyPort?: number
  socksProxyPort?: number
  needsNetworkRestriction: boolean
  allowUnixSockets?: string[]
  allowAllUnixSockets?: boolean
  allowLocalBinding?: boolean
  logTag: string
}): Promise<string> {
  const profile: string[] = [
    '(version 1)',
    `(deny default (with message "${logTag}"))`,
    '',
    `; LogTag: ${logTag}`,
    '',
    '; Essential permissions - based on Chrome sandbox policy',
    '; Process permissions',
    '(allow process-exec)',
    '(allow process-fork)',
    '(allow process-info* (target same-sandbox))',
    '(allow signal (target same-sandbox))',
    '(allow mach-priv-task-port (target same-sandbox))',
    '',
    '; User preferences',
    '(allow user-preference-read)',
    '',
    '; Mach IPC - specific services only (no wildcard)',
    '(allow mach-lookup',
    '  (global-name "com.apple.audio.systemsoundserver")',
    '  (global-name "com.apple.distributed_notifications@Uv3")',
    '  (global-name "com.apple.FontObjectsServer")',
    '  (global-name "com.apple.fonts")',
    '  (global-name "com.apple.logd")',
    '  (global-name "com.apple.lsd.mapdb")',
    '  (global-name "com.apple.PowerManagement.control")',
    '  (global-name "com.apple.system.logger")',
    '  (global-name "com.apple.system.notification_center")',
    '  (global-name "com.apple.trustd.agent")',
    '  (global-name "com.apple.system.opendirectoryd.libinfo")',
    '  (global-name "com.apple.system.opendirectoryd.membership")',
    '  (global-name "com.apple.bsd.dirhelper")',
    '  (global-name "com.apple.securityd.xpc")',
    '  (global-name "com.apple.SystemConfiguration.configd")',
    '  (global-name "com.apple.coreservices.launchservicesd")',
    ')',
    '',
    '; POSIX IPC - shared memory',
    '(allow ipc-posix-shm)',
    '',
    '; POSIX IPC - semaphores for Python multiprocessing',
    '(allow ipc-posix-sem)',
    '',
    '; IOKit - specific operations only',
    '(allow iokit-open',
    '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
    '  (iokit-registry-entry-class "RootDomainUserClient")',
    '  (iokit-user-client-class "IOSurfaceSendRight")',
    ')',
    '',
    '; IOKit properties',
    '(allow iokit-get-properties)',
    '',
    "; Specific safe system-sockets, doesn't allow network access",
    '(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))',
    '',
    '; sysctl - specific sysctls only',
    '(allow sysctl-read',
    '  (sysctl-name "hw.activecpu")',
    '  (sysctl-name "hw.busfrequency_compat")',
    '  (sysctl-name "hw.byteorder")',
    '  (sysctl-name "hw.cacheconfig")',
    '  (sysctl-name "hw.cachelinesize_compat")',
    '  (sysctl-name "hw.cpufamily")',
    '  (sysctl-name "hw.cpufrequency")',
    '  (sysctl-name "hw.cpufrequency_compat")',
    '  (sysctl-name "hw.cputype")',
    '  (sysctl-name "hw.l1dcachesize_compat")',
    '  (sysctl-name "hw.l1icachesize_compat")',
    '  (sysctl-name "hw.l2cachesize_compat")',
    '  (sysctl-name "hw.l3cachesize_compat")',
    '  (sysctl-name "hw.logicalcpu")',
    '  (sysctl-name "hw.logicalcpu_max")',
    '  (sysctl-name "hw.machine")',
    '  (sysctl-name "hw.memsize")',
    '  (sysctl-name "hw.ncpu")',
    '  (sysctl-name "hw.nperflevels")',
    '  (sysctl-name "hw.packages")',
    '  (sysctl-name "hw.pagesize_compat")',
    '  (sysctl-name "hw.pagesize")',
    '  (sysctl-name "hw.physicalcpu")',
    '  (sysctl-name "hw.physicalcpu_max")',
    '  (sysctl-name "hw.tbfrequency_compat")',
    '  (sysctl-name "hw.vectorunit")',
    '  (sysctl-name "kern.argmax")',
    '  (sysctl-name "kern.bootargs")',
    '  (sysctl-name "kern.hostname")',
    '  (sysctl-name "kern.maxfiles")',
    '  (sysctl-name "kern.maxfilesperproc")',
    '  (sysctl-name "kern.maxproc")',
    '  (sysctl-name "kern.ngroups")',
    '  (sysctl-name "kern.osproductversion")',
    '  (sysctl-name "kern.osrelease")',
    '  (sysctl-name "kern.ostype")',
    '  (sysctl-name "kern.osvariant_status")',
    '  (sysctl-name "kern.osversion")',
    '  (sysctl-name "kern.secure_kernel")',
    '  (sysctl-name "kern.tcsm_available")',
    '  (sysctl-name "kern.tcsm_enable")',
    '  (sysctl-name "kern.usrstack64")',
    '  (sysctl-name "kern.version")',
    '  (sysctl-name "kern.willshutdown")',
    '  (sysctl-name "machdep.cpu.brand_string")',
    '  (sysctl-name "machdep.ptrauth_enabled")',
    '  (sysctl-name "security.mac.lockdown_mode_state")',
    '  (sysctl-name "sysctl.proc_cputype")',
    '  (sysctl-name "vm.loadavg")',
    '  (sysctl-name-prefix "hw.optional.arm")',
    '  (sysctl-name-prefix "hw.optional.arm.")',
    '  (sysctl-name-prefix "hw.optional.armv8_")',
    '  (sysctl-name-prefix "hw.perflevel")',
    '  (sysctl-name-prefix "kern.proc.pgrp.")',
    '  (sysctl-name-prefix "kern.proc.pid.")',
    '  (sysctl-name-prefix "machdep.cpu.")',
    '  (sysctl-name-prefix "net.routetable.")',
    ')',
    '',
    '; V8 thread calculations',
    '(allow sysctl-write',
    '  (sysctl-name "kern.tcsm_enable")',
    ')',
    '',
    '; Distributed notifications',
    '(allow distributed-notification-post)',
    '',
    '; Specific mach-lookup permissions for security operations',
    '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
    '(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))',
    '',
    '; File I/O on device files',
    '(allow file-ioctl (literal "/dev/null"))',
    '(allow file-ioctl (literal "/dev/zero"))',
    '(allow file-ioctl (literal "/dev/random"))',
    '(allow file-ioctl (literal "/dev/urandom"))',
    '(allow file-ioctl (literal "/dev/dtracehelper"))',
    '(allow file-ioctl (literal "/dev/tty"))',
    '',
    '(allow file-ioctl file-read-data file-write-data',
    '  (require-all',
    '    (literal "/dev/null")',
    '    (vnode-type CHARACTER-DEVICE)',
    '  )',
    ')',
    '',
  ]

  // Network rules
  profile.push('; Network')
  if (!needsNetworkRestriction) {
    profile.push('(allow network*)')
  } else {
    // Allow local binding if requested
    if (allowLocalBinding) {
      profile.push('(allow network-bind (local ip "localhost:*"))')
      profile.push('(allow network-inbound (local ip "localhost:*"))')
      profile.push('(allow network-outbound (local ip "localhost:*"))')
    }
    // Unix domain sockets for local IPC (SSH agent, Docker, etc.)
    if (allowAllUnixSockets) {
      // Allow all Unix socket paths
      profile.push('(allow network* (subpath "/"))')
    } else if (allowUnixSockets && allowUnixSockets.length > 0) {
      // Allow specific Unix socket paths
      for (const socketPath of allowUnixSockets) {
        const normalizedPath = normalizePathForSandbox(socketPath)
        profile.push(`(allow network* (subpath ${escapePath(normalizedPath)}))`)
      }
    }
    // If both allowAllUnixSockets and allowUnixSockets are false/undefined/empty, Unix sockets are blocked by default

    // Allow localhost TCP operations for the HTTP proxy
    if (httpProxyPort !== undefined) {
      profile.push(
        `(allow network-bind (local ip "localhost:${httpProxyPort}"))`,
      )
      profile.push(
        `(allow network-inbound (local ip "localhost:${httpProxyPort}"))`,
      )
      profile.push(
        `(allow network-outbound (remote ip "localhost:${httpProxyPort}"))`,
      )
    }

    // Allow localhost TCP operations for the SOCKS proxy
    if (socksProxyPort !== undefined) {
      profile.push(
        `(allow network-bind (local ip "localhost:${socksProxyPort}"))`,
      )
      profile.push(
        `(allow network-inbound (local ip "localhost:${socksProxyPort}"))`,
      )
      profile.push(
        `(allow network-outbound (remote ip "localhost:${socksProxyPort}"))`,
      )
    }
  }
  profile.push('')

  // Read rules
  profile.push('; File read')
  profile.push(...generateReadRules(readConfig, logTag))
  profile.push('')

  // Write rules
  profile.push('; File write')
  profile.push(...(await generateWriteRules(writeConfig, logTag)))

  return profile.join('\n')
}

/**
 * Escape path for sandbox profile using JSON.stringify for proper escaping
 */
function escapePath(pathStr: string): string {
  return JSON.stringify(pathStr)
}

/**
 * Get TMPDIR parent directory if it matches macOS pattern /var/folders/XX/YYY/T/
 * Returns both /var/ and /private/var/ versions since /var is a symlink
 */
function getTmpdirParentIfMacOSPattern(): string[] {
  const tmpdir = process.env.TMPDIR
  if (!tmpdir) return []

  const match = tmpdir.match(
    /^\/(private\/)?var\/folders\/[^/]{2}\/[^/]+\/T\/?$/,
  )
  if (!match) return []

  const parent = tmpdir.replace(/\/T\/?$/, '')

  // Return both /var/ and /private/var/ versions since /var is a symlink
  if (parent.startsWith('/private/var/')) {
    return [parent, parent.replace('/private', '')]
  } else if (parent.startsWith('/var/')) {
    return [parent, '/private' + parent]
  }

  return [parent]
}

/**
 * Wrap command with macOS sandbox
 */
export async function wrapCommandWithSandboxMacOS(
  params: MacOSSandboxParams,
): Promise<string> {
  const {
    command,
    httpProxyPort,
    socksProxyPort,
    needsNetworkRestriction,
    allowUnixSockets,
    allowAllUnixSockets,
    allowLocalBinding,
    readConfig,
    writeConfig,
  } = params

  // No sandboxing needed
  if (!needsNetworkRestriction && !readConfig && !writeConfig) {
    return command
  }

  const logTag = generateLogTag(command)

  const profile = await generateSandboxProfile({
    readConfig,
    writeConfig,
    httpProxyPort,
    socksProxyPort,
    needsNetworkRestriction,
    allowUnixSockets,
    allowAllUnixSockets,
    allowLocalBinding,
    logTag,
  })

  // Generate proxy environment variables using shared utility
  const proxyEnv = `export ${generateProxyEnvVars(httpProxyPort, socksProxyPort).join(' ')} && `

  const wrappedCommand = shellquote.quote([
    'sandbox-exec',
    '-p',
    profile,
    'bash',
    '-c',
    proxyEnv + command,
  ])

  logForDebugging(
    `[Sandbox macOS] Applied restrictions - network: ${!!(httpProxyPort || socksProxyPort)}, read: ${
      readConfig
        ? 'allowAllExcept' in readConfig
          ? 'allowAllExcept'
          : 'denyAllExcept'
        : 'none'
    }, write: ${
      writeConfig
        ? 'allowAllExcept' in writeConfig
          ? 'allowAllExcept'
          : 'denyAllExcept'
        : 'none'
    }`,
  )

  return wrappedCommand
}

/**
 * Start monitoring macOS system logs for sandbox violations
 * Look for sandbox-related kernel deny events ending in {logTag}
 */
export function startMacOSSandboxLogMonitor(
  callback: SandboxViolationCallback,
  ignoreViolations?: IgnoreViolationsConfig,
): () => void {
  // Pre-compile regex patterns for better performance
  const cmdExtractRegex = /CMD64_(.+?)_END/
  const sandboxExtractRegex = /Sandbox:\s+(.+)$/

  // Pre-process ignore patterns for faster lookup
  const wildcardPaths = ignoreViolations?.['*'] || []
  const commandPatterns = ignoreViolations
    ? Object.entries(ignoreViolations).filter(([pattern]) => pattern !== '*')
    : []

  // Stream and filter kernel logs for all sandbox violations
  // We can't filter by specific logTag since it's dynamic per command
  const logProcess = spawn('log', [
    'stream',
    '--predicate',
    `(eventMessage ENDSWITH "${sessionSuffix}")`,
    '--style',
    'compact',
  ])

  logProcess.stdout?.on('data', (data: Buffer) => {
    const lines = data.toString().split('\n')

    // Get violation and command lines
    const violationLine = lines.find(
      line => line.includes('Sandbox:') && line.includes('deny'),
    )
    const commandLine = lines.find(line => line.startsWith('CMD64_'))

    if (!violationLine) return

    // Extract violation details
    const sandboxMatch = violationLine.match(sandboxExtractRegex)
    if (!sandboxMatch?.[1]) return

    const violationDetails = sandboxMatch[1]

    // Try to get command
    let command: string | undefined
    let encodedCommand: string | undefined
    if (commandLine) {
      const cmdMatch = commandLine.match(cmdExtractRegex)
      encodedCommand = cmdMatch?.[1]
      if (encodedCommand) {
        try {
          command = decodeSandboxedCommand(encodedCommand)
        } catch {
          // Failed to decode, continue without command
        }
      }
    }

    // Always filter out noisey violations
    if (
      violationDetails.includes('mDNSResponder') ||
      violationDetails.includes('mach-lookup com.apple.diagnosticd') ||
      violationDetails.includes('mach-lookup com.apple.analyticsd')
    ) {
      return
    }

    // Check if we should ignore this violation
    if (ignoreViolations && command) {
      // Check wildcard patterns first
      if (wildcardPaths.length > 0) {
        const shouldIgnore = wildcardPaths.some(path =>
          violationDetails.includes(path),
        )
        if (shouldIgnore) return
      }

      // Check command-specific patterns
      for (const [pattern, paths] of commandPatterns) {
        if (command.includes(pattern)) {
          const shouldIgnore = paths.some(path =>
            violationDetails.includes(path),
          )
          if (shouldIgnore) return
        }
      }
    }

    // Not ignored - report the violation
    callback({
      line: violationDetails,
      command,
      encodedCommand,
      timestamp: new Date(), // We could parse the timestamp from the log but this feels more reliable
    })
  })

  logProcess.stderr?.on('data', (data: Buffer) => {
    logForDebugging(`[Sandbox Monitor] Log stream stderr: ${data.toString()}`)
  })

  logProcess.on('error', (error: Error) => {
    logForDebugging(
      `[Sandbox Monitor] Failed to start log stream: ${error.message}`,
    )
  })

  logProcess.on('exit', (code: number | null) => {
    logForDebugging(`[Sandbox Monitor] Log stream exited with code: ${code}`)
  })

  return () => {
    logForDebugging('[Sandbox Monitor] Stopping log monitor')
    logProcess.kill('SIGTERM')
  }
}
