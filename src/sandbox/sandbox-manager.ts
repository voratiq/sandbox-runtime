import { createHttpProxyServer } from './http-proxy.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { logForDebugging } from '../utils/debug.js'
import { getPlatform, type Platform } from '../utils/platform.js'
import * as fs from 'fs'
import type { SandboxRuntimeConfig } from './sandbox-config.js'
import type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from './sandbox-schemas.js'
import {
  wrapCommandWithSandboxLinux,
  initializeLinuxNetworkBridge,
  type LinuxNetworkBridgeContext,
} from './linux-sandbox-utils.js'
import {
  wrapCommandWithSandboxMacOS,
  startMacOSSandboxLogMonitor,
} from './macos-sandbox-utils.js'
import {
  getDefaultWritePaths,
  containsGlobChars,
  removeTrailingGlobSuffix,
} from './sandbox-utils.js'
import { SandboxViolationStore } from './sandbox-violation-store.js'
import { EOL } from 'node:os'

interface HostNetworkManagerContext {
  httpProxyPort: number
  socksProxyPort: number
  linuxBridge: LinuxNetworkBridgeContext | undefined
}

// ============================================================================
// Private Module State
// ============================================================================

let config: SandboxRuntimeConfig | undefined
let httpProxyServer: ReturnType<typeof createHttpProxyServer> | undefined
let socksProxyServer: SocksProxyWrapper | undefined
let managerContext: HostNetworkManagerContext | undefined
let initializationPromise: Promise<HostNetworkManagerContext> | undefined
let cleanupRegistered = false
let logMonitorShutdown: (() => void) | undefined
const sandboxViolationStore = new SandboxViolationStore()

// ============================================================================
// Private Helper Functions (not exported)
// ============================================================================

function registerCleanup(): void {
  if (cleanupRegistered) {
    return
  }
  const cleanupHandler = () =>
    reset().catch(e => {
      logForDebugging(`Cleanup failed in registerCleanup ${e}`, {
        level: 'error',
      })
    })
  process.once('exit', cleanupHandler)
  process.once('SIGINT', cleanupHandler)
  process.once('SIGTERM', cleanupHandler)
  cleanupRegistered = true
}

function matchesDomainPattern(hostname: string, pattern: string): boolean {
  // Support wildcard patterns like *.example.com
  // This matches any subdomain but not the base domain itself
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.substring(2) // Remove '*.'
    return hostname.toLowerCase().endsWith('.' + baseDomain.toLowerCase())
  }

  // Exact match for non-wildcard patterns
  return hostname.toLowerCase() === pattern.toLowerCase()
}

async function filterNetworkRequest(
  port: number,
  host: string,
  sandboxAskCallback?: SandboxAskCallback,
): Promise<boolean> {
  if (!config) {
    logForDebugging('No config available, denying network request')
    return false
  }

  // Check denied domains first
  for (const deniedDomain of config.network.deniedDomains) {
    if (matchesDomainPattern(host, deniedDomain)) {
      logForDebugging(`Denied by config rule: ${host}:${port}`)
      return false
    }
  }

  // Check allowed domains
  for (const allowedDomain of config.network.allowedDomains) {
    if (matchesDomainPattern(host, allowedDomain)) {
      logForDebugging(`Allowed by config rule: ${host}:${port}`)
      return true
    }
  }

  // No matching rules - ask user or deny
  if (!sandboxAskCallback) {
    logForDebugging(`No matching config rule, denying: ${host}:${port}`)
    return false
  }

  logForDebugging(`No matching config rule, asking user: ${host}:${port}`)
  try {
    const userAllowed = await sandboxAskCallback({ host, port })
    if (userAllowed) {
      logForDebugging(`User allowed: ${host}:${port}`)
      return true
    } else {
      logForDebugging(`User denied: ${host}:${port}`)
      return false
    }
  } catch (error) {
    logForDebugging(`Error in permission callback: ${error}`, {
      level: 'error',
    })
    return false
  }
}

async function startHttpProxyServer(
  sandboxAskCallback?: SandboxAskCallback,
): Promise<number> {
  httpProxyServer = createHttpProxyServer({
    filter: (port: number, host: string) =>
      filterNetworkRequest(port, host, sandboxAskCallback),
  })

  return new Promise<number>((resolve, reject) => {
    if (!httpProxyServer) {
      reject(new Error('HTTP proxy server undefined before listen'))
      return
    }

    const server = httpProxyServer

    server.once('error', reject)
    server.once('listening', () => {
      const address = server.address()
      if (address && typeof address === 'object') {
        server.unref()
        logForDebugging(`HTTP proxy listening on localhost:${address.port}`)
        resolve(address.port)
      } else {
        reject(new Error('Failed to get proxy server address'))
      }
    })

    server.listen(0, '127.0.0.1')
  })
}

async function startSocksProxyServer(
  sandboxAskCallback?: SandboxAskCallback,
): Promise<number> {
  socksProxyServer = createSocksProxyServer({
    filter: (port: number, host: string) =>
      filterNetworkRequest(port, host, sandboxAskCallback),
  })

  return new Promise<number>((resolve, reject) => {
    if (!socksProxyServer) {
      // This is mostly just for the typechecker
      reject(new Error('SOCKS proxy server undefined before listen'))
      return
    }

    socksProxyServer
      .listen(0, '127.0.0.1')
      .then((port: number) => {
        socksProxyServer?.unref()
        resolve(port)
      })
      .catch(reject)
  })
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

async function initialize(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback?: SandboxAskCallback,
  enableLogMonitor = false,
): Promise<void> {
  // Store config for use by other functions
  config = runtimeConfig

  // Return if already initializing
  if (initializationPromise) {
    await initializationPromise
    return
  }

  // Start log monitor for macOS if enabled
  if (enableLogMonitor && getPlatform() === 'macos') {
    logMonitorShutdown = startMacOSSandboxLogMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      config.ignoreViolations,
    )
    logForDebugging('Started macOS sandbox log monitor')
  }

  // Register cleanup handlers first time
  registerCleanup()

  // Initialize network infrastructure
  initializationPromise = (async () => {
    try {
      // Start proxy servers in parallel
      const [httpProxyPort, socksProxyPort] = await Promise.all([
        startHttpProxyServer(sandboxAskCallback),
        startSocksProxyServer(sandboxAskCallback),
      ])

      // Initialize platform-specific infrastructure
      let linuxBridge: LinuxNetworkBridgeContext | undefined
      if (getPlatform() === 'linux') {
        linuxBridge = await initializeLinuxNetworkBridge(
          httpProxyPort,
          socksProxyPort,
        )
      }

      const context: HostNetworkManagerContext = {
        httpProxyPort,
        socksProxyPort,
        linuxBridge,
      }
      managerContext = context
      logForDebugging('Network infrastructure initialized')
      return context
    } catch (error) {
      // Clear state on error so initialization can be retried
      initializationPromise = undefined
      managerContext = undefined
      reset().catch(e => {
        logForDebugging(`Cleanup failed in initializationPromise ${e}`, {
          level: 'error',
        })
      })
      throw error
    }
  })()

  await initializationPromise
}

function isSupportedPlatform(platform: Platform): boolean {
  const supportedPlatforms: Platform[] = ['macos', 'linux']
  return supportedPlatforms.includes(platform)
}

function isSandboxingEnabled(): boolean {
  // Sandboxing is enabled if config has been set (via initialize())
  return config !== undefined
}


function getFsReadConfig(): FsReadRestrictionConfig {
  if (!config) {
    return { denyOnly: [] }
  }

  // Filter out glob patterns on Linux
  const denyPaths = config.filesystem.denyRead
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux: ${path}`)
        return false
      }
      return true
    })

  return {
    denyOnly: denyPaths,
  }
}

function getFsWriteConfig(): FsWriteRestrictionConfig {
  if (!config) {
    return { allowOnly: getDefaultWritePaths(), denyWithinAllow: [] }
  }

  // Filter out glob patterns on Linux for allowWrite
  const allowPaths = config.filesystem.allowWrite
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux: ${path}`)
        return false
      }
      return true
    })

  // Filter out glob patterns on Linux for denyWrite
  const denyPaths = config.filesystem.denyWrite
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux: ${path}`)
        return false
      }
      return true
    })

  // Build allowOnly list: default paths + configured allow paths
  const allowOnly = [...getDefaultWritePaths(), ...allowPaths]

  return {
    allowOnly,
    denyWithinAllow: denyPaths,
  }
}

function getNetworkRestrictionConfig(): NetworkRestrictionConfig {
  if (!config) {
    return {}
  }

  const allowedHosts = config.network.allowedDomains
  const deniedHosts = config.network.deniedDomains

  return {
    ...(allowedHosts.length > 0 && { allowedHosts }),
    ...(deniedHosts.length > 0 && { deniedHosts }),
  }
}

function getAllowUnixSockets(): string[] | undefined {
  return config?.network?.allowUnixSockets
}

function getAllowAllUnixSockets(): boolean | undefined {
  return config?.network?.allowAllUnixSockets
}

function getAllowLocalBinding(): boolean | undefined {
  return config?.network?.allowLocalBinding
}

function getIgnoreViolations(): Record<string, string[]> | undefined {
  return config?.ignoreViolations
}

function getEnableWeakerNestedSandbox(): boolean | undefined {
  return config?.enableWeakerNestedSandbox
}

function getProxyPort(): number | undefined {
  return managerContext?.httpProxyPort
}

function getSocksProxyPort(): number | undefined {
  return managerContext?.socksProxyPort
}

function getLinuxHttpSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.httpSocketPath
}

function getLinuxSocksSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.socksSocketPath
}

/**
 * Wait for network initialization to complete if already in progress
 * Returns true if initialized successfully, false otherwise
 */
async function waitForNetworkInitialization(): Promise<boolean> {
  if (!config) {
    return false
  }
  if (initializationPromise) {
    try {
      await initializationPromise
      return true
    } catch {
      return false
    }
  }
  return managerContext !== undefined
}

async function wrapWithSandbox(command: string): Promise<string> {
  // If no config, return command as-is
  if (!config) {
    return command
  }

  const platform = getPlatform()

  // Wait for network initialization
  await waitForNetworkInitialization()

  switch (platform) {
    case 'macos':
      return await wrapCommandWithSandboxMacOS({
        command,
        httpProxyPort: getProxyPort(),
        socksProxyPort: getSocksProxyPort(),
        readConfig: getFsReadConfig(),
        writeConfig: getFsWriteConfig(),
        needsNetworkRestriction: true,
        allowUnixSockets: getAllowUnixSockets(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
        allowLocalBinding: getAllowLocalBinding(),
        ignoreViolations: getIgnoreViolations(),
      })

    case 'linux':
      return wrapCommandWithSandboxLinux({
        command,
        hasNetworkRestrictions: true,
        hasFilesystemRestrictions: true,
        httpSocketPath: getLinuxHttpSocketPath(),
        socksSocketPath: getLinuxSocksSocketPath(),
        httpProxyPort: managerContext?.httpProxyPort,
        socksProxyPort: managerContext?.socksProxyPort,
        readConfig: getFsReadConfig(),
        writeConfig: getFsWriteConfig(),
        enableWeakerNestedSandbox: getEnableWeakerNestedSandbox(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
      })

    default:
      // Unsupported platform - this should not happen since isSandboxingEnabled() checks platform support
      throw new Error(
        `Sandbox configuration is not supported on platform: ${platform}`,
      )
  }
}

async function reset(): Promise<void> {
  // Stop log monitor
  if (logMonitorShutdown) {
    logMonitorShutdown()
    logMonitorShutdown = undefined
  }

  if (managerContext?.linuxBridge) {
    const {
      httpSocketPath,
      socksSocketPath,
      httpBridgeProcess,
      socksBridgeProcess,
    } = managerContext.linuxBridge

    // Kill HTTP bridge
    if (httpBridgeProcess.pid && !httpBridgeProcess.killed) {
      try {
        process.kill(httpBridgeProcess.pid, 'SIGTERM')
        logForDebugging('Killed HTTP bridge process')
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
          logForDebugging(`Error killing HTTP bridge: ${err}`, {
            level: 'error',
          })
        }
      }
    }

    // Kill SOCKS bridge
    if (socksBridgeProcess.pid && !socksBridgeProcess.killed) {
      try {
        process.kill(socksBridgeProcess.pid, 'SIGTERM')
        logForDebugging('Killed SOCKS bridge process')
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
          logForDebugging(`Error killing SOCKS bridge: ${err}`, {
            level: 'error',
          })
        }
      }
    }

    // Clean up sockets
    if (httpSocketPath) {
      try {
        fs.rmSync(httpSocketPath, { force: true })
        logForDebugging('Cleaned up HTTP socket')
      } catch (err) {
        logForDebugging(`HTTP socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }

    if (socksSocketPath) {
      try {
        fs.rmSync(socksSocketPath, { force: true })
        logForDebugging('Cleaned up SOCKS socket')
      } catch (err) {
        logForDebugging(`SOCKS socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }
  }

  // Close servers in parallel
  const closePromises: Promise<void>[] = []

  if (httpProxyServer) {
    const server = httpProxyServer // Capture reference to avoid TypeScript error
    const httpClose = new Promise<void>(resolve => {
      server.close(error => {
        if (error && error.message !== 'Server is not running.') {
          logForDebugging(`Error closing HTTP proxy server: ${error.message}`, {
            level: 'error',
          })
        }
        resolve()
      })
    })
    closePromises.push(httpClose)
  }

  if (socksProxyServer) {
    const socksClose = socksProxyServer.close().catch((error: Error) => {
      logForDebugging(`Error closing SOCKS proxy server: ${error.message}`, {
        level: 'error',
      })
    })
    closePromises.push(socksClose)
  }

  // Wait for all servers to close
  await Promise.all(closePromises)

  // Clear references
  httpProxyServer = undefined
  socksProxyServer = undefined
  managerContext = undefined
  initializationPromise = undefined
}

function getSandboxViolationStore() {
  return sandboxViolationStore
}

function annotateStderrWithSandboxFailures(
  command: string,
  stderr: string,
): string {
  if (!config) {
    return stderr
  }

  const violations = sandboxViolationStore.getViolationsForCommand(command)
  if (violations.length === 0) {
    return stderr
  }

  let annotated = stderr
  annotated += EOL + '<sandbox_violations>' + EOL
  for (const violation of violations) {
    annotated += violation.line + EOL
  }
  annotated += '</sandbox_violations>'

  return annotated
}

/**
 * Returns glob patterns from Edit/Read permission rules that are not
 * fully supported on Linux. Returns empty array on macOS or when
 * sandboxing is disabled.
 *
 * Patterns ending with /** are excluded since they work as subpaths.
 */
function getLinuxGlobPatternWarnings(): string[] {
  // Only warn on Linux
  // macOS supports glob patterns via regex conversion
  if (getPlatform() !== 'linux' || !config) {
    return []
  }

  const globPatterns: string[] = []

  // Check filesystem paths for glob patterns
  const allPaths = [
    ...config.filesystem.allowRead,
    ...config.filesystem.denyRead,
    ...config.filesystem.allowWrite,
    ...config.filesystem.denyWrite,
  ]

  for (const path of allPaths) {
    // Strip trailing /** since that's just a subpath (directory and everything under it)
    const pathWithoutTrailingStar = removeTrailingGlobSuffix(path)

    // Only warn if there are still glob characters after removing trailing /**
    if (containsGlobChars(pathWithoutTrailingStar)) {
      globPatterns.push(path)
    }
  }

  return globPatterns
}

// ============================================================================
// Public API Interface
// ============================================================================

/**
 * Interface for the sandbox manager API
 */
export interface ISandboxManager {
  initialize(
    runtimeConfig: SandboxRuntimeConfig,
    sandboxAskCallback?: SandboxAskCallback,
    enableLogMonitor?: boolean,
  ): Promise<void>
  isSupportedPlatform(platform: Platform): boolean
  isSandboxingEnabled(): boolean
  getFsReadConfig(): FsReadRestrictionConfig
  getFsWriteConfig(): FsWriteRestrictionConfig
  getNetworkRestrictionConfig(): NetworkRestrictionConfig
  getAllowUnixSockets(): string[] | undefined
  getAllowLocalBinding(): boolean | undefined
  getEnableWeakerNestedSandbox(): boolean | undefined
  getProxyPort(): number | undefined
  getSocksProxyPort(): number | undefined
  getLinuxHttpSocketPath(): string | undefined
  getLinuxSocksSocketPath(): string | undefined
  waitForNetworkInitialization(): Promise<boolean>
  wrapWithSandbox(command: string): Promise<string>
  getSandboxViolationStore(): SandboxViolationStore
  annotateStderrWithSandboxFailures(command: string, stderr: string): string
  getLinuxGlobPatternWarnings(): string[]
  reset(): Promise<void>
}

// ============================================================================
// Export as Namespace with Interface
// ============================================================================

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  reset,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
} as const
