import { createHttpProxyServer } from './http-proxy.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { logForDebugging } from '../utils/debug.js'
import { getPlatform, type Platform } from '../utils/platform.js'
import * as fs from 'fs'
import {
  WEB_FETCH_TOOL_NAME,
  FILE_EDIT_TOOL_NAME,
  FILE_READ_TOOL_NAME,
} from '../utils/settings.js'
import { getSettings, permissionRuleValueFromString } from '../utils/settings.js'
import type {
  SandboxAskCallback,
  IgnoreViolationsConfig,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from './sandbox-schemas.js'
import {
  wrapCommandWithSandboxLinux,
  initializeLinuxNetworkBridge,
  hasLinuxSandboxDependenciesSync,
  type LinuxNetworkBridgeContext,
} from './linux-sandbox-utils.js'
import {
  wrapCommandWithSandboxMacOS,
  startMacOSSandboxLogMonitor,
  hasMacOSSandboxDependenciesSync,
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

function getWebFetchRules(behavior: 'allow' | 'deny' | 'ask'): string[] {
  const settings = getSettings()
  if (!settings?.permissions) {
    return []
  }

  const rulesArray = settings.permissions[behavior] || []

  return rulesArray.filter(ruleString => {
    const rule = permissionRuleValueFromString(ruleString)
    return (
      rule.toolName === WEB_FETCH_TOOL_NAME &&
      rule.ruleContent?.startsWith('domain:')
    )
  })
}

function matchesWebFetchRule(hostname: string, ruleString: string): boolean {
  const rule = permissionRuleValueFromString(ruleString)
  if (
    rule.toolName !== WEB_FETCH_TOOL_NAME ||
    !rule.ruleContent?.startsWith('domain:')
  ) {
    return false
  }
  const domainPattern = rule.ruleContent.substring('domain:'.length)

  // Support wildcard patterns like *.example.com
  // This matches any subdomain but not the base domain itself
  if (domainPattern.startsWith('*.')) {
    const baseDomain = domainPattern.substring(2) // Remove '*.'
    return hostname.toLowerCase().endsWith('.' + baseDomain.toLowerCase())
  }

  // Exact match for non-wildcard patterns
  return hostname.toLowerCase() === domainPattern.toLowerCase()
}

function getFileEditRules(behavior: 'allow' | 'deny' | 'ask'): string[] {
  const settings = getSettings()
  if (!settings?.permissions) {
    return []
  }

  const rulesArray = settings.permissions[behavior] || []

  return rulesArray.filter(ruleString => {
    const rule = permissionRuleValueFromString(ruleString)
    return rule.toolName === FILE_EDIT_TOOL_NAME
  })
}

function getFileReadRules(behavior: 'allow' | 'deny' | 'ask'): string[] {
  const settings = getSettings()
  if (!settings?.permissions) {
    return []
  }

  const rulesArray = settings.permissions[behavior] || []

  // Get rules for Read tool
  return rulesArray.filter(ruleString => {
    const rule = permissionRuleValueFromString(ruleString)
    return rule.toolName === FILE_READ_TOOL_NAME
  })
}

async function filterNetworkRequest(
  port: number,
  host: string,
  sandboxAskCallback?: SandboxAskCallback,
): Promise<boolean> {
  // Check WebFetch permission rules (port-agnostic, hostname only)
  const denyRules = getWebFetchRules('deny')
  for (const rule of denyRules) {
    if (matchesWebFetchRule(host, rule)) {
      logForDebugging(`Denied by WebFetch rule: ${host}:${port}`)
      return false
    }
  }

  const allowRules = getWebFetchRules('allow')
  for (const rule of allowRules) {
    if (matchesWebFetchRule(host, rule)) {
      logForDebugging(`Allowed by WebFetch rule: ${host}:${port}`)
      return true
    }
  }

  // No matching rules - ask user or deny
  if (!sandboxAskCallback) {
    logForDebugging(`No matching WebFetch rule, denying: ${host}:${port}`)
    return false
  }

  logForDebugging(`No matching WebFetch rule, asking user: ${host}:${port}`)
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

async function startHttpProxyOrUseExistingPort(
  providedPort: number | undefined,
  sandboxAskCallback?: SandboxAskCallback,
): Promise<number> {
  if (providedPort !== undefined) {
    logForDebugging(`Using provided HTTP proxy port: ${providedPort}`)
    return providedPort
  }
  const port = await startHttpProxyServer(sandboxAskCallback)
  logForDebugging(`Started HTTP proxy server on port ${port}`)
  return port
}

async function startSocksProxyOrUseExistingPort(
  providedPort: number | undefined,
  sandboxAskCallback?: SandboxAskCallback,
): Promise<number> {
  if (providedPort !== undefined) {
    logForDebugging(`Using provided SOCKS proxy port: ${providedPort}`)
    return providedPort
  }
  const port = await startSocksProxyServer(sandboxAskCallback)
  logForDebugging(`Started SOCKS proxy server on port ${port}`)
  return port
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

async function initialize(
  sandboxAskCallback?: SandboxAskCallback,
  enableLogMonitor = false,
): Promise<void> {
  if (!isSandboxingEnabled()) {
    return
  }

  // Return if already initializing
  if (initializationPromise) {
    await initializationPromise
    return
  }

  const settings = getSettings()

  // Start log monitor for macOS if enabled and sandboxing is enabled
  if (enableLogMonitor && getPlatform() === 'macos' && isSandboxingEnabled()) {
    logMonitorShutdown = startMacOSSandboxLogMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      getIgnoreViolations(),
    )
    logForDebugging('Started macOS sandbox log monitor')
  }

  // Register cleanup handlers first time
  registerCleanup()

  // Initialize network infrastructure
  // Network filtering is based on WebFetch permission rules, so proxy servers
  // must always be initialized when sandbox is enabled
  initializationPromise = (async () => {
    try {
      // Check if ports are provided in settings
      const providedHttpProxyPort = settings.sandbox?.network?.httpProxyPort
      const providedSocksProxyPort = settings.sandbox?.network?.socksProxyPort

      // Start proxy servers in parallel, using provided ports when available
      const [httpProxyPort, socksProxyPort] = await Promise.all([
        startHttpProxyOrUseExistingPort(
          providedHttpProxyPort,
          sandboxAskCallback,
        ),
        startSocksProxyOrUseExistingPort(
          providedSocksProxyPort,
          sandboxAskCallback,
        ),
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
  // Sandboxing is not supported on Windows
  if (!isSupportedPlatform(getPlatform())) {
    return false
  }

  // On Linux, check if required dependencies are available
  if (getPlatform() === 'linux' && !hasLinuxSandboxDependenciesSync()) {
    console.error(
      'Sandbox disabled: Required dependencies not found. Please install: bwrap, socat, and ripgrep',
    )
    console.error('  Install with: apt install bubblewrap socat ripgrep')
    return false
  }

  // On macOS, check if required dependencies are available
  if (getPlatform() === 'macos' && !hasMacOSSandboxDependenciesSync()) {
    console.error(
      'Sandbox disabled: ripgrep (rg) not found. Please install ripgrep.',
    )
    console.error('  Install with: brew install ripgrep')
    return false
  }

  // Sandbox is always enabled (unless platform is not supported or dependencies are missing)
  return true
}


function getFsReadConfig(): FsReadRestrictionConfig {
  // Build read config from Read permission deny rules
  const denyRules = getFileReadRules('deny')

  const denyPaths = denyRules
    .map(ruleString => {
      const rule = permissionRuleValueFromString(ruleString)
      return rule.ruleContent || null
    })
    .filter((path): path is string => path !== null)
    .map(path => {
      // Normalize by removing trailing /** for consistency
      return removeTrailingGlobSuffix(path)
    })
    .filter(path => {
      // On Linux, filter out glob patterns since they're not fully supported
      // (trailing /** already removed by normalization above)
      if (getPlatform() === 'linux') {
        if (containsGlobChars(path)) {
          logForDebugging(`Skipping glob pattern on Linux: ${path}`)
          return false
        }
      }
      return true
    })

  return {
    denyOnly: denyPaths,
  }
}

function getFsWriteConfig(): FsWriteRestrictionConfig {
  // Build write config from Edit permission allow/deny rules
  const allowRules = getFileEditRules('allow')
  const allowPaths = allowRules
    .map(ruleString => {
      const rule = permissionRuleValueFromString(ruleString)
      return rule.ruleContent || null
    })
    .filter((path): path is string => path !== null)
    .map(path => {
      // Normalize by removing trailing /** for consistency
      return removeTrailingGlobSuffix(path)
    })
    .filter(path => {
      // On Linux, filter out glob patterns since they're not fully supported
      // (trailing /** already removed by normalization above)
      if (getPlatform() === 'linux') {
        if (containsGlobChars(path)) {
          logForDebugging(`Skipping glob pattern on Linux: ${path}`)
          return false
        }
      }
      return true
    })

  // Get Edit deny rules - these become the denyWithinAllow paths
  const denyRules = getFileEditRules('deny')
  const denyPaths = denyRules
    .map(ruleString => {
      const rule = permissionRuleValueFromString(ruleString)
      return rule.ruleContent || null
    })
    .filter((path): path is string => path !== null)
    .map(path => {
      // Normalize by removing trailing /** for consistency
      return removeTrailingGlobSuffix(path)
    })
    .filter(path => {
      // On Linux, filter out glob patterns since they're not fully supported
      // (trailing /** already removed by normalization above)
      if (getPlatform() === 'linux') {
        if (containsGlobChars(path)) {
          logForDebugging(`Skipping glob pattern on Linux: ${path}`)
          return false
        }
      }
      return true
    })

  // Build allowOnly list: default paths + Edit allow rules
  const allowOnly = [...getDefaultWritePaths(), ...allowPaths]

  return {
    allowOnly,
    denyWithinAllow: denyPaths,
  }
}

function getNetworkRestrictionConfig(): NetworkRestrictionConfig {
  // Build network config from WebFetch permission allow/deny rules
  const allowRules = getWebFetchRules('allow')
  const allowedHosts = allowRules
    .map(ruleString => {
      const rule = permissionRuleValueFromString(ruleString)
      // Extract domain from "domain:example.com" format
      if (rule.ruleContent?.startsWith('domain:')) {
        return rule.ruleContent.substring('domain:'.length)
      }
      return null
    })
    .filter((host): host is string => host !== null)

  const denyRules = getWebFetchRules('deny')
  const deniedHosts = denyRules
    .map(ruleString => {
      const rule = permissionRuleValueFromString(ruleString)
      // Extract domain from "domain:example.com" format
      if (rule.ruleContent?.startsWith('domain:')) {
        return rule.ruleContent.substring('domain:'.length)
      }
      return null
    })
    .filter((host): host is string => host !== null)

  return {
    ...(allowedHosts.length > 0 && { allowedHosts }),
    ...(deniedHosts.length > 0 && { deniedHosts }),
  }
}

function getAllowUnixSockets(): string[] | undefined {
  const settings = getSettings()
  return settings.sandbox?.network?.allowUnixSockets
}

function getAllowLocalBinding(): boolean | undefined {
  const settings = getSettings()
  return settings.sandbox?.network?.allowLocalBinding
}

function getIgnoreViolations(): IgnoreViolationsConfig | undefined {
  const settings = getSettings()
  return settings.sandbox?.ignoreViolations
}

function getEnableWeakerNestedSandbox(): boolean | undefined {
  const settings = getSettings()
  return settings.sandbox?.enableWeakerNestedSandbox
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
  if (!isSandboxingEnabled()) {
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
  // If no sandboxing is enabled, return command as-is
  if (!isSandboxingEnabled()) {
    return command
  }

  const platform = getPlatform()
  const isSandboxed = isSandboxingEnabled()

  // Wait for network initialization if needed
  if (isSandboxed) {
    await waitForNetworkInitialization()
  }

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
  if (!isSandboxingEnabled()) {
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
  // Only warn on Linux with sandboxing enabled
  // macOS supports glob patterns via regex conversion
  if (getPlatform() !== 'linux' || !isSandboxingEnabled()) {
    return []
  }

  const settings = getSettings()
  if (!settings?.permissions) {
    return []
  }

  const globPatterns: string[] = []

  // Check allow and deny rules for glob patterns
  for (const behavior of ['allow', 'deny'] as const) {
    const rules = settings.permissions[behavior] || []
    for (const ruleString of rules) {
      const rule = permissionRuleValueFromString(ruleString)

      // Only check Edit and Read rules (file operations)
      if (
        (rule.toolName === 'Edit' || rule.toolName === 'Read') &&
        rule.ruleContent
      ) {
        // Strip trailing /** since that's just a subpath (directory and everything under it)
        const pathWithoutTrailingStar = removeTrailingGlobSuffix(
          rule.ruleContent,
        )

        // Only warn if there are still glob characters after removing trailing /**
        if (containsGlobChars(pathWithoutTrailingStar)) {
          globPatterns.push(ruleString)
        }
      }
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
  getIgnoreViolations(): IgnoreViolationsConfig | undefined
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
  getIgnoreViolations,
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
