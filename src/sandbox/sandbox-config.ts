/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

/**
 * Network configuration for the sandbox
 */
export interface NetworkConfig {
  /** List of allowed domains (e.g., ["github.com", "*.npmjs.org"]) */
  allowedDomains: string[]
  /** List of denied domains */
  deniedDomains: string[]
  /** Unix socket paths that are allowed (macOS only) */
  allowUnixSockets?: string[]
  /** Whether to allow binding to local ports (optional, default: false) */
  allowLocalBinding?: boolean
}

/**
 * Filesystem configuration for the sandbox
 */
export interface FilesystemConfig {
  /** Paths denied for reading */
  denyRead: string[]
  /** Paths allowed for writing */
  allowWrite: string[]
  /** Paths denied for writing (takes precedence over allowWrite) */
  denyWrite: string[]
}

/**
 * Configuration for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 * The special key "*" matches all commands.
 *
 * Example:
 * {
 *   "*": ["/usr/bin", "/System"],           // Ignore for all commands
 *   "git push": ["/usr/bin/nc"],            // Ignore nc errors when running git push
 *   "npm": ["/private/tmp"],                // Ignore tmp access for npm commands
 * }
 */
export type IgnoreViolationsConfig = Record<string, string[]>

/**
 * Main configuration for Sandbox Runtime
 */
export interface SandboxRuntimeConfig {
  /** Network restrictions configuration */
  network: NetworkConfig
  /** Filesystem restrictions configuration */
  filesystem: FilesystemConfig
  /** Optional configuration for ignoring specific violations */
  ignoreViolations?: IgnoreViolationsConfig
  /** Enable weaker nested sandbox mode (for Docker environments) */
  enableWeakerNestedSandbox?: boolean
}
