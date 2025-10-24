// Library exports
export { SandboxManager } from './sandbox/sandbox-manager.js'
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'

// Configuration types and schemas
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  IgnoreViolationsConfig as ViolationIgnoreConfig,
} from './sandbox/sandbox-config.js'

export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  IgnoreViolationsConfigSchema,
} from './sandbox/sandbox-config.js'

// Schema types and utilities
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
  SandboxConfig,
  IgnoreViolationsConfig,
} from './sandbox/sandbox-schemas.js'
export { SandboxConfigSchema } from './sandbox/sandbox-schemas.js'

// Platform-specific utilities
export { hasLinuxSandboxDependenciesSync } from './sandbox/linux-sandbox-utils.js'
export type { SandboxViolationEvent } from './sandbox/macos-sandbox-utils.js'

// Utility functions
export { getDefaultWritePaths } from './sandbox/sandbox-utils.js'
