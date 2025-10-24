// Filesystem restriction configs (internal structures built from permission rules)
export interface FsReadRestrictionConfig {
  denyOnly: string[]
}

export interface FsWriteRestrictionConfig {
  allowOnly: string[]
  denyWithinAllow: string[]
}

// Network restriction config (internal structure built from permission rules)
export interface NetworkRestrictionConfig {
  allowedHosts?: string[]
  deniedHosts?: string[]
}

export type NetworkHostPattern = {
  host: string
  port: number | undefined
}

export type SandboxAskCallback = (
  params: NetworkHostPattern,
) => Promise<boolean>
