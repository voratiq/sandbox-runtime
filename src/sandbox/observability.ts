export type NetworkDecision = 'allow' | 'deny'
export type NetworkDecisionReason = 'allowlist' | 'denylist' | 'no-match'
export type NetworkRoute = 'direct' | 'mitm'

export interface NetworkEvent {
  type: 'network'
  ts: number
  correlation_id: string
  host: string
  port: number
  decision: NetworkDecision
  reason: NetworkDecisionReason
  route: NetworkRoute
}

export type FsViolationOperation = 'read' | 'write'
export type FsViolationReason = 'denyRead' | 'denyWrite' | 'no-allowWrite'

export interface FsViolationEvent {
  type: 'fs_violation'
  ts: number
  correlation_id: string
  path: string
  operation: FsViolationOperation
  reason: FsViolationReason
}

export type SandboxEvent = NetworkEvent | FsViolationEvent

export interface SandboxEvents {
  onEvent?: (event: SandboxEvent) => void
}

export interface NetworkFilterResult {
  allowed: boolean
  reason: NetworkDecisionReason
}

const REDACTED = '[REDACTED]'

const CLI_FLAG_NAMES = ['token', 'password', 'secret', 'key', 'auth'] as const
const SENSITIVE_HEADER_NAMES = [
  'authorization',
  'cookie',
  'x-api-key',
  'proxy-authorization',
] as const
const SENSITIVE_QUERY_PARAMS = ['token', 'key', 'secret', 'password', 'auth']
const SENSITIVE_ENV_SUFFIXES = [
  '_TOKEN',
  '_KEY',
  '_SECRET',
  '_PASSWORD',
  '_CREDENTIAL',
] as const

type SandboxEventContext = {
  correlationId?: string
  onEvent?: (event: SandboxEvent) => void
}

const contextStack: SandboxEventContext[] = []

export function pushSandboxEventContext(
  context: SandboxEventContext,
): () => void {
  contextStack.push(context)
  let popped = false
  return () => {
    if (popped) return
    popped = true
    const idx = contextStack.lastIndexOf(context)
    if (idx !== -1) {
      contextStack.splice(idx, 1)
    }
  }
}

export function getSandboxEventContextDepth(): number {
  return contextStack.length
}

function getCurrentContext(): SandboxEventContext | undefined {
  return contextStack.at(-1)
}

function scrubCliFlags(input: string): string {
  let out = input
  for (const name of CLI_FLAG_NAMES) {
    const re = new RegExp(`(--${name})(\\s+|=)([^\\s]+)`, 'gi')
    out = out.replace(re, `$1$2${REDACTED}`)
  }
  return out
}

function scrubUrlQueryParams(input: string): string {
  const qIndex = input.indexOf('?')
  if (qIndex === -1) return input

  const hashIndex = input.indexOf('#', qIndex)
  const base = input.slice(0, qIndex)
  const query = input.slice(
    qIndex + 1,
    hashIndex === -1 ? undefined : hashIndex,
  )
  const hash = hashIndex === -1 ? '' : input.slice(hashIndex)

  const parts = query.split('&').map(part => {
    const eq = part.indexOf('=')
    const rawKey = eq === -1 ? part : part.slice(0, eq)
    const rawValue = eq === -1 ? '' : part.slice(eq + 1)
    let decodedKey = rawKey
    try {
      decodedKey = decodeURIComponent(rawKey)
    } catch {
      // Leave as-is if it contains invalid percent-encoding
    }
    const key = decodedKey.toLowerCase()
    if (SENSITIVE_QUERY_PARAMS.includes(key)) {
      return `${rawKey}=${encodeURIComponent(REDACTED)}`
    }
    return eq === -1 ? rawKey : `${rawKey}=${rawValue}`
  })

  return `${base}?${parts.join('&')}${hash}`
}

function scrubString(input: string): string {
  return scrubUrlQueryParams(scrubCliFlags(input))
}

function isSensitiveHeaderKey(key: string): boolean {
  return SENSITIVE_HEADER_NAMES.includes(key.toLowerCase() as never)
}

function isSensitiveEnvKey(key: string): boolean {
  const upper = key.toUpperCase()
  return SENSITIVE_ENV_SUFFIXES.some(suffix => upper.endsWith(suffix))
}

export function scrubSecrets(value: unknown): unknown {
  if (typeof value === 'string') {
    return scrubString(value)
  }
  if (Array.isArray(value)) {
    return value.map(scrubSecrets)
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, nested] of Object.entries(value)) {
      if (isSensitiveHeaderKey(key) || isSensitiveEnvKey(key)) {
        out[key] = REDACTED
        continue
      }
      out[key] = scrubSecrets(nested)
    }
    return out
  }
  return value
}

function emitEvent(event: SandboxEvent): void {
  const ctx = getCurrentContext()
  if (!ctx?.onEvent) return

  try {
    const scrubbed = scrubSecrets(event) as SandboxEvent
    ctx.onEvent(scrubbed)
  } catch {
    // Never allow observability to break sandbox enforcement paths
  }
}

export function emitNetworkDecisionEvent(params: {
  host: string
  port: number
  decision: NetworkDecision
  reason: NetworkDecisionReason
  route: NetworkRoute
  correlationId?: string
  ts?: number
}): void {
  const ctx = getCurrentContext()
  const correlationId = params.correlationId ?? ctx?.correlationId ?? ''

  emitEvent({
    type: 'network',
    ts: params.ts ?? Date.now(),
    correlation_id: correlationId,
    host: params.host,
    port: params.port,
    decision: params.decision,
    reason: params.reason,
    route: params.route,
  })
}

export function emitFsViolationEvent(params: {
  path: string
  operation: FsViolationOperation
  reason: FsViolationReason
  correlationId?: string
  ts?: number
}): void {
  const ctx = getCurrentContext()
  const correlationId = params.correlationId ?? ctx?.correlationId ?? ''

  emitEvent({
    type: 'fs_violation',
    ts: params.ts ?? Date.now(),
    correlation_id: correlationId,
    path: params.path,
    operation: params.operation,
    reason: params.reason,
  })
}
