import { createHash, randomUUID } from 'node:crypto'

export type TelemetryStage = 'start' | 'attempt' | 'completion' | 'failure'
export type TelemetryStatus = 'success' | 'failed' | 'cancelled'

export interface TelemetrySandboxVerdict {
  decision: string | null
  reason: string | null
  policy_tag: string | null
}

export interface TelemetryNetworkDetails {
  resolved_host: string | null
  resolved_ip: string | null
  tls_outcome: string | null
  tls_error: string | null
  dns_source: string | null
}

export interface TelemetryHttpMetadata {
  req_headers: Record<string, string | null> | null
  resp_headers: Record<string, string | null> | null
  payload_bytes: number | null
  payload_hash: string | null
  compression: string | null
}

export interface TelemetryEvent {
  event: 'sandbox_request'
  trace_id: string
  stage: TelemetryStage
  attempt: number
  command: string | null
  status: TelemetryStatus
  status_code: number | null
  sandbox_verdict: TelemetrySandboxVerdict | null
  network: TelemetryNetworkDetails | null
  http_metadata: TelemetryHttpMetadata | null
  latency_ms: number | null
  queue_latency_ms: number | null
  user_context: string | null
  egress_type: string | null
  timestamp: string
}

export type TelemetrySink = (event: TelemetryEvent) => void

const DEFAULT_HEADER_WHITELIST = new Set([
  'retry-after',
  'x-request-id',
  'x-trace-id',
  'traceparent',
  'tracestate',
  'content-encoding',
  'content-type',
  'content-length',
])

const SENSITIVE_FLAG_NAMES = new Set([
  '--token',
  '--secret',
  '--password',
  '--passwd',
  '--api-key',
  '--api_key',
  '--apikey',
  '--authorization',
  '--auth',
  '--bearer',
])

const SENSITIVE_KEY_PATTERN =
  /token|secret|password|passwd|api[-_]?key|authorization|bearer/i
const SECRET_VALUE_PATTERN =
  /(bearer\s+[a-z0-9+/=_-]{8,}|sk-[a-z0-9]{16,}|[a-z0-9]{24,}|AIza[0-9a-z_-]{35})/i

interface TelemetryContext {
  enabled: boolean
  traceId: string | null
  command: string | null
  userContext: string | null
  sink: TelemetrySink
}

const defaultSink: TelemetrySink = event => {
  process.stderr.write(`${JSON.stringify(event)}\n`)
}

const context: TelemetryContext = {
  enabled: false,
  traceId: null,
  command: null,
  userContext: null,
  sink: defaultSink,
}

export interface InitializeTelemetryOptions {
  debugEnabled: boolean
  commandArgs?: string[]
  userContext?: string | null
}

export function initializeTelemetry(
  options: InitializeTelemetryOptions,
): string | null {
  context.enabled = Boolean(options.debugEnabled)

  if (!context.enabled) {
    context.traceId = null
    context.command = null
    context.userContext = options.userContext ?? null
    context.sink = defaultSink
    return null
  }

  const traceId = randomUUID()
  context.traceId = traceId
  context.command = options.commandArgs
    ? sanitizeCommandArgs(options.commandArgs)
    : null
  context.userContext = options.userContext ?? null
  context.sink = context.sink || defaultSink

  process.env.DEBUG = process.env.DEBUG || 'true'
  process.env.SRT_TRACE_ID = traceId

  const bannerMessage = `Debug telemetry active (trace_id=${traceId})`
  process.stderr.write(`${bannerMessage}\n`)

  return traceId
}

export function isTelemetryEnabled(): boolean {
  return context.enabled
}

export function getTelemetryTraceId(): string | null {
  return context.traceId
}

export function setTelemetrySink(sink: TelemetrySink | null): void {
  context.sink = sink ?? defaultSink
}

export interface EmitTelemetryEventOptions {
  stage: TelemetryStage
  status: TelemetryStatus
  attempt?: number
  status_code?: number | null
  sandbox_verdict?: Partial<TelemetrySandboxVerdict> | null
  network?: Partial<TelemetryNetworkDetails> | null
  http_metadata?: Partial<TelemetryHttpMetadata> | null
  latency_ms?: number | null
  queue_latency_ms?: number | null
  user_context?: string | null
  egress_type?: string | null
  command?: string | null
}

export function emitTelemetryEvent(
  options: EmitTelemetryEventOptions,
): TelemetryEvent | null {
  if (!context.enabled || !context.traceId) {
    return null
  }

  const attempt = options.attempt ?? 0
  const command = options.command ?? context.command ?? null

  const event: TelemetryEvent = {
    event: 'sandbox_request',
    trace_id: context.traceId,
    stage: options.stage,
    attempt,
    command,
    status: options.status,
    status_code: options.status_code === undefined ? null : options.status_code,
    sandbox_verdict: normalizeSandboxVerdict(options.sandbox_verdict),
    network: normalizeNetwork(options.network),
    http_metadata: normalizeHttp(options.http_metadata),
    latency_ms:
      options.latency_ms === undefined || options.latency_ms === null
        ? null
        : Math.round(options.latency_ms),
    queue_latency_ms:
      options.queue_latency_ms === undefined ||
      options.queue_latency_ms === null
        ? null
        : Math.round(options.queue_latency_ms),
    user_context:
      options.user_context === undefined
        ? context.userContext
        : options.user_context,
    egress_type: options.egress_type === undefined ? null : options.egress_type,
    timestamp: new Date().toISOString(),
  }

  scrubSecretsInEvent(event)
  context.sink(event)

  return event
}

export function sanitizeCommandArgs(args: string[]): string {
  const sanitizedArgs: string[] = []
  let redactNext = false

  for (const arg of args) {
    if (redactNext) {
      sanitizedArgs.push(redactValue(arg))
      redactNext = false
      continue
    }

    if (SENSITIVE_FLAG_NAMES.has(arg.toLowerCase())) {
      sanitizedArgs.push(arg)
      redactNext = true
      continue
    }

    sanitizedArgs.push(sanitizeArg(arg))
  }

  return sanitizedArgs.join(' ')
}

export function sanitizeHeaders(
  headers: Record<string, number | string | string[] | undefined>,
  whitelist: Set<string> = DEFAULT_HEADER_WHITELIST,
): Record<string, string | null> {
  const sanitized: Record<string, string | null> = {}

  for (const [key, value] of Object.entries(headers)) {
    const lowercaseKey = key.toLowerCase()
    if (value === undefined) {
      sanitized[lowercaseKey] = null
      continue
    }

    if (!whitelist.has(lowercaseKey)) {
      sanitized[lowercaseKey] = '[REDACTED]'
      continue
    }

    const normalizedValue = Array.isArray(value)
      ? value.join(',')
      : String(value)
    sanitized[lowercaseKey] = autoRedactValue(normalizedValue)
  }

  return sanitized
}

export function redactValue(value: string): string {
  const hash = createHash('sha256').update(value).digest('hex')
  return `sha256:${hash}`
}

function sanitizeArg(arg: string): string {
  const trimmed = arg.trim()
  if (!trimmed) {
    return trimmed
  }

  const equalIndex = trimmed.indexOf('=')
  if (equalIndex > -1) {
    const key = trimmed.slice(0, equalIndex)
    const value = trimmed.slice(equalIndex + 1)
    if (isSensitiveKey(key) || looksSensitiveValue(value)) {
      return `${key}=${redactValue(value)}`
    }
    return trimmed
  }

  if (isSensitiveKey(trimmed) || looksSensitiveValue(trimmed)) {
    return redactValue(trimmed)
  }

  return trimmed
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/^-+/, '')
  return SENSITIVE_KEY_PATTERN.test(normalized)
}

function looksSensitiveValue(value: string): boolean {
  if (!value) {
    return false
  }

  if (SECRET_VALUE_PATTERN.test(value)) {
    return true
  }

  // Long base64/hex strings are suspicious
  const compact = value.replace(/[^a-z0-9]/gi, '')
  if (compact.length >= 24) {
    if (/^[a-f0-9]+$/i.test(compact) || /^[a-z0-9+/=]+$/i.test(value)) {
      return true
    }
  }

  return false
}

function normalizeSandboxVerdict(
  verdict: Partial<TelemetrySandboxVerdict> | null | undefined,
): TelemetrySandboxVerdict | null {
  if (!verdict) {
    return {
      decision: null,
      reason: null,
      policy_tag: null,
    }
  }

  return {
    decision: verdict.decision ?? null,
    reason: verdict.reason ?? null,
    policy_tag: verdict.policy_tag ?? null,
  }
}

function normalizeNetwork(
  network: Partial<TelemetryNetworkDetails> | null | undefined,
): TelemetryNetworkDetails | null {
  if (!network) {
    return {
      resolved_host: null,
      resolved_ip: null,
      tls_outcome: null,
      tls_error: null,
      dns_source: null,
    }
  }

  return {
    resolved_host: network.resolved_host ?? null,
    resolved_ip: network.resolved_ip ?? null,
    tls_outcome: network.tls_outcome ?? null,
    tls_error: network.tls_error ?? null,
    dns_source: network.dns_source ?? null,
  }
}

function normalizeHttp(
  metadata: Partial<TelemetryHttpMetadata> | null | undefined,
): TelemetryHttpMetadata | null {
  if (!metadata) {
    return {
      req_headers: null,
      resp_headers: null,
      payload_bytes: null,
      payload_hash: null,
      compression: null,
    }
  }

  return {
    req_headers: metadata.req_headers ?? null,
    resp_headers: metadata.resp_headers ?? null,
    payload_bytes:
      metadata.payload_bytes === undefined ? null : metadata.payload_bytes,
    payload_hash: metadata.payload_hash ?? null,
    compression: metadata.compression ?? null,
  }
}

function autoRedactValue(value: string): string {
  if (looksSensitiveValue(value)) {
    return redactValue(value)
  }
  return value
}

function scrubSecretsInEvent(event: TelemetryEvent): void {
  if (
    event.command &&
    looksSensitiveValue(event.command) &&
    !event.command.includes('sha256:')
  ) {
    event.command = redactValue(event.command)
  }

  if (
    event.user_context &&
    looksSensitiveValue(event.user_context) &&
    !event.user_context.includes('sha256:')
  ) {
    event.user_context = redactValue(event.user_context)
  }
}
