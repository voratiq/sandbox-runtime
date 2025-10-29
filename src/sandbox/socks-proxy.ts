import type { Server as NetServer } from 'net'
import {
  createServer,
  defaultConnectionHandler,
  type Socks5Server,
} from '@pondwader/socks5-server'
import { performance } from 'node:perf_hooks'
import { logForDebugging } from '../utils/debug.js'
import {
  emitTelemetryEvent,
  isTelemetryEnabled,
  type TelemetrySandboxVerdict,
} from '../utils/telemetry.js'

const SOCKS_STATUS_CODES = {
  REQUEST_GRANTED: 0,
  GENERAL_FAILURE: 1,
  CONNECTION_NOT_ALLOWED: 2,
  NETWORK_UNREACHABLE: 3,
  HOST_UNREACHABLE: 4,
  CONNECTION_REFUSED: 5,
  TTL_EXPIRED: 6,
  COMMAND_NOT_SUPPORTED: 7,
  ADDRESS_TYPE_NOT_SUPPORTED: 8,
} as const

type SocksStatusKey = keyof typeof SOCKS_STATUS_CODES

type RulesetValidator = NonNullable<Socks5Server['rulesetValidator']>
type SocksConnection = Parameters<RulesetValidator>[0]
type MetadataAwareConnection = SocksConnection & {
  metadata?: Record<string, unknown>
}
type TelemetryMetadata = Record<string, unknown> & {
  __telemetry?: SocksTelemetryContext
}

interface SocksTelemetryContext {
  host: string
  port: number
  attempt: number
  verdict: TelemetrySandboxVerdict
  startTime: number
  attemptTime: number
  egressType: string
}

export interface ProxyFilterDecision {
  allowed: boolean
  verdict: TelemetrySandboxVerdict
}

export interface SocksProxyServerOptions {
  filter(
    port: number,
    host: string,
  ): Promise<ProxyFilterDecision> | ProxyFilterDecision
}

export interface SocksProxyWrapper {
  server: Socks5Server
  getPort(): number | undefined
  listen(port: number, hostname: string): Promise<number>
  close(): Promise<void>
  unref(): void
}

function inferEgressType(port: number): string {
  if (port === 443) {
    return 'https'
  }
  if (port === 80) {
    return 'http'
  }
  return 'tcp'
}

function getOrInitMetadata(
  connection: MetadataAwareConnection,
): TelemetryMetadata {
  if (!connection.metadata || typeof connection.metadata !== 'object') {
    connection.metadata = {}
  }
  return connection.metadata as TelemetryMetadata
}

function attachTelemetryContext(
  connection: MetadataAwareConnection,
  context: SocksTelemetryContext,
): void {
  const metadata = getOrInitMetadata(connection)
  metadata.__telemetry = context
}

function getTelemetryContext(
  connection: MetadataAwareConnection,
): SocksTelemetryContext | undefined {
  const metadata = connection.metadata
  if (!metadata || typeof metadata !== 'object') {
    return undefined
  }
  return (metadata as TelemetryMetadata).__telemetry
}

export function createSocksProxyServer(
  options: SocksProxyServerOptions,
): SocksProxyWrapper {
  const socksServer = createServer()

  socksServer.setRulesetValidator(async (conn: MetadataAwareConnection) => {
    try {
      const telemetryActive = isTelemetryEnabled()
      const host = conn.destAddress
      const port = conn.destPort
      const egressType = inferEgressType(port)
      const startTime = telemetryActive ? performance.now() : 0

      if (telemetryActive) {
        emitTelemetryEvent({
          stage: 'start',
          status: 'success',
          attempt: 0,
          sandbox_verdict: {
            decision: 'pending',
            reason: 'socks_request_received',
            policy_tag: 'network.allowlist',
          },
          network: {
            resolved_host: host,
            resolved_ip: null,
            tls_outcome: null,
            tls_error: null,
            dns_source: null,
          },
          egress_type: egressType,
        })
      }

      let decision: ProxyFilterDecision
      try {
        decision = await options.filter(port, host)
      } catch (error) {
        logForDebugging(`Error validating connection: ${error}`, {
          level: 'error',
        })
        decision = {
          allowed: false,
          verdict: {
            decision: 'deny',
            reason: 'filter_failure',
            policy_tag: 'network.allowlist',
          },
        }
      }

      if (!decision.allowed) {
        if (telemetryActive) {
          emitTelemetryEvent({
            stage: 'failure',
            status: 'failed',
            attempt: 0,
            status_code: SOCKS_STATUS_CODES.CONNECTION_NOT_ALLOWED,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: host,
              resolved_ip: null,
              tls_outcome: null,
              tls_error: null,
              dns_source: null,
            },
            latency_ms: performance.now() - startTime,
            egress_type: egressType,
          })
        }
        return false
      }

      const attemptTime = telemetryActive ? performance.now() : 0

      if (telemetryActive) {
        emitTelemetryEvent({
          stage: 'attempt',
          status: 'success',
          attempt: 0,
          sandbox_verdict: decision.verdict,
          network: {
            resolved_host: host,
            resolved_ip: null,
            tls_outcome: null,
            tls_error: null,
            dns_source: null,
          },
          latency_ms: null,
          queue_latency_ms: attemptTime - startTime,
          egress_type: egressType,
        })
      }

      attachTelemetryContext(conn, {
        host,
        port,
        attempt: 0,
        verdict: decision.verdict,
        startTime,
        attemptTime,
        egressType,
      })

      return true
    } catch (error) {
      logForDebugging(`Error validating connection: ${error}`, {
        level: 'error',
      })
      return false
    }
  })

  socksServer.setConnectionHandler(
    (connection: MetadataAwareConnection, sendStatus) => {
      const telemetryActive = isTelemetryEnabled()
      const telemetryContext = telemetryActive
        ? getTelemetryContext(connection)
        : undefined
      let statusEmitted = false

      const wrappedSendStatus = (status: SocksStatusKey) => {
        if (telemetryActive && telemetryContext && !statusEmitted) {
          statusEmitted = true
          const latency = performance.now() - telemetryContext.attemptTime
          const statusCode =
            SOCKS_STATUS_CODES[status] ?? SOCKS_STATUS_CODES.GENERAL_FAILURE
          const success = status === 'REQUEST_GRANTED'

          emitTelemetryEvent({
            stage: success ? 'completion' : 'failure',
            status: success ? 'success' : 'failed',
            attempt: telemetryContext.attempt,
            status_code: statusCode,
            sandbox_verdict: telemetryContext.verdict,
            network: {
              resolved_host: telemetryContext.host,
              resolved_ip: null,
              tls_outcome: null,
              tls_error: success ? null : status,
              dns_source: null,
            },
            latency_ms: latency,
            egress_type: telemetryContext.egressType,
          })
        }

        sendStatus(status)
      }

      const stream = defaultConnectionHandler(
        connection as SocksConnection,
        wrappedSendStatus,
      )

      return stream
    },
  )

  return {
    server: socksServer,
    getPort(): number | undefined {
      try {
        const serverInternal = (
          socksServer as unknown as { server?: NetServer }
        )?.server
        if (serverInternal && typeof serverInternal?.address === 'function') {
          const address = serverInternal.address()
          if (address && typeof address === 'object' && 'port' in address) {
            return address.port
          }
        }
      } catch (error) {
        logForDebugging(`Error getting port: ${error}`, { level: 'error' })
      }
      return undefined
    },
    listen(port: number, hostname: string): Promise<number> {
      return new Promise((resolve, reject) => {
        const listeningCallback = (): void => {
          const actualPort = this.getPort()
          if (actualPort) {
            logForDebugging(
              `SOCKS proxy listening on ${hostname}:${actualPort}`,
            )
            resolve(actualPort)
          } else {
            reject(new Error('Failed to get SOCKS proxy server port'))
          }
        }
        socksServer.listen(port, hostname, listeningCallback)
      })
    },
    async close(): Promise<void> {
      return new Promise((resolve, reject) => {
        socksServer.close(error => {
          if (error) {
            const errorMessage = error.message?.toLowerCase() || ''
            const isAlreadyClosed =
              errorMessage.includes('not running') ||
              errorMessage.includes('already closed') ||
              errorMessage.includes('not listening')

            if (!isAlreadyClosed) {
              reject(error)
              return
            }
          }
          resolve()
        })
      })
    },
    unref(): void {
      try {
        const serverInternal = (
          socksServer as unknown as { server?: NetServer }
        )?.server
        if (serverInternal && typeof serverInternal?.unref === 'function') {
          serverInternal.unref()
        }
      } catch (error) {
        logForDebugging(`Error calling unref: ${error}`, { level: 'error' })
      }
    },
  }
}
