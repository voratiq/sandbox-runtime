import type { Socket, Server } from 'node:net'
import type { Duplex } from 'node:stream'
import { createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect } from 'node:net'
import type { TLSSocket } from 'node:tls'
import { URL } from 'node:url'
import { performance } from 'node:perf_hooks'
import { createHash } from 'node:crypto'
import { logForDebugging } from '../utils/debug.js'
import {
  emitTelemetryEvent,
  isTelemetryEnabled,
  sanitizeHeaders,
  type TelemetrySandboxVerdict,
} from '../utils/telemetry.js'

export interface ProxyFilterDecision {
  allowed: boolean
  verdict: TelemetrySandboxVerdict
}

export interface HttpProxyServerOptions {
  filter(
    port: number,
    host: string,
    socket: Socket | Duplex,
  ): Promise<ProxyFilterDecision> | ProxyFilterDecision
}

const HTTP_FORBIDDEN_RESPONSE =
  'HTTP/1.1 403 Forbidden\r\n' +
  'Content-Type: text/plain\r\n' +
  'X-Proxy-Error: blocked-by-allowlist\r\n' +
  '\r\n' +
  'Connection blocked by network allowlist'

function inferEgressType(port: number | undefined, protocol?: string): string {
  if (protocol === 'https:') {
    return 'https'
  }
  if (protocol === 'http:') {
    return 'http'
  }
  if (port === 443) {
    return 'https'
  }
  if (port === 80) {
    return 'http'
  }
  return 'tcp'
}

function getCompressionHeader(
  headers: Record<string, number | string | string[] | undefined>,
): string | null {
  const value = headers['content-encoding']
  if (!value) {
    return null
  }
  if (Array.isArray(value)) {
    return value[0] ?? null
  }
  return String(value)
}

export function createHttpProxyServer(options: HttpProxyServerOptions): Server {
  const server = createServer()

  server.on('connect', async (req, socket) => {
    socket.on('error', err => {
      logForDebugging(`Client socket error: ${err.message}`, { level: 'error' })
    })

    try {
      const [hostname, portStr] = req.url!.split(':')
      const port = portStr === undefined ? undefined : parseInt(portStr, 10)

      if (!hostname || !port || Number.isNaN(port)) {
        logForDebugging(`Invalid CONNECT request: ${req.url}`, {
          level: 'error',
        })
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }

      const telemetryActive = isTelemetryEnabled()
      const egressType = inferEgressType(port, 'https:')
      const startTime = telemetryActive ? performance.now() : 0

      if (telemetryActive) {
        emitTelemetryEvent({
          stage: 'start',
          status: 'success',
          attempt: 0,
          sandbox_verdict: {
            decision: 'pending',
            reason: 'connect_request_received',
            policy_tag: 'network.allowlist',
          },
          network: {
            resolved_host: hostname,
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
        decision = await options.filter(port, hostname, socket)
      } catch (error) {
        logForDebugging(`Filter threw error: ${error}`, { level: 'error' })
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
            status_code: 403,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: hostname,
              resolved_ip: null,
              tls_outcome: null,
              tls_error: null,
              dns_source: null,
            },
            latency_ms: performance.now() - startTime,
            egress_type: egressType,
          })
        }

        socket.end(HTTP_FORBIDDEN_RESPONSE)
        return
      }

      if (telemetryActive) {
        emitTelemetryEvent({
          stage: 'attempt',
          status: 'success',
          attempt: 0,
          sandbox_verdict: decision.verdict,
          network: {
            resolved_host: hostname,
            resolved_ip: null,
            tls_outcome: null,
            tls_error: null,
            dns_source: null,
          },
          latency_ms: null,
          queue_latency_ms: performance.now() - startTime,
          egress_type: egressType,
        })
      }

      const attemptStart = telemetryActive ? performance.now() : 0
      let resolvedIp: string | null = null
      let completionEmitted = false
      let tlsError: string | null = null

      const serverSocket = connect(port, hostname, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        serverSocket.pipe(socket)
        socket.pipe(serverSocket)

        if (telemetryActive && !completionEmitted) {
          completionEmitted = true
          emitTelemetryEvent({
            stage: 'completion',
            status: 'success',
            attempt: 0,
            status_code: 200,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: hostname,
              resolved_ip: resolvedIp ?? serverSocket.remoteAddress ?? null,
              tls_outcome: 'tunnel_established',
              tls_error: tlsError,
              dns_source: resolvedIp ? 'system' : null,
            },
            latency_ms: performance.now() - attemptStart,
            egress_type: egressType,
          })
        }
      })

      serverSocket.once('lookup', (err, address) => {
        if (err) {
          tlsError = err.message
          return
        }
        resolvedIp = address
      })

      serverSocket.on('error', err => {
        logForDebugging(`CONNECT tunnel failed: ${err.message}`, {
          level: 'error',
        })
        if (telemetryActive && !completionEmitted) {
          completionEmitted = true
          emitTelemetryEvent({
            stage: 'failure',
            status: 'failed',
            attempt: 0,
            status_code: 502,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: hostname,
              resolved_ip: resolvedIp,
              tls_outcome: 'tunnel_error',
              tls_error: err.message,
              dns_source: resolvedIp ? 'system' : null,
            },
            latency_ms: performance.now() - attemptStart,
            egress_type: egressType,
          })
        }
        socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      })

      socket.on('error', err => {
        logForDebugging(`Client socket error: ${err.message}`, {
          level: 'error',
        })
        serverSocket.destroy()
        if (telemetryActive && !completionEmitted) {
          completionEmitted = true
          emitTelemetryEvent({
            stage: 'failure',
            status: 'failed',
            attempt: 0,
            status_code: null,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: hostname,
              resolved_ip: resolvedIp,
              tls_outcome: 'client_socket_error',
              tls_error: err.message,
              dns_source: resolvedIp ? 'system' : null,
            },
            latency_ms: performance.now() - attemptStart,
            egress_type: egressType,
          })
        }
      })

      socket.on('end', () => serverSocket.end())
      serverSocket.on('end', () => socket.end())
    } catch (err) {
      logForDebugging(`Error handling CONNECT: ${err}`, { level: 'error' })
      socket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n')
    }
  })

  server.on('request', async (req, res) => {
    const telemetryActive = isTelemetryEnabled()
    const startTime = telemetryActive ? performance.now() : 0

    try {
      const url = new URL(req.url!)
      const hostname = url.hostname
      const port =
        url.port && url.port !== ''
          ? parseInt(url.port, 10)
          : url.protocol === 'https:'
            ? 443
            : 80

      const egressType = inferEgressType(port, url.protocol)

      if (telemetryActive) {
        emitTelemetryEvent({
          stage: 'start',
          status: 'success',
          attempt: 0,
          sandbox_verdict: {
            decision: 'pending',
            reason: 'http_request_received',
            policy_tag: 'network.allowlist',
          },
          network: {
            resolved_host: hostname,
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
        decision = await options.filter(port, hostname, req.socket)
      } catch (error) {
        logForDebugging(`Filter threw error: ${error}`, { level: 'error' })
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
            status_code: 403,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: hostname,
              resolved_ip: null,
              tls_outcome: null,
              tls_error: null,
              dns_source: null,
            },
            latency_ms: performance.now() - startTime,
            egress_type: egressType,
          })
        }

        res.writeHead(403, {
          'Content-Type': 'text/plain',
          'X-Proxy-Error': 'blocked-by-allowlist',
        })
        res.end('Connection blocked by network allowlist')
        return
      }

      if (telemetryActive) {
        emitTelemetryEvent({
          stage: 'attempt',
          status: 'success',
          attempt: 0,
          sandbox_verdict: decision.verdict,
          network: {
            resolved_host: hostname,
            resolved_ip: null,
            tls_outcome: null,
            tls_error: null,
            dns_source: null,
          },
          latency_ms: null,
          queue_latency_ms: performance.now() - startTime,
          egress_type: egressType,
        })
      }

      const attemptStart = telemetryActive ? performance.now() : 0
      let resolvedIp: string | null = null
      let tlsOutcome: string | null =
        url.protocol === 'https:' ? 'handshake_pending' : null
      let tlsError: string | null = null
      let telemetryCompleted = false

      const requestHeaders = telemetryActive
        ? sanitizeHeaders(
            req.headers as Record<
              string,
              string | string[] | number | undefined
            >,
          )
        : {}

      const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest

      const proxyReq = requestFn(
        {
          hostname,
          port,
          path: url.pathname + url.search,
          method: req.method,
          headers: {
            ...req.headers,
            host: url.host,
          },
        },
        proxyRes => {
          res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers)

          const responseHeaders = telemetryActive
            ? sanitizeHeaders(
                proxyRes.headers as Record<
                  string,
                  string | string[] | number | undefined
                >,
              )
            : null

          let responseBytes = 0
          const hash = telemetryActive ? createHash('sha256') : null

          if (telemetryActive && hash) {
            proxyRes.on('data', chunk => {
              responseBytes += chunk.length
              hash.update(chunk)
            })
          }

          proxyRes.on('end', () => {
            if (telemetryActive && !telemetryCompleted) {
              telemetryCompleted = true
              const latency = performance.now() - attemptStart
              const payloadHash =
                hash && responseBytes > 0 ? hash.digest('hex') : null

              emitTelemetryEvent({
                stage: 'completion',
                status:
                  proxyRes.statusCode &&
                  proxyRes.statusCode >= 200 &&
                  proxyRes.statusCode < 400
                    ? 'success'
                    : 'failed',
                attempt: 0,
                status_code: proxyRes.statusCode ?? null,
                sandbox_verdict: decision.verdict,
                network: {
                  resolved_host: hostname,
                  resolved_ip:
                    resolvedIp ??
                    (proxyRes.socket
                      ? (proxyRes.socket.remoteAddress ?? null)
                      : null),
                  tls_outcome: tlsOutcome,
                  tls_error: tlsError,
                  dns_source: resolvedIp ? 'system' : null,
                },
                http_metadata: {
                  req_headers: requestHeaders,
                  resp_headers: responseHeaders,
                  payload_bytes: responseBytes,
                  payload_hash: payloadHash,
                  compression: responseHeaders
                    ? getCompressionHeader(
                        proxyRes.headers as Record<
                          string,
                          number | string | string[] | undefined
                        >,
                      )
                    : null,
                },
                latency_ms: latency,
                egress_type: egressType,
              })
            }
          })

          proxyRes.on('error', err => {
            logForDebugging(`Proxy response error: ${err.message}`, {
              level: 'error',
            })
            if (telemetryActive && !telemetryCompleted) {
              telemetryCompleted = true
              emitTelemetryEvent({
                stage: 'failure',
                status: 'failed',
                attempt: 0,
                status_code: null,
                sandbox_verdict: decision.verdict,
                network: {
                  resolved_host: hostname,
                  resolved_ip: resolvedIp,
                  tls_outcome: tlsOutcome,
                  tls_error: err.message,
                  dns_source: resolvedIp ? 'system' : null,
                },
                http_metadata: {
                  req_headers: requestHeaders,
                  resp_headers: responseHeaders,
                  payload_bytes: null,
                  payload_hash: null,
                  compression: null,
                },
                latency_ms: performance.now() - attemptStart,
                egress_type: egressType,
              })
            }
          })

          proxyRes.pipe(res)
        },
      )

      proxyReq.on('socket', (socket: Socket) => {
        if (!telemetryActive) {
          return
        }

        socket.once('lookup', (err, address) => {
          if (err) {
            tlsError = err.message
            return
          }
          resolvedIp = address
        })

        socket.once('error', err => {
          tlsError = err.message
        })

        if (url.protocol === 'https:') {
          ;(socket as TLSSocket).once('secureConnect', () => {
            tlsOutcome = 'handshake_success'
          })
        }
      })

      proxyReq.on('error', err => {
        logForDebugging(`Proxy request failed: ${err.message}`, {
          level: 'error',
        })

        if (telemetryActive && !telemetryCompleted) {
          telemetryCompleted = true
          emitTelemetryEvent({
            stage: 'failure',
            status: 'failed',
            attempt: 0,
            status_code: null,
            sandbox_verdict: decision.verdict,
            network: {
              resolved_host: hostname,
              resolved_ip: resolvedIp,
              tls_outcome:
                url.protocol === 'https:'
                  ? 'handshake_error'
                  : 'connection_error',
              tls_error: err.message,
              dns_source: resolvedIp ? 'system' : null,
            },
            http_metadata: {
              req_headers: requestHeaders,
              resp_headers: null,
              payload_bytes: null,
              payload_hash: null,
              compression: null,
            },
            latency_ms: performance.now() - attemptStart,
            egress_type: egressType,
          })
        }

        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain' })
          res.end('Bad Gateway')
        }
      })

      req.pipe(proxyReq)
    } catch (err) {
      logForDebugging(`Error handling HTTP request: ${err}`, { level: 'error' })
      res.writeHead(500, { 'Content-Type': 'text/plain' })
      res.end('Internal Server Error')
    }
  })

  return server
}
