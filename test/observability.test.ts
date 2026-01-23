import { describe, it, expect } from 'bun:test'
import * as net from 'node:net'
import { once } from 'node:events'
import { createHttpProxyServer } from '../src/sandbox/http-proxy.js'
import { createSocksProxyServer } from '../src/sandbox/socks-proxy.js'
import {
  pushSandboxEventContext,
  scrubSecrets,
} from '../src/sandbox/observability.js'

describe('observability', () => {
  it('scrubs secrets in strings and objects', () => {
    const input = {
      cmd: 'curl --token abc --password=def --key ghi --auth jkl',
      url: 'https://example.com/path?token=abc&x=1#hash',
      headers: {
        Authorization: 'Bearer SECRET',
        Cookie: 'a=b',
        'X-Api-Key': 'key',
        'Proxy-Authorization': 'Basic abc123',
        Other: 'ok',
      },
      env: {
        MY_TOKEN: 'abc',
        SAFE: 'yes',
      },
    }

    const scrubbed = scrubSecrets(input) as typeof input

    expect(scrubbed.cmd).toContain('--token [REDACTED]')
    expect(scrubbed.cmd).toContain('--password=[REDACTED]')
    expect(scrubbed.cmd).toContain('--key [REDACTED]')
    expect(scrubbed.cmd).toContain('--auth [REDACTED]')

    // Query value is URL-encoded "[REDACTED]"
    expect(scrubbed.url).toContain('token=%5BREDACTED%5D')
    expect(scrubbed.url).toContain('x=1')

    expect(scrubbed.headers.Authorization).toBe('[REDACTED]')
    expect(scrubbed.headers.Cookie).toBe('[REDACTED]')
    expect(scrubbed.headers['X-Api-Key']).toBe('[REDACTED]')
    expect(scrubbed.headers['Proxy-Authorization']).toBe('[REDACTED]')
    expect(scrubbed.headers.Other).toBe('ok')

    expect(scrubbed.env.MY_TOKEN).toBe('[REDACTED]')
    expect(scrubbed.env.SAFE).toBe('yes')
  })

  it('emits a structured HTTP proxy network decision event', async () => {
    const events: unknown[] = []
    const dispose = pushSandboxEventContext({
      correlationId: 'abc-123',
      onEvent: e => events.push(e),
    })

    const server = createHttpProxyServer({
      filter: () => ({ allowed: false, reason: 'denylist' }),
      getMitmSocketPath: () => '/tmp/fake-mitm.sock',
    })

    try {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject)
        server.listen(0, '127.0.0.1', () => resolve())
      })

      const addr = server.address()
      if (!addr || typeof addr !== 'object') {
        throw new Error('Failed to get proxy server address')
      }

      const socket = net.connect(addr.port, '127.0.0.1')
      socket.write(
        'CONNECT example.com:443 HTTP/1.1\r\n' +
          'Host: example.com:443\r\n' +
          '\r\n',
      )
      await once(socket, 'data')
      socket.destroy()

      const event = events.find(
        e => (e as { type?: string }).type === 'network',
      ) as
        | undefined
        | {
            type: 'network'
            ts: number
            correlation_id: string
            host: string
            port: number
            decision: 'allow' | 'deny'
            reason: 'allowlist' | 'denylist' | 'no-match'
            route: 'direct' | 'mitm'
          }

      expect(event).toBeDefined()
      expect(typeof event?.ts).toBe('number')
      expect(event).toMatchObject({
        type: 'network',
        correlation_id: 'abc-123',
        host: 'example.com',
        port: 443,
        decision: 'deny',
        reason: 'denylist',
        route: 'mitm',
      })
    } finally {
      dispose()
      server.close()
    }
  })

  it('emits a structured SOCKS proxy network decision event', async () => {
    const events: unknown[] = []
    const dispose = pushSandboxEventContext({
      correlationId: 'abc-123',
      onEvent: e => events.push(e),
    })

    const proxy = createSocksProxyServer({
      filter: () => ({ allowed: false, reason: 'denylist' }),
    })

    try {
      const port = await proxy.listen(0, '127.0.0.1')

      const socket = net.connect(port, '127.0.0.1')

      // Greeting: version 5, 1 method, no-auth (0x00)
      socket.write(Buffer.from([0x05, 0x01, 0x00]))
      await once(socket, 'data')

      // Connect request: example.com:443
      const host = Buffer.from('example.com')
      const req = Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
        host,
        Buffer.from([0x01, 0xbb]),
      ])
      socket.write(req)
      await once(socket, 'data')
      socket.destroy()

      const event = events.find(
        e => (e as { type?: string }).type === 'network',
      ) as
        | undefined
        | {
            type: 'network'
            ts: number
            correlation_id: string
            host: string
            port: number
            decision: 'allow' | 'deny'
            reason: 'allowlist' | 'denylist' | 'no-match'
            route: 'direct' | 'mitm'
          }

      expect(event).toBeDefined()
      expect(event).toMatchObject({
        type: 'network',
        correlation_id: 'abc-123',
        host: 'example.com',
        port: 443,
        decision: 'deny',
        reason: 'denylist',
        route: 'direct',
      })
    } finally {
      dispose()
      await proxy.close()
    }
  })
})
