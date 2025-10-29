import { describe, test, beforeEach, afterEach, expect } from 'bun:test'
import {
  initializeTelemetry,
  emitTelemetryEvent,
  setTelemetrySink,
  sanitizeHeaders,
  sanitizeCommandArgs,
  type TelemetryEvent,
} from '../src/utils/telemetry.js'

describe('Telemetry module', () => {
  beforeEach(() => {
    // Reset module state before each test
    initializeTelemetry({ debugEnabled: false })
    setTelemetrySink(null)
  })

  afterEach(() => {
    initializeTelemetry({ debugEnabled: false })
    setTelemetrySink(null)
    delete process.env.SRT_TRACE_ID
    delete process.env.DEBUG
  })

  test('does not emit events when telemetry is disabled', () => {
    const events: TelemetryEvent[] = []
    setTelemetrySink(event => {
      events.push(event)
    })

    emitTelemetryEvent({
      stage: 'start',
      status: 'success',
    })

    expect(events.length).toBe(0)
  })

  test('redacts sensitive command arguments when telemetry enabled', () => {
    const events: TelemetryEvent[] = []
    setTelemetrySink(event => {
      events.push(event)
    })

    initializeTelemetry({
      debugEnabled: true,
      commandArgs: [
        'curl',
        '--token',
        'secret-value-that-should-not-leak',
        '--api-key=sk-1234567890ABCDEFGHIJK',
      ],
    })

    emitTelemetryEvent({
      stage: 'start',
      status: 'success',
    })

    expect(events.length).toBe(1)
    const emittedCommand = events[0].command ?? ''
    expect(emittedCommand).toContain('--token sha256:')
    expect(emittedCommand).toContain('--api-key=sha256:')
    expect(emittedCommand).not.toContain('secret-value-that-should-not-leak')
    expect(emittedCommand).not.toContain('sk-1234567890ABCDEFGHIJK')
  })

  test('sanitizeHeaders obfuscates non-whitelisted headers', () => {
    const sanitized = sanitizeHeaders({
      authorization: 'Bearer abcdef',
      'x-request-id': 'req-123',
      host: 'example.com',
      'content-encoding': 'gzip',
    })

    expect(sanitized['authorization']).toBe('[REDACTED]')
    expect(sanitized['host']).toBe('[REDACTED]')
    expect(sanitized['x-request-id']).toBe('req-123')
    expect(sanitized['content-encoding']).toBe('gzip')
  })

  test('sanitizeCommandArgs hashes long opaque values heuristically', () => {
    const command = sanitizeCommandArgs([
      'python',
      'script.py',
      '--password=super-secret-password',
      'sk-abcdefghijklmnopqrstuvwxyz0123',
    ])

    expect(command).toContain('--password=sha256:')
    expect(command).toContain('sha256:')
    expect(command).not.toContain('super-secret-password')
    expect(command).not.toContain('sk-abcdefghijklmnopqrstuvwxyz0123')
  })
})
