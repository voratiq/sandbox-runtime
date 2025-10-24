import { isIP } from 'node:net'
import { z } from 'zod'

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

export function generateHostListSchema(allowedOrDenied: 'allowed' | 'denied') {
  return z
    .array(z.string())
    .describe(
      `List of automatically ${allowedOrDenied} network hosts (e.g., ["github.com:443", "api.example.com"])`,
    )
    .transform((patterns): string[] => {
      // Parse and validate each host pattern
      return patterns.map(pattern => {
        const parsed = safeParseRestrictionPattern(pattern)
        if (parsed instanceof Error) {
          throw new Error(`Invalid network host pattern: ${parsed.message}`)
        }
        // Return the original validated string, not the parsed pattern
        return pattern
      })
    })
}

// Port number schema
const portNumberSchema = z
  .string()
  .regex(/^\d+$/)
  .transform(val => parseInt(val, 10))
  .refine(
    port => port >= 1 && port <= 65535,
    'Port must be between 1 and 65535',
  )

// Schema for IPv6 addresses without port
// Examples: "::1" (IPv6 loopback), "2001:db8::1", "fe80::1"
const ipv6Schema = z
  .string()
  .refine(val => isIP(val) === 6 && !val.includes('[') && !val.includes(']'))
  .transform(
    (val): NetworkHostPattern => ({
      host: val,
      port: undefined,
    }),
  )

// Schema for IPv6 addresses with port (requires bracket notation)
// Examples: "[::1]:8080", "[2001:db8::1]:443", "[fe80::1]:22"
const ipv6WithPortSchema = z
  .string()
  .regex(/^\[([^\]]+)\]:(\d+)$/)
  .transform((val): NetworkHostPattern => {
    const match = val.match(/^\[([^\]]+)\]:(\d+)$/)!
    const host = match[1]!
    const portStr = match[2]!

    // Validate that the host part is actually an IPv6 address
    if (isIP(host) !== 6) {
      throw new Error('Invalid IPv6 address in bracket notation')
    }

    // Parse and validate port
    const portResult = portNumberSchema.safeParse(portStr)
    if (!portResult.success) {
      throw new Error('Invalid port number')
    }
    const port = portResult.data

    return { host, port }
  })

// Schema for IPv4 addresses without port
// Examples: "192.168.1.1", "127.0.0.1", "10.0.0.1"
const ipv4Schema = z
  .string()
  .refine(val => isIP(val) === 4)
  .transform(
    (val): NetworkHostPattern => ({
      host: val,
      port: undefined,
    }),
  )

// Schema for IPv4 addresses with port
// Examples: "192.168.1.1:8080", "127.0.0.1:443", "10.0.0.1:22"
const ipv4WithPortSchema = z
  .string()
  .regex(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/)
  .transform((val): NetworkHostPattern => {
    const match = val.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/)!
    const host = match[1]!
    const portStr = match[2]!

    // Validate that the host part is actually an IPv4 address
    if (isIP(host) !== 4) {
      throw new Error('Invalid IPv4 address format')
    }

    // Parse and validate port
    const portResult = portNumberSchema.safeParse(portStr)
    if (!portResult.success) {
      throw new Error('Invalid port number')
    }
    const port = portResult.data

    return { host, port }
  })

// Base schema for validating domain names (not IP addresses)
// Examples: "example.com", "localhost", "*.example.com", "sub.domain.com"
const domainNameSchema = z.string().refine(val => {
  // Basic format checks
  if (
    val.length === 0 ||
    val.includes(':') || // No colons (would indicate port or IPv6)
    val.includes('/') || // No paths or protocol prefixes
    val.includes('?') || // No query strings
    val.includes('#') || // No fragments
    isIP(val) // Not an IP address
  ) {
    return false
  }

  // Special case: localhost is always valid
  if (val === 'localhost') {
    return true
  }

  // Wildcard domains: *.example.com (must have dot after wildcard)
  if (val.startsWith('*.')) {
    const domainPart = val.slice(2)
    return (
      domainPart.includes('.') &&
      !domainPart.startsWith('.') &&
      !domainPart.endsWith('.')
    )
  }

  // Regular domains: must contain at least one dot and not start/end with dot
  return val.includes('.') && !val.startsWith('.') && !val.endsWith('.')
})

// Schema for domain name without port
// Examples: "example.com", "*.example.com", "localhost"
const hostnameSchema = domainNameSchema.transform(
  (val): NetworkHostPattern => ({
    host: val,
    port: undefined,
  }),
)

// Schema for domain name with port
// Examples: "example.com:8080", "localhost:3000", "*.example.com:443"
const hostnameWithPortSchema = z
  .string()
  .regex(/^([^:]+):(\d+)$/)
  .transform((val): NetworkHostPattern => {
    const match = val.match(/^([^:]+):(\d+)$/)!
    const host = match[1]!
    const portStr = match[2]!

    // Validate that the host part is a valid domain name
    const hostResult = domainNameSchema.safeParse(host)
    if (!hostResult.success) {
      throw new Error('Invalid domain name')
    }

    // Parse and validate port
    const portResult = portNumberSchema.safeParse(portStr)
    if (!portResult.success) {
      throw new Error('Invalid port number')
    }
    const port = portResult.data

    return { host, port }
  })

// Combined schema that tries each pattern in order
const hostPatternSchema = z.union([
  ipv6WithPortSchema,
  ipv6Schema,
  ipv4WithPortSchema,
  ipv4Schema,
  hostnameWithPortSchema,
  hostnameSchema,
])

/**
 * Safely parse a network restriction pattern.
 * Returns the parsed pattern or an Error.
 */
export function safeParseRestrictionPattern(
  pattern: string,
): NetworkHostPattern | Error {
  const result = hostPatternSchema.safeParse(pattern)
  if (!result.success) {
    // Provide helpful error messages for common mistakes
    if (pattern.startsWith('http://') || pattern.startsWith('https://')) {
      return Error(
        `Invalid network restriction: "${pattern}" - remove the protocol (http:// or https://)`,
      )
    }
    if (pattern.includes('/')) {
      return Error(
        `Invalid network restriction: "${pattern}" - paths are not allowed, only hosts`,
      )
    }
    if (pattern === '') {
      return Error(
        `Invalid network restriction: empty string - please provide a host`,
      )
    }
    if (pattern.endsWith(':')) {
      return Error(
        `Invalid network restriction: "${pattern}" - incomplete port specification`,
      )
    }
    return Error(`Invalid network restriction: "${pattern}"`)
  }
  return result.data
}

/**
 * Schema for command-specific sandbox violation ignore patterns.
 * Maps command patterns to lists of filesystem paths to ignore violations for.
 * The special key "*" matches all commands.
 *
 * Example:
 * {
 *   "*": ["/usr/bin", "/System"],           // Ignore for all commands
 *   "git push": ["/usr/bin/nc"],            // Ignore nc errors when running git push
 *   "npm": ["/private/tmp"],                // Ignore tmp access for npm commands
 * }
 */
export const IgnoreViolationsSchema = z
  .record(
    z.string(),
    z
      .array(z.string())
      .describe(
        'List of filesystem paths to ignore sandbox violations for when this command pattern matches',
      ),
  )
  .describe(
    'Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands',
  )

export type IgnoreViolationsConfig = z.infer<typeof IgnoreViolationsSchema>

// ============================================================================
// COMBINED SCHEMAS
// ============================================================================

// Network restriction schemas
export const NetworkConfigSchema = z
  .object({
    allowUnixSockets: z
      .array(z.string())
      .optional()
      .describe(
        'Allow Unix domain sockets for local IPC (SSH agent, Docker, etc.). Provide an array of specific paths. Defaults to blocking if not specified. ' +
          'IMPORTANT: On Linux, this configuration is not supported.',
      ),
    allowAllUnixSockets: z
      .boolean()
      .optional()
      .describe(
        'Allow all Unix domain socket connections without restrictions. ' +
          'On Linux, this disables the seccomp filter that blocks Unix sockets and allows sandboxing without seccomp dependencies (gcc/clang/libseccomp-dev). ' +
          'On macOS, this allows all Unix socket paths. ' +
          'WARNING: This significantly reduces sandbox security by allowing arbitrary Unix socket connections. ' +
          'Only enable if Unix socket access is required and the security trade-off is acceptable. ' +
          'Default: false (secure).',
      ),
    allowLocalBinding: z
      .boolean()
      .optional()
      .describe(
        'Allow binding to local network addresses (e.g., localhost ports). Defaults to false if not specified',
      ),
    httpProxyPort: z
      .number()
      .int()
      .min(1)
      .max(65535)
      .optional()
      .describe(
        'HTTP proxy port to use for network filtering. If not specified, a proxy server will be started automatically',
      ),
    socksProxyPort: z
      .number()
      .int()
      .min(1)
      .max(65535)
      .optional()
      .describe(
        'SOCKS proxy port to use for network filtering. If not specified, a proxy server will be started automatically',
      ),
  })
  .optional()

// Complete sandbox config schema
export const SandboxConfigSchema = z.object({
  network: NetworkConfigSchema,
  ignoreViolations: IgnoreViolationsSchema.optional(),
  enableWeakerNestedSandbox: z
    .boolean()
    .optional()
    .describe(
      'Enable weaker sandbox mode for unprivileged docker environments where --proc mounting fails. ' +
        'This significantly reduces the strength of the sandbox and should only be used when this risk is acceptable.' +
        'Default: false (secure).',
    ),
})

export type SandboxConfig = z.infer<typeof SandboxConfigSchema>
