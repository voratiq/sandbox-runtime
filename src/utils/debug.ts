/**
 * Simple debug logging for standalone sandbox
 */
export function logForDebugging(
  message: string,
  options?: { level?: 'info' | 'error' | 'warn' },
): void {
  // Only log if DEBUG environment variable is set
  if (!process.env.DEBUG) {
    return
  }

  const level = options?.level || 'info'
  const prefix = '[SandboxDebug]'

  switch (level) {
    case 'error':
      console.error(`${prefix} ${message}`)
      break
    case 'warn':
      console.warn(`${prefix} ${message}`)
      break
    default:
      console.log(`${prefix} ${message}`)
  }
}
