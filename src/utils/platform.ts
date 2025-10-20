/**
 * Platform detection utilities
 */

export type Platform = 'macos' | 'linux' | 'windows' | 'unknown'

export function getPlatform(): Platform {
  switch (process.platform) {
    case 'darwin':
      return 'macos'
    case 'linux':
      return 'linux'
    case 'win32':
      return 'windows'
    default:
      return 'unknown'
  }
}
