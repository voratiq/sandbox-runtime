import { execFile } from 'child_process'
import { promisify } from 'util'

const execFilePromise = promisify(execFile)

/**
 * Simple wrapper around execFile that doesn't throw on non-zero exit codes
 * Simplified version for standalone sandbox use
 */
export async function execFileNoThrow(
  file: string,
  args: string[],
  options: { timeout?: number; cwd?: string } = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const result = await execFilePromise(file, args, {
      timeout: options.timeout || 10000,
      cwd: options.cwd,
      maxBuffer: 10 * 1024 * 1024, // 10MB
    })
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      code: 0,
    }
  } catch (error: unknown) {
    // execFile throws on non-zero exit, but we want to return the result
    if (error && typeof error === 'object' && 'code' in error) {
      return {
        stdout: (error as { stdout?: string }).stdout || '',
        stderr: (error as { stderr?: string }).stderr || '',
        code: typeof error.code === 'number' ? error.code : 1,
      }
    }
    // For other errors (like ENOENT), return error info
    return {
      stdout: '',
      stderr: error instanceof Error ? error.message : String(error),
      code: 1,
    }
  }
}
