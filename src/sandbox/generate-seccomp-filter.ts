import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as fs from 'node:fs'
import { logForDebugging } from '../utils/debug.js'
import { spawnSync } from 'node:child_process'
import { memoize } from 'lodash-es'

/**
 * Map Node.js process.arch to our vendor directory architecture names
 * Returns null for unsupported architectures
 */
function getVendorArchitecture(): string | null {
  const arch = process.arch as string
  switch (arch) {
    case 'x64':
    case 'x86_64':
      return 'x64'
    case 'arm64':
    case 'aarch64':
      return 'arm64'
    case 'ia32':
    case 'x86':
      // TODO: Add support for 32-bit x86 (ia32)
      // Currently blocked because the seccomp filter does not block the socketcall() syscall,
      // which is used on 32-bit x86 for all socket operations (socket, socketpair, bind, connect, etc.).
      // On 32-bit x86, the direct socket() syscall doesn't exist - instead, all socket operations
      // are multiplexed through socketcall(SYS_SOCKET, ...), socketcall(SYS_SOCKETPAIR, ...), etc.
      //
      // To properly support 32-bit x86, we need to:
      // 1. Build a separate i386 BPF filter (BPF bytecode is architecture-specific)
      // 2. Modify vendor/seccomp-src/seccomp-unix-block.c to conditionally add rules that block:
      //    - socketcall(SYS_SOCKET, [AF_UNIX, ...])
      //    - socketcall(SYS_SOCKETPAIR, [AF_UNIX, ...])
      // 3. This requires complex BPF logic to inspect socketcall's sub-function argument
      //
      // Until then, 32-bit x86 is not supported to avoid a security bypass.
      logForDebugging(
        `[SeccompFilter] 32-bit x86 (ia32) is not currently supported due to missing socketcall() syscall blocking. ` +
        `The current seccomp filter only blocks socket(AF_UNIX, ...), but on 32-bit x86, socketcall() can be used to bypass this.`,
        { level: 'error' },
      )
      return null
    default:
      logForDebugging(
        `[SeccompFilter] Unsupported architecture: ${arch}. Only x64 and arm64 are supported.`,
      )
      return null
  }
}

/**
 * Check if Python 3 is available (synchronous)
 * Python 3 is required for applying seccomp filters via the helper script
 * Memoized to avoid repeated system calls
 */
export const hasPython3Sync = memoize((): boolean => {
  try {
    const result = spawnSync('python3', ['--version'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    return result.status === 0
  } catch {
    return false
  }
})

/**
 * Check if seccomp dependencies are available (synchronous)
 * Returns true if (gcc OR clang) AND libseccomp-dev are installed
 * Memoized to avoid repeated system calls
 */
export const hasSeccompDependenciesSync = memoize((): boolean => {
  try {
    // Check for gcc or clang
    const gccResult = spawnSync('which', ['gcc'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    const clangResult = spawnSync('which', ['clang'], {
      stdio: 'ignore',
      timeout: 1000,
    })

    const hasCompiler = gccResult.status === 0 || clangResult.status === 0
    if (!hasCompiler) {
      return false
    }

    // Check for libseccomp by trying to compile the actual seccomp-unix-block.c file
    // This is more reliable than checking for specific files since package
    // installation paths vary across distributions
    const sourceHash = getFilterGeneratorSourceHash()

    // Write source to temp file
    const sourcePath = writeSourceToTempFile('seccomp-unix-block', sourceHash)
    if (!sourcePath) {
      return false
    }

    const testBinary = join(
      tmpdir(),
      `seccomp-test-${process.pid}-${createHash('sha256').update(Math.random().toString()).digest('hex').substring(0, 8)}`,
    )

    try {
      // Try to compile the real program
      const compiler = gccResult.status === 0 ? 'gcc' : 'clang'
      const compileResult = spawnSync(
        compiler,
        ['-o', testBinary, sourcePath, '-lseccomp'],
        {
          stdio: 'ignore',
          timeout: 5000,
        },
      )

      // Clean up test binary
      try {
        fs.rmSync(testBinary, { force: true })
      } catch {
        // Ignore cleanup errors
      }

      return compileResult.status === 0
    } catch {
      // Clean up on error
      try {
        fs.rmSync(testBinary, { force: true })
      } catch {
        // Ignore cleanup errors
      }
      return false
    }
  } catch {
    return false
  }
})

/**
 * Get the path to a pre-generated BPF filter file from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-generated BPF files are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/unix-block.bpf
 *
 * Tries multiple paths for resilience:
 * 1. ../../vendor/seccomp/{arch}/unix-block.bpf (package root - standard npm installs)
 * 2. ../vendor/seccomp/{arch}/unix-block.bpf (dist/vendor - for bundlers)
 */
export function getPreGeneratedBpfPath(): string | null {

  // Determine architecture
  const arch = getVendorArchitecture()
  if (!arch) {
    logForDebugging(
      `[SeccompFilter] Cannot find pre-generated BPF filter: unsupported architecture ${process.arch}`,
    )
    return null
  }

  logForDebugging(`[SeccompFilter] Detected architecture: ${arch}`)

  // Try to locate the BPF file with fallback paths
  // Path is relative to the compiled code location (dist/sandbox/)
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'seccomp', arch, 'unix-block.bpf')

  // Try paths in order of preference
  const pathsToTry = [
    join(baseDir, '..', '..', relativePath), // package root: vendor/seccomp/...
    join(baseDir, '..', relativePath),       // dist: dist/vendor/seccomp/...
  ]

  for (const bpfPath of pathsToTry) {
    if (fs.existsSync(bpfPath)) {
      logForDebugging(
        `[SeccompFilter] Found pre-generated BPF filter: ${bpfPath} (${arch})`,
      )
      return bpfPath
    }
  }

  logForDebugging(
    `[SeccompFilter] Pre-generated BPF filter not found in any expected location (${arch})`,
  )
  return null
}

/**
 * Get the path to the apply-seccomp binary from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-built apply-seccomp binaries are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/apply-seccomp
 *
 * Tries multiple paths for resilience:
 * 1. ../../vendor/seccomp/{arch}/apply-seccomp (package root - standard npm installs)
 * 2. ../vendor/seccomp/{arch}/apply-seccomp (dist/vendor - for bundlers)
 */
export function getApplySeccompBinaryPath(): string | null {
  // Determine architecture
  const arch = getVendorArchitecture()
  if (!arch) {
    logForDebugging(
      `[SeccompFilter] Cannot find apply-seccomp binary: unsupported architecture ${process.arch}`,
    )
    return null
  }

  logForDebugging(`[SeccompFilter] Looking for apply-seccomp binary for architecture: ${arch}`)

  // Try to locate the binary with fallback paths
  // Path is relative to the compiled code location (dist/sandbox/)
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'seccomp', arch, 'apply-seccomp')

  // Try paths in order of preference
  const pathsToTry = [
    join(baseDir, '..', '..', relativePath), // package root: vendor/seccomp/...
    join(baseDir, '..', relativePath),       // dist: dist/vendor/seccomp/...
  ]

  for (const binaryPath of pathsToTry) {
    if (fs.existsSync(binaryPath)) {
      logForDebugging(
        `[SeccompFilter] Found apply-seccomp binary: ${binaryPath} (${arch})`,
      )
      return binaryPath
    }
  }

  logForDebugging(
    `[SeccompFilter] apply-seccomp binary not found in any expected location (${arch})`,
  )
  return null
}

// Cache directory for compiled binaries
const CACHE_DIR = join(tmpdir(), 'claude', 'seccomp-cache')

/**
 * Get the path to a source file in the vendor/seccomp-src directory
 * Handles both development and production paths
 *
 * Tries multiple paths for resilience:
 * 1. ../../vendor/seccomp-src/{filename} (package root - standard npm installs)
 * 2. ../vendor/seccomp-src/{filename} (dist/vendor - for bundlers)
 *
 * Returns the first path that exists, or the first path if none exist
 */
function getVendorSourcePath(filename: string): string {
  // Path is relative to the compiled code location (dist/sandbox/)
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'seccomp-src', filename)

  // Try paths in order of preference
  const pathsToTry = [
    join(baseDir, '..', '..', relativePath), // package root: vendor/seccomp-src/...
    join(baseDir, '..', relativePath),       // dist: dist/vendor/seccomp-src/...
  ]

  // Return first path that exists
  for (const path of pathsToTry) {
    if (fs.existsSync(path)) {
      return path
    }
  }

  // If none exist, return first path for backward compatibility with error messages
  return pathsToTry[0]
}

/**
 * Read a source file from vendor/seccomp-src directory
 * Returns null if the file doesn't exist
 */
function readVendorSource(filename: string): string | null {
  const sourcePath = getVendorSourcePath(filename)

  try {
    if (!fs.existsSync(sourcePath)) {
      logForDebugging(
        `[SeccompFilter] Source file not found: ${sourcePath}`,
        { level: 'warn' },
      )
      return null
    }

    return fs.readFileSync(sourcePath, 'utf8')
  } catch (err) {
    logForDebugging(
      `[SeccompFilter] Failed to read source file ${sourcePath}: ${err}`,
      { level: 'error' },
    )
    return null
  }
}

/**
 * Get the hash of the filter generator C source
 */
function getFilterGeneratorSourceHash(): string {
  const source = readVendorSource('seccomp-unix-block.c')
  if (!source) {
    // Fallback hash if source file is missing
    return 'missing'
  }
  return createHash('sha256')
    .update(source)
    .digest('hex')
    .substring(0, 16)
}

/**
 * Write C source code to a temporary file
 * Returns the path to the temporary source file, or null on failure
 */
function writeSourceToTempFile(
  name: string,
  hash: string,
): string | null {
  const sourcePath = join(CACHE_DIR, `${name}-${hash}.c`)

  // Check if source file already exists (cached)
  if (fs.existsSync(sourcePath)) {
    return sourcePath
  }

  // Read source from vendor directory
  const source = readVendorSource(`${name}.c`)
  if (!source) {
    logForDebugging(
      `[SeccompFilter] Cannot write source file: source not found in vendor directory`,
      { level: 'error' },
    )
    return null
  }

  try {
    // Create cache directory if it doesn't exist (recursive to create parent dirs)
    fs.mkdirSync(CACHE_DIR, { recursive: true })

    // Write the C source to the temp file
    fs.writeFileSync(sourcePath, source, { encoding: 'utf8' })
    logForDebugging(`[SeccompFilter] Wrote C source to ${sourcePath}`)
    return sourcePath
  } catch (err) {
    logForDebugging(`[SeccompFilter] Failed to write source file: ${err}`, {
      level: 'error',
    })
    return null
  }
}

/**
 * Compile the seccomp filter generator program
 * Returns the path to the compiled binary or null on failure
 */
function compileSeccompGenerator(): string | null {
  const sourceHash = getFilterGeneratorSourceHash()

  const binaryPath = join(CACHE_DIR, `seccomp-unix-block-${sourceHash}`)

  // Check if cached binary exists
  if (fs.existsSync(binaryPath)) {
    logForDebugging('[SeccompFilter] Using cached filter generator binary')
    return binaryPath
  }

  logForDebugging('[SeccompFilter] Compiling seccomp filter generator...')

  // Write source to temp file
  const sourcePath = writeSourceToTempFile('seccomp-unix-block', sourceHash)
  if (!sourcePath) {
    return null
  }

  // Try gcc first, then clang
  const compilers = ['gcc', 'clang']
  for (const compiler of compilers) {
    const result = spawnSync(
      compiler,
      ['-o', binaryPath, sourcePath, '-lseccomp'],
      {
        stdio: 'pipe',
        timeout: 30000, // 30 second timeout
      },
    )

    if (result.status === 0) {
      logForDebugging(
        `[SeccompFilter] Successfully compiled filter generator with ${compiler}`,
      )
      return binaryPath
    }

    logForDebugging(
      `[SeccompFilter] Filter generator compilation with ${compiler} failed: ${result.stderr?.toString() || 'unknown error'}`,
      { level: 'error' },
    )
  }

  logForDebugging(
    '[SeccompFilter] Failed to compile filter generator with any available compiler. ' +
      'Ensure gcc or clang and libseccomp-dev are installed.',
    { level: 'error' },
  )
  return null
}

/**
 * Get the path to the seccomp-unix-block generator binary
 * Compiles the binary at runtime
 */
function getSeccompGeneratorPath(): string | null {
  return compileSeccompGenerator()
}

/**
 * Generate a seccomp BPF filter that blocks Unix domain socket creation
 * Returns the path to the BPF filter file, or null if generation failed
 *
 * The filter blocks socket(AF_UNIX, ...) syscalls while allowing all other syscalls.
 * This prevents creation of new Unix domain socket file descriptors.
 *
 * Security scope:
 * - Blocks: socket(AF_UNIX, ...) syscall (creating new Unix socket FDs)
 * - Does NOT block: Operations on inherited Unix socket FDs (bind, connect, sendto, etc.)
 * - Does NOT block: Unix socket FDs passed via SCM_RIGHTS
 * - For most sandboxing scenarios, blocking socket creation is sufficient
 *
 * Note: This blocks ALL Unix socket creation, regardless of path. The allowUnixSockets
 * configuration is not supported on Linux due to seccomp-bpf limitations (it cannot
 * read user-space memory to inspect socket paths).
 *
 * Requirements:
 * - Pre-generated BPF filters included for x64 and ARM64
 * - For other architectures: gcc or clang + libseccomp-dev for runtime compilation
 *
 * @returns Path to the BPF filter file, or null on failure
 */
export function generateSeccompFilter(): string | null {
  // Try pre-generated BPF filter first (fast path - no compilation needed)
  const preGeneratedBpf = getPreGeneratedBpfPath()
  if (preGeneratedBpf) {
    logForDebugging('[SeccompFilter] Using pre-generated BPF filter')
    return preGeneratedBpf
  }

  // Fall back to runtime generation (requires gcc/clang + libseccomp-dev)
  logForDebugging(
    '[SeccompFilter] Pre-generated BPF not available, falling back to runtime compilation',
  )

  // Get the generator binary (pre-built or compile it)
  const binaryPath = getSeccompGeneratorPath()
  if (!binaryPath) {
    logForDebugging(
      '[SeccompFilter] Cannot generate BPF filter: no pre-generated file and compilation failed. ' +
        'Ensure gcc/clang and libseccomp-dev are installed for runtime compilation.',
      { level: 'error' },
    )
    return null
  }

  // Generate a unique filename for this filter
  const filterPath = join(
    tmpdir(),
    `claude-seccomp-${process.pid}-${createHash('sha256').update(Math.random().toString()).digest('hex').substring(0, 8)}.bpf`,
  )

  logForDebugging(`[SeccompFilter] Generating BPF filter to ${filterPath}`)

  // Run the compiled binary to generate the filter
  const result = spawnSync(binaryPath, [filterPath], {
    stdio: 'pipe',
    timeout: 5000, // 5 second timeout
  })

  if (result.status !== 0) {
    logForDebugging(
      `[SeccompFilter] Failed to generate filter: ${result.stderr?.toString() || 'unknown error'}`,
      { level: 'error' },
    )
    return null
  }

  // Verify the filter file was created
  if (!fs.existsSync(filterPath)) {
    logForDebugging('[SeccompFilter] Filter file was not created', {
      level: 'error',
    })
    return null
  }

  logForDebugging('[SeccompFilter] Successfully generated BPF filter via runtime compilation')
  return filterPath
}

/**
 * Clean up a seccomp filter file
 * Note: Pre-generated BPF files from vendor/ are never deleted
 */
export function cleanupSeccompFilter(filterPath: string): void {

  // Don't delete pre-generated BPF files from vendor/
  if (filterPath.includes('/vendor/seccomp/')) {
    logForDebugging('[SeccompFilter] Skipping cleanup of pre-generated BPF file')
    return
  }

  // Only clean up runtime-generated files (in /tmp/)
  try {
    if (fs.existsSync(filterPath)) {
      fs.rmSync(filterPath, { force: true })
      logForDebugging(`[SeccompFilter] Cleaned up filter file: ${filterPath}`)
    }
  } catch (err) {
    logForDebugging(`[SeccompFilter] Failed to clean up filter file: ${err}`, {
      level: 'error',
    })
  }
}

/**
 * Get the hash of the apply-seccomp Python script source
 */
function getApplySeccompScriptHash(): string {
  const source = readVendorSource('apply-seccomp-and-exec.py')
  if (!source) {
    // Fallback hash if source file is missing
    return 'missing'
  }
  return createHash('sha256')
    .update(source)
    .digest('hex')
    .substring(0, 16)
}

/**
 * Write the apply-seccomp Python script to the cache directory
 * Returns the path to the script, or null on failure
 */
function writeApplySeccompScript(): string | null {
  const scriptHash = getApplySeccompScriptHash()
  const scriptPath = join(CACHE_DIR, `apply-seccomp-and-exec-${scriptHash}.py`)

  // Check if script already exists (cached)
  if (fs.existsSync(scriptPath)) {
    logForDebugging('[SeccompFilter] Using cached apply-seccomp Python script')
    return scriptPath
  }

  // Read source from vendor directory
  const source = readVendorSource('apply-seccomp-and-exec.py')
  if (!source) {
    logForDebugging(
      '[SeccompFilter] Cannot write Python script: source not found in vendor directory',
      { level: 'error' },
    )
    return null
  }

  try {
    // Create cache directory if it doesn't exist
    fs.mkdirSync(CACHE_DIR, { recursive: true })

    // Write the Python script
    fs.writeFileSync(scriptPath, source, {
      encoding: 'utf8',
      mode: 0o755, // Make executable
    })

    logForDebugging(`[SeccompFilter] Wrote apply-seccomp Python script to ${scriptPath}`)
    return scriptPath
  } catch (err) {
    logForDebugging(
      `[SeccompFilter] Failed to write apply-seccomp Python script: ${err}`,
      { level: 'error' },
    )
    return null
  }
}

/**
 * Get the path to the apply-seccomp-and-exec Python script
 * This script applies a seccomp filter and execs a command, replacing the need
 * for nested bwrap with --seccomp flag.
 *
 * The script is cached in the temp directory to avoid repeated writes.
 *
 * @returns Path to the Python script, or null on failure
 */
export function getApplySeccompExecPath(): string | null {
  return writeApplySeccompScript()
}
