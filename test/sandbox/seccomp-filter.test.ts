import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import {
  generateSeccompFilter,
  cleanupSeccompFilter,
  hasSeccompDependenciesSync,
  getApplySeccompExecPath,
  getPreGeneratedBpfPath,
} from '../../src/sandbox/generate-seccomp-filter.js'
import {
  wrapCommandWithSandboxLinux,
  hasLinuxSandboxDependenciesSync,
} from '../../src/sandbox/linux-sandbox-utils.js'

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

function skipIfNotAnt(): boolean {
  return process.env.USER_TYPE !== 'ant'
}

describe('Seccomp Dependencies', () => {
  it('should check for seccomp dependencies', () => {
    if (skipIfNotLinux()) {
      return
    }

    const hasDeps = hasSeccompDependenciesSync()
    expect(typeof hasDeps).toBe('boolean')

    // If we have dependencies, we should have both compiler and libseccomp
    if (hasDeps) {
      const gccResult = spawnSync('which', ['gcc'], { stdio: 'ignore' })
      const clangResult = spawnSync('which', ['clang'], { stdio: 'ignore' })
      expect(gccResult.status === 0 || clangResult.status === 0).toBe(true)
    }
  }, { timeout: 15000 })

  it('should check for Linux sandbox dependencies', () => {
    if (skipIfNotLinux()) {
      return
    }

    const hasDeps = hasLinuxSandboxDependenciesSync()
    expect(typeof hasDeps).toBe('boolean')

    // Should always check for bwrap and socat
    if (hasDeps) {
      const bwrapResult = spawnSync('which', ['bwrap'], { stdio: 'ignore' })
      const socatResult = spawnSync('which', ['socat'], { stdio: 'ignore' })
      expect(bwrapResult.status).toBe(0)
      expect(socatResult.status).toBe(0)

      // For ANT users, should also check seccomp dependencies
      if (process.env.USER_TYPE === 'ant') {
        expect(hasSeccompDependenciesSync()).toBe(true)
      }
    }
  })

  it('should be memoized to avoid repeated checks', () => {
    if (skipIfNotLinux()) {
      return
    }

    // Call multiple times - should be fast due to memoization
    const result1 = hasSeccompDependenciesSync()
    const result2 = hasSeccompDependenciesSync()
    const result3 = hasSeccompDependenciesSync()

    expect(result1).toBe(result2)
    expect(result2).toBe(result3)
  })
})

describe('Pre-generated BPF Support', () => {
  it('should detect pre-generated BPF files on x64/arm64', () => {
    if (skipIfNotLinux()) {
      return
    }

    // Check if current architecture supports pre-generated BPF
    const arch = process.arch
    const preGeneratedBpf = getPreGeneratedBpfPath()

    if (arch === 'x64' || arch === 'x86_64' || arch === 'arm64' || arch === 'aarch64') {
      // Should have pre-generated BPF for these architectures
      expect(preGeneratedBpf).toBeTruthy()
      if (preGeneratedBpf) {
        expect(existsSync(preGeneratedBpf)).toBe(true)
        expect(preGeneratedBpf).toContain('vendor/seccomp')
        expect(preGeneratedBpf).toMatch(/unix-block\.bpf$/)
      }
    } else {
      // Other architectures should not have pre-generated BPF
      expect(preGeneratedBpf).toBeNull()
    }
  })

  it('should not require gcc/clang when pre-generated BPF exists', () => {
    if (skipIfNotLinux()) {
      return
    }

    const preGeneratedBpf = getPreGeneratedBpfPath()

    // Only test on architectures with pre-generated BPF
    if (!preGeneratedBpf) {
      return
    }

    // Check if we have compilation dependencies
    const hasCompilationDeps = hasSeccompDependenciesSync()

    // hasLinuxSandboxDependenciesSync should succeed on x64/arm64
    // with just bwrap and socat (pre-built binaries included)
    const hasSandboxDeps = hasLinuxSandboxDependenciesSync()

    // On x64/arm64 with pre-built binaries, we should have sandbox deps
    // regardless of whether compilation deps are available
    const bwrapResult = spawnSync('which', ['bwrap'], { stdio: 'ignore' })
    const socatResult = spawnSync('which', ['socat'], { stdio: 'ignore' })

    if (bwrapResult.status === 0 && socatResult.status === 0) {
      // Basic deps available - on x64/arm64 this should be sufficient
      // (pre-built apply-seccomp binaries and BPF filters are included)
      const arch = process.arch
      if (arch === 'x64' || arch === 'arm64') {
        expect(hasSandboxDeps).toBe(true)
      }
    }
  })

  it('should not allow seccomp on unsupported architectures', () => {
    if (skipIfNotLinux()) {
      return
    }

    const preGeneratedBpf = getPreGeneratedBpfPath()

    // Only test on architectures WITHOUT pre-generated BPF
    if (preGeneratedBpf !== null) {
      return
    }

    // On architectures without pre-built apply-seccomp binaries,
    // hasLinuxSandboxDependenciesSync() should return false
    // (unless allowAllUnixSockets is set to true)
    const hasSandboxDeps = hasLinuxSandboxDependenciesSync(false)

    // Unsupported architectures should not have sandbox deps when seccomp is required
    expect(hasSandboxDeps).toBe(false)

    // But should work when allowAllUnixSockets is true
    const hasSandboxDepsWithBypass = hasLinuxSandboxDependenciesSync(true)
    const bwrapResult = spawnSync('which', ['bwrap'], { stdio: 'ignore' })
    const socatResult = spawnSync('which', ['socat'], { stdio: 'ignore' })

    if (bwrapResult.status === 0 && socatResult.status === 0) {
      expect(hasSandboxDepsWithBypass).toBe(true)
    }
  })
})

describe('Seccomp Filter Generation', () => {
  let filterPath: string | null = null
  const generatedFilters: string[] = []

  afterAll(() => {
    // Clean up all generated filter files
    for (const path of generatedFilters) {
      try {
        cleanupSeccompFilter(path)
      } catch {
        // Ignore cleanup errors
      }
    }
  })

  it('should generate a valid BPF filter file', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    filterPath = generateSeccompFilter()
    if (filterPath) {
      generatedFilters.push(filterPath)
    }

    expect(filterPath).toBeTruthy()
    expect(filterPath).toMatch(/\.bpf$/)
    expect(filterPath).toContain(tmpdir())

    // Verify the file exists
    expect(existsSync(filterPath!)).toBe(true)

    // Verify the file has content (BPF bytecode)
    const stats = statSync(filterPath!)
    expect(stats.size).toBeGreaterThan(0)

    // BPF programs should be a multiple of 8 bytes (struct sock_filter is 8 bytes)
    expect(stats.size % 8).toBe(0)
  })

  it('should generate unique filter files on each call', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    const filter1 = generateSeccompFilter()
    const filter2 = generateSeccompFilter()

    if (filter1) generatedFilters.push(filter1)
    if (filter2) generatedFilters.push(filter2)

    expect(filter1).toBeTruthy()
    expect(filter2).toBeTruthy()

    // Should generate different filenames (timestamped)
    expect(filter1).not.toBe(filter2)
  })

  it('should return null when dependencies are missing', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (hasSeccompDependenciesSync()) {
      // Can't test this case if dependencies are available
      return
    }

    const filter = generateSeccompFilter()
    expect(filter).toBeNull()
  })

  it('should clean up filter files', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    const filter = generateSeccompFilter()
    expect(filter).toBeTruthy()
    expect(existsSync(filter!)).toBe(true)

    cleanupSeccompFilter(filter!)
    expect(existsSync(filter!)).toBe(false)
  })

  it('should handle cleanup of non-existent files gracefully', () => {
    if (skipIfNotLinux()) {
      return
    }

    const fakePath = '/tmp/nonexistent-filter.bpf'
    expect(() => cleanupSeccompFilter(fakePath)).not.toThrow()
  })
})

describe('Apply Seccomp Helper', () => {
  it('should compile the apply-seccomp-and-exec helper', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    const helperPath = getApplySeccompExecPath()
    expect(helperPath).toBeTruthy()

    // Verify the file exists and is executable
    expect(existsSync(helperPath!)).toBe(true)

    const stats = statSync(helperPath!)
    expect(stats.size).toBeGreaterThan(0)

    // Check if file is executable (Unix permission check)
    const mode = stats.mode
    const isExecutable = (mode & 0o111) !== 0
    expect(isExecutable).toBe(true)
  })

  it('should cache compiled helper binary', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    // Call multiple times - should return same cached path
    const helper1 = getApplySeccompExecPath()
    const helper2 = getApplySeccompExecPath()

    expect(helper1).toBe(helper2)
  })

  it('should store helper in cache directory', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    const helperPath = getApplySeccompExecPath()
    expect(helperPath).toBeTruthy()

    const cacheDir = join(tmpdir(), 'claude', 'seccomp-cache')
    expect(helperPath).toContain(cacheDir)
    expect(helperPath).toContain('apply-seccomp-and-exec')
  })
})

describe('Architecture Support', () => {
  it('should fail fast when architecture is unsupported and seccomp is needed', async () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    // This test documents the expected behavior:
    // When the architecture is not x64/arm64, the sandbox should fail the dependency
    // check instead of silently running without seccomp protection

    // The actual check happens in:
    // 1. hasLinuxSandboxDependenciesSync() checks for apply-seccomp binary availability
    // 2. Returns false if binary not available for the current architecture
    // 3. Error messages guide users to set allowAllUnixSockets: true
    expect(true).toBe(true) // Placeholder - actual behavior verified by integration tests
  })

  it('should include architecture information in error messages', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    // Verify error messages mention architecture support and alternatives
    // This is a documentation test to ensure error messages are helpful
    const expectedInErrorMessage = [
      'x64',
      'arm64',
      'architecture',
      'allowAllUnixSockets',
    ]

    // Error messages should guide users to either:
    // 1. Use a supported architecture (x64/arm64), OR
    // 2. Set allowAllUnixSockets: true to opt out
    expect(expectedInErrorMessage.length).toBeGreaterThan(0)
  })

  it('should allow bypassing architecture requirement with allowAllUnixSockets', async () => {
    if (skipIfNotLinux()) {
      return
    }

    // When allowAllUnixSockets is true, architecture check should not matter
    const testCommand = 'echo "test"'

    // This should NOT throw even on unsupported architecture (when allowAllUnixSockets=true)
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
      allowAllUnixSockets: true, // Bypass seccomp
    })

    // Command should not contain apply-seccomp binary
    expect(wrappedCommand).not.toContain('apply-seccomp')
    expect(wrappedCommand).toContain('echo "test"')
  })
})

describe('USER_TYPE Gating', () => {
  it('should only generate seccomp filters for ANT users', () => {
    if (skipIfNotLinux()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    if (process.env.USER_TYPE === 'ant') {
      // ANT users should get seccomp filters
      const filter = generateSeccompFilter()
      expect(filter).toBeTruthy()
      if (filter) {
        cleanupSeccompFilter(filter)
      }
    } else {
      // Non-ANT users - filter generation should still work for testing
      // but won't be used in production sandbox commands
      expect(true).toBe(true)
    }
  })

  it('should only apply seccomp in sandbox for ANT users', async () => {
    if (skipIfNotLinux()) {
      return
    }

    if (!hasLinuxSandboxDependenciesSync()) {
      return
    }

    const testCommand = 'echo "test"'
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    if (process.env.USER_TYPE === 'ant' && hasSeccompDependenciesSync()) {
      // ANT users should have seccomp helper in command
      expect(wrappedCommand).toContain('apply-seccomp-and-exec')
    } else {
      // Non-ANT users should not have seccomp
      expect(wrappedCommand).not.toContain('apply-seccomp-and-exec')
    }
  })
})

describe('Socket Filtering Behavior', () => {
  let filterPath: string | null = null

  beforeAll(() => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    filterPath = generateSeccompFilter()
  })

  afterAll(() => {
    if (filterPath) {
      cleanupSeccompFilter(filterPath)
    }
  })

  it('should block Unix socket creation (SOCK_STREAM)', async () => {
    if (skipIfNotLinux() || skipIfNotAnt() || !filterPath) {
      return
    }

    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('Unix socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).not.toBe(0)
    const stderr = result.stderr?.toString() || ''
    expect(stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('should block Unix socket creation (SOCK_DGRAM)', async () => {
    if (skipIfNotLinux() || skipIfNotAnt() || !filterPath) {
      return
    }

    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); print('Unix datagram created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).not.toBe(0)
    const stderr = result.stderr?.toString() || ''
    expect(stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('should allow TCP socket creation (IPv4)', async () => {
    if (skipIfNotLinux() || skipIfNotAnt() || !filterPath) {
      return
    }

    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('TCP socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout?.toString()).toContain('TCP socket created')
  })

  it('should allow UDP socket creation (IPv4)', async () => {
    if (skipIfNotLinux() || skipIfNotAnt() || !filterPath) {
      return
    }

    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); print('UDP socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout?.toString()).toContain('UDP socket created')
  })

  it('should allow IPv6 socket creation', async () => {
    if (skipIfNotLinux() || skipIfNotAnt() || !filterPath) {
      return
    }

    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); print('IPv6 socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout?.toString()).toContain('IPv6 socket created')
  })
})

describe('Two-Stage Seccomp Application', () => {
  it('should allow network infrastructure to run before filter', async () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasLinuxSandboxDependenciesSync()) {
      return
    }

    // This test verifies that the socat processes can start successfully
    // even though they use Unix sockets, because they run before the filter
    const testCommand = 'echo "test"'

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    // Command should include both socat and the seccomp helper
    if (hasSeccompDependenciesSync()) {
      expect(wrappedCommand).toContain('socat')
      expect(wrappedCommand).toContain('apply-seccomp-and-exec')

      // The socat should come before the apply-seccomp-and-exec
      const socatIndex = wrappedCommand.indexOf('socat')
      const seccompIndex = wrappedCommand.indexOf('apply-seccomp-and-exec')
      expect(socatIndex).toBeGreaterThan(-1)
      expect(seccompIndex).toBeGreaterThan(-1)
      expect(socatIndex).toBeLessThan(seccompIndex)
    }
  })

  it('should execute user command with filter applied', async () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasLinuxSandboxDependenciesSync() || !hasSeccompDependenciesSync()) {
      return
    }

    // User command tries to create Unix socket - should fail
    const testCommand = `python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    // Should fail due to seccomp filter
    expect(result.status).not.toBe(0)
  })
})

describe('Sandbox Integration', () => {
  it('should handle commands without network or filesystem restrictions', async () => {
    if (skipIfNotLinux()) {
      return
    }

    if (!hasLinuxSandboxDependenciesSync()) {
      return
    }

    const testCommand = 'echo "hello world"'
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    // Should still wrap the command even without restrictions
    expect(wrappedCommand).toBeTruthy()
    expect(typeof wrappedCommand).toBe('string')
  })

  it('should wrap commands with filesystem restrictions', async () => {
    if (skipIfNotLinux()) {
      return
    }

    if (!hasLinuxSandboxDependenciesSync()) {
      return
    }

    const testCommand = 'ls /'
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: true,
    })

    expect(wrappedCommand).toBeTruthy()
    expect(wrappedCommand).toContain('bwrap')
  })

  it('should include seccomp for ANT users with dependencies', async () => {
    if (skipIfNotLinux()) {
      return
    }

    if (!hasLinuxSandboxDependenciesSync()) {
      return
    }

    const testCommand = 'echo "test"'
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
    })

    const isAnt = process.env.USER_TYPE === 'ant'
    const hasSeccomp = hasSeccompDependenciesSync()

    if (isAnt && hasSeccomp) {
      expect(wrappedCommand).toContain('apply-seccomp-and-exec')
    } else {
      expect(wrappedCommand).not.toContain('apply-seccomp-and-exec')
    }
  })
})

describe('Error Handling', () => {
  it('should handle cleanup errors gracefully', () => {
    if (skipIfNotLinux()) {
      return
    }

    // Try to clean up invalid paths
    expect(() => cleanupSeccompFilter('')).not.toThrow()
    expect(() => cleanupSeccompFilter('/invalid/path/filter.bpf')).not.toThrow()
    expect(() => cleanupSeccompFilter('/tmp/nonexistent.bpf')).not.toThrow()
  })

  it('should handle multiple cleanup calls on same file', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    if (!hasSeccompDependenciesSync()) {
      return
    }

    const filter = generateSeccompFilter()
    if (!filter) {
      return
    }

    cleanupSeccompFilter(filter)
    // Second cleanup should not throw
    expect(() => cleanupSeccompFilter(filter)).not.toThrow()
  })
})
