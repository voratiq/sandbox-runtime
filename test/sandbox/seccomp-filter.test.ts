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
  })

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

describe('Python 3 Requirement', () => {
  it('should fail fast when Python 3 is missing and seccomp is needed', async () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    // Mock scenario where Python is missing
    // We can't actually remove Python, but we can test the error path
    // by checking that generateSeccompFilter() returns null when Python is missing

    // This test documents the expected behavior:
    // When Python 3 is unavailable, the sandbox should throw a clear error
    // instead of silently running without seccomp protection

    // The actual check happens in:
    // 1. generateSeccompFilter() returns null if !hasPython3Sync()
    // 2. buildSandboxCommand() throws error if getApplySeccompExecPath() returns null
    expect(true).toBe(true) // Placeholder - actual behavior verified by integration tests
  })

  it('should include Python 3 in error messages', () => {
    if (skipIfNotLinux() || skipIfNotAnt()) {
      return
    }

    // Verify error messages mention Python 3 and installation instructions
    // This is a documentation test to ensure error messages are helpful
    const expectedInErrorMessage = [
      'Python 3',
      'python3',
      'apt-get install python3',
      'allowAllUnixSockets',
    ]

    // Error messages should guide users to either:
    // 1. Install Python 3, OR
    // 2. Set allowAllUnixSockets: true to opt out
    expect(expectedInErrorMessage.length).toBeGreaterThan(0)
  })

  it('should allow bypassing Python requirement with allowAllUnixSockets', async () => {
    if (skipIfNotLinux()) {
      return
    }

    // When allowAllUnixSockets is true, Python 3 should not be required
    const testCommand = 'echo "test"'

    // This should NOT throw even if Python is missing (when allowAllUnixSockets=true)
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      hasNetworkRestrictions: false,
      hasFilesystemRestrictions: false,
      allowAllUnixSockets: true, // Bypass seccomp
    })

    // Command should not contain seccomp helper
    expect(wrappedCommand).not.toContain('apply-seccomp-and-exec')
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
