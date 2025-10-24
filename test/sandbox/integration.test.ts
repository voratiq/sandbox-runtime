import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync, spawn } from 'node:child_process'
import { existsSync, unlinkSync, mkdirSync, rmSync, statSync, readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getPlatform } from '../../src/utils/platform.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { generateSeccompFilter } from '../../src/sandbox/generate-seccomp-filter.js'

/**
 * Create a minimal test configuration for the sandbox with example.com allowed
 */
function createTestConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      allowRead: [],
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

// ============================================================================
// Helper Functions for BPF File Management
// ============================================================================

/**
 * Temporarily hide BPF files to force JIT compilation
 * Returns a map of file paths to their contents for later restoration
 */
function hideBpfFiles(): Map<string, Buffer> {
  const backups = new Map<string, Buffer>()

  // Hide BPF files from both vendor/ (source) and dist/vendor/ (runtime)
  const seccompDirs = [
    join(process.cwd(), 'vendor', 'seccomp'),
    join(process.cwd(), 'dist', 'vendor', 'seccomp'),
  ]

  for (const vendorSeccompDir of seccompDirs) {
    if (!existsSync(vendorSeccompDir)) {
      continue
    }

    // Find all BPF files in seccomp/*/unix-block.bpf
    const archDirs = readdirSync(vendorSeccompDir, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory())
      .map(dirent => dirent.name)

    for (const arch of archDirs) {
      const bpfPath = join(vendorSeccompDir, arch, 'unix-block.bpf')
      if (existsSync(bpfPath)) {
        // Backup file contents
        const contents = readFileSync(bpfPath)
        backups.set(bpfPath, contents)
        // Delete the file
        unlinkSync(bpfPath)
        console.log(`Hidden BPF file: ${bpfPath}`)
      }
    }
  }

  return backups
}

/**
 * Restore BPF files from backups
 */
function restoreBpfFiles(backups: Map<string, Buffer>): void {
  for (const [path, contents] of backups.entries()) {
    writeFileSync(path, contents)
    console.log(`Restored BPF file: ${path}`)
  }
}

/**
 * Assert that the sandbox is using pre-compiled BPF files
 */
function assertPrecompiledBpfInUse(): void {
  const bpfPath = generateSeccompFilter()

  expect(bpfPath).toBeTruthy()
  expect(bpfPath).toContain('/vendor/seccomp/')
  expect(existsSync(bpfPath!)).toBe(true)

  console.log(`✓ Verified using pre-compiled BPF: ${bpfPath}`)
}

/**
 * Assert that the sandbox is using JIT-compiled BPF files
 */
function assertJitBpfInUse(): void {
  const bpfPath = generateSeccompFilter()

  expect(bpfPath).toBeTruthy()
  expect(bpfPath).toContain('/tmp/claude-seccomp-')
  expect(bpfPath).toContain('.bpf')
  expect(existsSync(bpfPath!)).toBe(true)

  // Verify it was recently created (within last 10 seconds)
  const stats = statSync(bpfPath!)
  const age = Date.now() - stats.mtimeMs
  expect(age).toBeLessThan(10000)

  console.log(`✓ Verified using JIT-compiled BPF: ${bpfPath}`)
}

// ============================================================================
// Main Test Suite
// ============================================================================

describe('Sandbox Integration Tests', () => {
  const TEST_SOCKET_PATH = '/tmp/claude-test.sock'
  // Use a directory within the repository (which is the CWD)
  const TEST_DIR = join(process.cwd(), '.sandbox-test-tmp')
  let socketServer: any = null

  beforeAll(async () => {
    if (skipIfNotLinux()) {
      return
    }

    // Create test directory
    if (!existsSync(TEST_DIR)) {
      mkdirSync(TEST_DIR, { recursive: true })
    }

    // Create a Unix socket server for testing
    // We'll use Node.js to create a simple socket server
    const net = await import('node:net')

    // Clean up any existing socket
    if (existsSync(TEST_SOCKET_PATH)) {
      unlinkSync(TEST_SOCKET_PATH)
    }

    // Create Unix socket server
    socketServer = net.createServer((socket) => {
      socket.on('data', (data) => {
        socket.write('Echo: ' + data.toString())
      })
    })

    await new Promise<void>((resolve, reject) => {
      socketServer.listen(TEST_SOCKET_PATH, () => {
        console.log(`Test socket server listening on ${TEST_SOCKET_PATH}`)
        resolve()
      })
      socketServer.on('error', reject)
    })

    // Initialize sandbox
    await SandboxManager.initialize(createTestConfig())
  })

  afterAll(async () => {
    if (skipIfNotLinux()) {
      return
    }

    // Clean up socket server
    if (socketServer) {
      socketServer.close()
    }

    // Clean up socket file
    if (existsSync(TEST_SOCKET_PATH)) {
      unlinkSync(TEST_SOCKET_PATH)
    }

    // Clean up test directory
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }

    // Reset sandbox
    await SandboxManager.reset()
  })

  // ==========================================================================
  // Scenario 1: With Pre-compiled BPF
  // ==========================================================================

  describe('With Pre-compiled BPF', () => {
    beforeAll(() => {
      if (skipIfNotLinux()) {
        return
      }

      console.log('\n=== Testing with Pre-compiled BPF ===')
      assertPrecompiledBpfInUse()
    })


    describe('Unix Socket Restrictions', () => {
      it('should block Unix socket connections with seccomp', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Wrap command with sandbox
        const command = await SandboxManager.wrapWithSandbox(
          `echo "Test message" | nc -U ${TEST_SOCKET_PATH}`
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should fail due to seccomp filter blocking socket creation
        const output = (result.stderr || result.stdout || '').toLowerCase()
        // Different netcat versions report the error differently
        const hasExpectedError = output.includes('operation not permitted') ||
                                 output.includes('create unix socket failed')
        expect(hasExpectedError).toBe(true)
        expect(result.status).not.toBe(0)
      })
    })

    describe('Network Restrictions', () => {
      it('should block HTTP requests to non-allowlisted domains', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'curl -s http://blocked-domain.example'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('blocked by network allowlist')
      })

      it('should block HTTP requests to anthropic.com (not in allowlist)', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Use --max-time to timeout quickly, and --show-error to see proxy errors
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s --show-error --max-time 2 https://www.anthropic.com'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // The proxy blocks the connection, causing curl to timeout or fail
        // Check that the request did not succeed
        const output = (result.stderr || result.stdout || '').toLowerCase()
        const didFail = result.status !== 0 || result.status === null
        expect(didFail).toBe(true)

        // The output should either contain an error or be empty (timeout)
        // It should NOT contain successful HTML response
        expect(output).not.toContain('<!doctype html')
        expect(output).not.toContain('<html')
      })

      it('should allow HTTP requests to allowlisted domains', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Note: example.com should be in the allowlist via .claude/settings.json
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s http://example.com'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        // Should succeed and return HTML
        const output = result.stdout || ''
        expect(result.status).toBe(0)
        expect(output).toContain('Example Domain')
      })
    })

    describe('Filesystem Restrictions', () => {
      it('should block writes outside current working directory', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const testFile = join(tmpdir(), 'sandbox-blocked-write.txt')

        // Clean up if exists
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }

        const command = await SandboxManager.wrapWithSandbox(
          `echo "should fail" > ${testFile}`
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Should fail with read-only file system error
        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('read-only file system')
        expect(existsSync(testFile)).toBe(false)
      })

      it('should allow writes within current working directory', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Ensure test directory exists
        if (!existsSync(TEST_DIR)) {
          mkdirSync(TEST_DIR, { recursive: true })
        }

        const testFile = join(TEST_DIR, 'allowed-write.txt')
        const testContent = 'test content from sandbox'

        // Clean up if exists
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }

        const command = await SandboxManager.wrapWithSandbox(
          `echo "${testContent}" > allowed-write.txt`
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Debug output if failed
        if (result.status !== 0) {
          console.error('Command failed:', command)
          console.error('Status:', result.status)
          console.error('Stdout:', result.stdout)
          console.error('Stderr:', result.stderr)
          console.error('CWD:', TEST_DIR)
          console.error('Test file path:', testFile)
        }

        // Should succeed
        expect(result.status).toBe(0)
        expect(existsSync(testFile)).toBe(true)

        // Verify content
        const content = Bun.file(testFile).text()
        expect(await content).toContain(testContent)

        // Clean up
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }
      })

      it('should allow reads from anywhere', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Try reading from home directory
        const command = await SandboxManager.wrapWithSandbox(
          'head -n 5 ~/.bashrc'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should succeed (assuming .bashrc exists)
        expect(result.status).toBe(0)

        // If .bashrc exists, should have some content
        if (existsSync(`${process.env.HOME}/.bashrc`)) {
          expect(result.stdout).toBeTruthy()
        }
      })
    })

    describe('Command Execution', () => {
      it('should execute basic commands successfully', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox('echo "Hello from sandbox"')

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('Hello from sandbox')
      })

      it('should handle complex command pipelines', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'echo "line1\nline2\nline3" | grep line2'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('line2')
        expect(result.stdout).not.toContain('line1')
      })
    })
  })

  // ==========================================================================
  // Scenario 2: With JIT-compiled BPF
  // ==========================================================================

  describe('With JIT-compiled BPF', () => {
    let bpfBackups: Map<string, Buffer> = new Map()

    beforeAll(async () => {
      if (skipIfNotLinux()) {
        return
      }

      console.log('\n=== Testing with JIT-compiled BPF ===')

      // Hide pre-compiled BPF files to force JIT compilation
      bpfBackups = hideBpfFiles()

      // Reset sandbox to clear any cached BPF paths
      await SandboxManager.reset()
      await SandboxManager.initialize(createTestConfig())

      // Verify JIT mode is active
      assertJitBpfInUse()
    })

    afterAll(async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Restore pre-compiled BPF files
      restoreBpfFiles(bpfBackups)

      // Reset sandbox again to restore normal behavior
      await SandboxManager.reset()
      await SandboxManager.initialize(createTestConfig())
    })

    describe('Pre-generated BPF Files', () => {
      it('should generate BPF files at runtime when pre-compiled files are missing', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Generate BPF filter and verify it's in /tmp/
        const bpfPath = generateSeccompFilter()

        expect(bpfPath).toBeTruthy()
        expect(bpfPath).toContain('/tmp/claude-seccomp-')
        expect(existsSync(bpfPath!)).toBe(true)

        console.log(`✓ Generated runtime BPF file: ${bpfPath}`)

        // Verify it's a reasonable size (should be similar to pre-compiled)
        const stats = statSync(bpfPath!)
        expect(stats.size).toBeGreaterThan(50)
        expect(stats.size).toBeLessThan(200)
        console.log(`✓ BPF file is ${stats.size} bytes`)
      })
    })

    describe('Unix Socket Restrictions', () => {
      it('should block Unix socket connections with seccomp', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Wrap command with sandbox
        const command = await SandboxManager.wrapWithSandbox(
          `echo "Test message" | nc -U ${TEST_SOCKET_PATH}`
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should fail due to seccomp filter blocking socket creation
        const output = (result.stderr || result.stdout || '').toLowerCase()
        // Different netcat versions report the error differently
        const hasExpectedError = output.includes('operation not permitted') ||
                                 output.includes('create unix socket failed')
        expect(hasExpectedError).toBe(true)
        expect(result.status).not.toBe(0)
      })
    })

    describe('Network Restrictions', () => {
      it('should block HTTP requests to non-allowlisted domains', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'curl -s http://blocked-domain.example'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('blocked by network allowlist')
      })

      it('should block HTTP requests to anthropic.com (not in allowlist)', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Use --max-time to timeout quickly, and --show-error to see proxy errors
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s --show-error --max-time 2 https://www.anthropic.com'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // The proxy blocks the connection, causing curl to timeout or fail
        // Check that the request did not succeed
        const output = (result.stderr || result.stdout || '').toLowerCase()
        const didFail = result.status !== 0 || result.status === null
        expect(didFail).toBe(true)

        // The output should either contain an error or be empty (timeout)
        // It should NOT contain successful HTML response
        expect(output).not.toContain('<!doctype html')
        expect(output).not.toContain('<html')
      })

      it('should allow HTTP requests to allowlisted domains', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Note: example.com should be in the allowlist via .claude/settings.json
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s http://example.com'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        // Should succeed and return HTML
        const output = result.stdout || ''
        expect(result.status).toBe(0)
        expect(output).toContain('Example Domain')
      })
    })

    describe('Filesystem Restrictions', () => {
      it('should block writes outside current working directory', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const testFile = join(tmpdir(), 'sandbox-blocked-write-jit.txt')

        // Clean up if exists
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }

        const command = await SandboxManager.wrapWithSandbox(
          `echo "should fail" > ${testFile}`
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Should fail with read-only file system error
        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('read-only file system')
        expect(existsSync(testFile)).toBe(false)
      })

      it('should allow writes within current working directory', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Ensure test directory exists
        if (!existsSync(TEST_DIR)) {
          mkdirSync(TEST_DIR, { recursive: true })
        }

        const testFile = join(TEST_DIR, 'allowed-write-jit.txt')
        const testContent = 'test content from sandbox with JIT BPF'

        // Clean up if exists
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }

        const command = await SandboxManager.wrapWithSandbox(
          `echo "${testContent}" > allowed-write-jit.txt`
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Debug output if failed
        if (result.status !== 0) {
          console.error('Command failed:', command)
          console.error('Status:', result.status)
          console.error('Stdout:', result.stdout)
          console.error('Stderr:', result.stderr)
          console.error('CWD:', TEST_DIR)
          console.error('Test file path:', testFile)
        }

        // Should succeed
        expect(result.status).toBe(0)
        expect(existsSync(testFile)).toBe(true)

        // Verify content
        const content = Bun.file(testFile).text()
        expect(await content).toContain(testContent)

        // Clean up
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }
      })

      it('should allow reads from anywhere', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Try reading from home directory
        const command = await SandboxManager.wrapWithSandbox(
          'head -n 5 ~/.bashrc'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should succeed (assuming .bashrc exists)
        expect(result.status).toBe(0)

        // If .bashrc exists, should have some content
        if (existsSync(`${process.env.HOME}/.bashrc`)) {
          expect(result.stdout).toBeTruthy()
        }
      })
    })

    describe('Command Execution', () => {
      it('should execute basic commands successfully', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox('echo "Hello from sandbox with JIT BPF"')

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('Hello from sandbox with JIT BPF')
      })

      it('should handle complex command pipelines', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'echo "line1\nline2\nline3" | grep line2'
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('line2')
        expect(result.stdout).not.toContain('line1')
      })
    })
  })
})
