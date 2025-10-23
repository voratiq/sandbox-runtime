import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, unlinkSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

/**
 * Create a test configuration for the sandbox with example.com allowlisted
 */
function createTestConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

function skipIfNotSupported(): boolean {
  const platform = getPlatform()
  return platform !== 'linux' && platform !== 'macos'
}

function isMacOS(): boolean {
  return getPlatform() === 'macos'
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
    if (skipIfNotSupported()) {
      return
    }

    console.log(`Running tests on ${getPlatform()}`)

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

    // Initialize sandbox with config
    await SandboxManager.initialize(createTestConfig())
  })

  afterAll(async () => {
    if (skipIfNotSupported()) {
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

  describe('Unix Socket Restrictions', () => {
    it('should block Unix socket connections', async () => {
      if (skipIfNotSupported()) {
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

      // Should fail due to sandbox blocking socket creation
      const output = (result.stderr || result.stdout || '').toLowerCase()

      // Different platforms/netcat versions report the error differently
      // Linux: "operation not permitted" (seccomp)
      // macOS: "operation not permitted" or "denied" (sandbox-exec)
      const hasExpectedError = output.includes('operation not permitted') ||
                               output.includes('create unix socket failed') ||
                               output.includes('denied') ||
                               output.includes('sandbox') ||
                               output.includes('protocol wrong type') ||
                               output.includes('bad file descriptor')

      // On macOS, the command might fail silently with no output if sandboxed
      const didFail = result.status !== 0 || hasExpectedError
      expect(didFail).toBe(true)
    })
  })

  describe('Network Restrictions', () => {
    it('should block HTTP requests to anthropic.com (not in allowlist)', async () => {
      if (skipIfNotSupported()) {
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
      if (skipIfNotSupported()) {
        return
      }

      // Note: example.com is in the allowlist via createTestConfig()
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
      if (skipIfNotSupported()) {
        return
      }

      // Use /etc which is definitely read-only on both platforms
      const testFile = '/etc/sandbox-blocked-write.txt'

      // Clean up if exists (it shouldn't)
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

      // The key thing is that the file should NOT have been created
      expect(existsSync(testFile)).toBe(false)

      // Should fail - command returns non-zero or contains error
      const output = (result.stderr || result.stdout || '').toLowerCase()

      // Error message varies by platform
      // Linux: "read-only file system"
      // macOS: "read-only" or "permission denied" or "operation not permitted"
      const hasErrorOrFailed = result.status !== 0 ||
                                output.includes('read-only') ||
                                output.includes('permission denied') ||
                                output.includes('operation not permitted')
      expect(hasErrorOrFailed).toBe(true)
    })

    it('should allow writes within current working directory', async () => {
      if (skipIfNotSupported()) {
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
      if (skipIfNotSupported()) {
        return
      }

      // Try reading a common file that exists on both platforms
      // Use .profile or .bash_profile on macOS, .bashrc on Linux
      const testFiles = isMacOS()
        ? ['~/.profile', '~/.bash_profile', '~/.zshrc']
        : ['~/.bashrc', '~/.profile']

      let testedFile = null
      for (const file of testFiles) {
        const expandedPath = file.replace('~', process.env.HOME || '')
        if (existsSync(expandedPath)) {
          testedFile = file
          break
        }
      }

      if (!testedFile) {
        console.log('Skipping read test: no suitable test file found in home directory')
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        `head -n 5 ${testedFile}`
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should succeed
      expect(result.status).toBe(0)
      expect(result.stdout).toBeTruthy()
    })
  })

  describe('Command Execution', () => {
    it('should execute basic commands successfully', async () => {
      if (skipIfNotSupported()) {
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
      if (skipIfNotSupported()) {
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
