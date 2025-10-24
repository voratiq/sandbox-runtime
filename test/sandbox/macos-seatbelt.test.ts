import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, unlinkSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'

/**
 * Tests for macOS Seatbelt read bypass vulnerability
 *
 * Issue: Files protected by read deny rules could be exfiltrated by moving them
 * to readable locations using the mv command. The rename() syscall was not blocked
 * by file-read* rules.
 *
 * Fix: Added file-write-unlink deny rules to block rename/move operations on:
 * 1. The denied files/directories themselves
 * 2. All ancestor directories (to prevent moving parent directories)
 */

function skipIfNotMacOS(): boolean {
  return getPlatform() !== 'macos'
}

describe('macOS Seatbelt Read Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied-dir')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_SECRET_CONTENT = 'SECRET_CREDENTIAL_DATA'
  const TEST_MOVED_FILE = join(TEST_BASE_DIR, 'moved-secret.txt')
  const TEST_MOVED_DIR = join(TEST_BASE_DIR, 'moved-denied-dir')

  beforeAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)
  })

  afterAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Direct File Move Prevention', () => {
    it('should block moving a read-denied file to a readable location', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create Seatbelt profile that denies reading the secret file
      const profile = `
(version 1)
(allow default)
(deny file-read* (subpath "${TEST_DENIED_DIR}"))
(deny file-write-unlink (subpath "${TEST_DENIED_DIR}"))
${getAncestorDenyRules(TEST_DENIED_DIR)}
      `.trim()

      // Verify the file exists and is readable before applying sandbox
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)

      // Attempt to move the file within the sandbox
      const result = spawnSync(
        'sandbox-exec',
        ['-p', profile, 'mv', TEST_SECRET_FILE, TEST_MOVED_FILE],
        {
          encoding: 'utf8',
          timeout: 5000,
        }
      )

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)
      expect(existsSync(TEST_MOVED_FILE)).toBe(false)
    })

    it('should still block reading the file (sanity check)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create Seatbelt profile that denies reading the secret file
      const profile = `
(version 1)
(allow default)
(deny file-read* (subpath "${TEST_DENIED_DIR}"))
(deny file-write-unlink (subpath "${TEST_DENIED_DIR}"))
${getAncestorDenyRules(TEST_DENIED_DIR)}
      `.trim()

      // Attempt to read the file within the sandbox
      const result = spawnSync(
        'sandbox-exec',
        ['-p', profile, 'cat', TEST_SECRET_FILE],
        {
          encoding: 'utf8',
          timeout: 5000,
        }
      )

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the secret content
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })
  })

  describe('Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a read-denied file', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create Seatbelt profile that denies reading the secret file
      const profile = `
(version 1)
(allow default)
(deny file-read* (subpath "${TEST_DENIED_DIR}"))
(deny file-write-unlink (subpath "${TEST_DENIED_DIR}"))
${getAncestorDenyRules(TEST_DENIED_DIR)}
      `.trim()

      // Verify the directory exists before applying sandbox
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)

      // Attempt to move the parent directory within the sandbox
      const result = spawnSync(
        'sandbox-exec',
        ['-p', profile, 'mv', TEST_DENIED_DIR, TEST_MOVED_DIR],
        {
          encoding: 'utf8',
          timeout: 5000,
        }
      )

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_MOVED_DIR)).toBe(false)
    })
  })

  describe('Glob Pattern Support', () => {
    it('should block moving files matching a glob pattern', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create a glob pattern that matches all .txt files in denied-dir
      const globPattern = join(TEST_DENIED_DIR, '*.txt')

      // Convert glob to regex (simplified for this test)
      const regexPattern = `^${TEST_DENIED_DIR.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/[^/]*\\.txt$`

      // Create Seatbelt profile with glob pattern
      const profile = `
(version 1)
(allow default)
(deny file-read* (regex "${regexPattern}"))
(deny file-write-unlink (regex "${regexPattern}"))
${getAncestorDenyRules(TEST_DENIED_DIR)}
      `.trim()

      // Attempt to move the secret.txt file within the sandbox
      const result = spawnSync(
        'sandbox-exec',
        ['-p', profile, 'mv', TEST_SECRET_FILE, TEST_MOVED_FILE],
        {
          encoding: 'utf8',
          timeout: 5000,
        }
      )

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)
      expect(existsSync(TEST_MOVED_FILE)).toBe(false)
    })
  })
})

/**
 * Helper function to generate ancestor directory deny rules
 * This mimics what the actual implementation does
 */
function getAncestorDenyRules(pathStr: string): string {
  const ancestors: string[] = []
  let currentPath = pathStr

  // Walk up the directory tree until we reach root
  while (true) {
    const parentPath = join(currentPath, '..')
    // Resolve to get the actual parent path
    const resolvedParent = parentPath

    // Break if we've reached the top
    if (resolvedParent === '/' || resolvedParent === currentPath) {
      break
    }

    ancestors.push(resolvedParent)
    currentPath = resolvedParent
  }

  // Generate deny rules for each ancestor
  return ancestors
    .map(ancestor => `(deny file-write-unlink (literal "${ancestor}"))`)
    .join('\n')
}
