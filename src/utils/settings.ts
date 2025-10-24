import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { z } from 'zod'
import { mergeWith } from 'lodash-es'
import { SandboxConfigSchema } from '../sandbox/sandbox-schemas.js'
import { getPlatform } from './platform.js'
import { logForDebugging } from './debug.js'

// Tool name constants
export const WEB_FETCH_TOOL_NAME = 'WebFetch'
export const FILE_EDIT_TOOL_NAME = 'Edit'
export const FILE_READ_TOOL_NAME = 'Read'

/**
 * Permission rule structure
 */
export type PermissionRule = {
  toolName: string
  ruleContent?: string
}

/**
 * Zod schema for sandbox settings
 */
const SandboxSettingsSchema = z.object({
  permissions: z
    .object({
      allow: z.array(z.string()).optional(),
      deny: z.array(z.string()).optional(),
      ask: z.array(z.string()).optional(),
    })
    .optional(),
  sandbox: SandboxConfigSchema.optional(),
})

/**
 * Minimal settings structure for sandbox
 */
export type SandboxSettings = z.infer<typeof SandboxSettingsSchema>

/**
 * Setting source types
 */
export type SettingSource =
  | 'userSettings'
  | 'projectSettings'
  | 'localSettings'
  | 'policySettings'
  | 'flagSettings'

export type EditableSettingSource =
  | 'userSettings'
  | 'projectSettings'
  | 'localSettings'

// Session-level cache for settings
let sessionSettingsCache: SandboxSettings | null = null

// Store the --settings flag path
let flagSettingsPath: string | undefined

/**
 * Set the path for flag-based settings (e.g., from --settings flag)
 */
export function setFlagSettingsPath(path: string | undefined): void {
  flagSettingsPath = path
  resetSettingsCache()
}

/**
 * Get the managed settings file path based on platform
 */
function getManagedSettingsFilePath(): string {
  switch (getPlatform()) {
    case 'macos':
      return '/Library/Application Support/ClaudeCode/managed-settings.json'
    case 'windows':
      return 'C:\\ProgramData\\ClaudeCode\\managed-settings.json'
    default:
      return '/etc/claude-code/managed-settings.json'
  }
}

/**
 * Get file path for a specific setting source
 */
export function getSettingsFilePathForSource(
  source: SettingSource,
): string | undefined {
  const cwd = process.cwd()
  const homeDir = os.homedir()

  switch (source) {
    case 'userSettings':
      return path.join(homeDir, '.claude', 'settings.json')
    case 'projectSettings':
      return path.join(cwd, '.claude', 'settings.json')
    case 'localSettings':
      return path.join(cwd, '.claude', 'settings.local.json')
    case 'policySettings':
      return getManagedSettingsFilePath()
    case 'flagSettings':
      return flagSettingsPath
  }
}

/**
 * Parse permission rule string into structured format
 * Format: "ToolName(rule)" or "ToolName"
 */
export function permissionRuleValueFromString(
  ruleString: string,
): PermissionRule {
  const match = ruleString.match(/^([^(]+)(?:\(([^)]*)\))?$/)

  if (!match) {
    throw new Error(`Invalid permission rule format: ${ruleString}`)
  }

  const [, toolName, ruleContent] = match

  return {
    toolName: toolName?.trim() || '',
    ruleContent: ruleContent?.trim(),
  }
}

/**
 * Load settings from a single file
 */
function loadSettingsFile(filePath: string): SandboxSettings | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null
    }

    const content = fs.readFileSync(filePath, 'utf-8')
    if (content.trim() === '') {
      return null
    }

    const data = JSON.parse(content)

    // Validate with Zod
    const result = SandboxSettingsSchema.safeParse(data)

    if (!result.success) {
      // Loud error to stderr
      console.error(`\n❌ Settings validation error in: ${filePath}`)
      console.error('Details:')
      result.error.issues.forEach(issue => {
        const pathStr = issue.path.length > 0 ? issue.path.join('.') : 'root'
        console.error(`  - ${pathStr}: ${issue.message}`)
      })
      console.error('')

      // Also log for debugging
      logForDebugging(
        `Validation failed for ${filePath}: ${result.error.message}`,
        { level: 'error' },
      )
      return null
    }

    logForDebugging(
      `Loaded from ${filePath}: ${JSON.stringify(result.data, null, 2)}`,
    )

    return result.data
  } catch (error) {
    // Loud error to stderr
    console.error(`\n❌ Failed to parse settings file: ${filePath}`)
    if (error instanceof SyntaxError) {
      console.error(`JSON syntax error: ${error.message}`)
    } else {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
    console.error('')

    // Also log for debugging
    logForDebugging(`Failed to read ${filePath}: ${error}`, {
      level: 'error',
    })
    return null
  }
}

/**
 * Merge two arrays and deduplicate
 */
function mergeArrays<T>(arr1: T[], arr2: T[]): T[] {
  return Array.from(new Set([...arr1, ...arr2]))
}

/**
 * Deep merge two settings objects using lodash mergeWith
 * Arrays are concatenated and deduplicated
 * Objects are recursively deep merged
 */
function mergeSettings(
  base: SandboxSettings,
  override: SandboxSettings,
): SandboxSettings {
  return mergeWith(base, override, (objValue: unknown, srcValue: unknown) => {
    // Custom merge for arrays: concatenate and deduplicate
    if (Array.isArray(objValue) && Array.isArray(srcValue)) {
      return mergeArrays(objValue, srcValue)
    }
    // For non-arrays, let lodash handle the default deep merge behavior
    return undefined
  })
}

/**
 * Reset the session-level settings cache
 */
export function resetSettingsCache(): void {
  sessionSettingsCache = null
}

/**
 * Get settings for a specific source
 */
export function getSettingsForSource(
  source: SettingSource,
): SandboxSettings | null {
  const settingsFilePath = getSettingsFilePathForSource(source)
  if (!settingsFilePath) {
    return null
  }
  return loadSettingsFile(settingsFilePath)
}

/**
 * Update settings for a specific source
 */
export function updateSettingsForSource(
  source: EditableSettingSource,
  settings: SandboxSettings,
): void {
  const filePath = getSettingsFilePathForSource(source)
  if (!filePath) {
    return
  }

  try {
    // Create the directory if needed
    const dir = path.dirname(filePath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }

    // Load existing settings
    const existingSettings = loadSettingsFile(filePath) || {}

    // Merge with new settings
    const updatedSettings = mergeSettings(existingSettings, settings)

    // Write to file
    fs.writeFileSync(filePath, JSON.stringify(updatedSettings, null, 2) + '\n')

    // Invalidate cache
    resetSettingsCache()
  } catch (error) {
    logForDebugging(`Failed to write ${filePath}: ${error}`, {
      level: 'error',
    })
  }
}

/**
 * Load settings from disk without using cache
 */
function loadSettingsFromDisk(): SandboxSettings {
  // Define setting sources in priority order (lowest to highest)
  const sources: SettingSource[] = [
    'userSettings',
    'projectSettings',
    'localSettings',
    'policySettings',
  ]

  // Add flagSettings if a path was provided
  if (flagSettingsPath) {
    sources.push('flagSettings')
  }

  let merged: SandboxSettings = {}

  // Merge settings from each source
  for (const source of sources) {
    const settings = getSettingsForSource(source)
    if (settings) {
      merged = mergeSettings(merged, settings)
    }
  }

  logForDebugging(`Final merged settings: ${JSON.stringify(merged, null, 2)}`)

  return merged
}

/**
 * Get merged settings from all sources with session-level caching
 * Merges in priority order:
 * 1. User settings (~/.claude/settings.json)
 * 2. Project settings ($CWD/.claude/settings.json)
 * 3. Local settings ($CWD/.claude/settings.local.json)
 * 4. Policy settings (platform-specific managed settings)
 * 5. Flag settings (from --settings flag if provided)
 *
 * Settings are cached for the session. Call resetSettingsCache() to invalidate.
 */
export function getSettings(): SandboxSettings {
  // Use cached result if available
  if (sessionSettingsCache !== null) {
    return sessionSettingsCache
  }

  // Load from disk and cache the result
  sessionSettingsCache = loadSettingsFromDisk()
  return sessionSettingsCache
}

/**
 * Get the filesystem implementation (for dependency injection/testing)
 */
export function getFsImplementation() {
  return fs
}
