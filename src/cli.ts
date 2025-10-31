#!/usr/bin/env node
import { Command } from 'commander'
import { SandboxManager } from './index.js'
import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig,
} from './sandbox/sandbox-config.js'
import { spawn } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import {
  initializeTelemetry,
  emitTelemetryEvent,
  sanitizeCommandArgs,
  isTelemetryEnabled,
} from './utils/telemetry.js'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { performance } from 'node:perf_hooks'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
const { version } = require('../package.json') as { version: string }

/**
 * Load and validate sandbox configuration from a file
 */
function loadConfig(filePath: string): SandboxRuntimeConfig | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null
    }
    const content = fs.readFileSync(filePath, 'utf-8')
    if (content.trim() === '') {
      return null
    }

    // Parse JSON
    const parsed = JSON.parse(content)

    // Validate with zod schema
    const result = SandboxRuntimeConfigSchema.safeParse(parsed)

    if (!result.success) {
      console.error(`Invalid configuration in ${filePath}:`)
      result.error.issues.forEach(issue => {
        const path = issue.path.join('.')
        console.error(`  - ${path}: ${issue.message}`)
      })
      return null
    }

    return result.data
  } catch (error) {
    // Log parse errors to help users debug invalid config files
    if (error instanceof SyntaxError) {
      console.error(`Invalid JSON in config file ${filePath}: ${error.message}`)
    } else {
      console.error(`Failed to load config from ${filePath}: ${error}`)
    }
    return null
  }
}

/**
 * Get default config path
 */
function getDefaultConfigPath(): string {
  return path.join(os.homedir(), '.srt-settings.json')
}

/**
 * Create a minimal default config if no config file exists
 */
function getDefaultConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: [],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

async function main(): Promise<void> {
  const program = new Command()

  program
    .name('srt')
    .description(
      'Run commands in a sandbox with network and filesystem restrictions',
    )
    .version(version)

  // Default command - run command in sandbox
  program
    .argument('<command...>', 'command to run in the sandbox')
    .option('-d, --debug', 'enable debug logging')
    .option(
      '-s, --settings <path>',
      'path to config file (default: ~/.srt-settings.json)',
    )
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: { debug?: boolean; settings?: string },
      ) => {
        try {
          const sanitizedCommand = sanitizeCommandArgs(commandArgs)

          const debugEnabled = Boolean(options.debug)

          if (debugEnabled && !process.env.DEBUG) {
            process.env.DEBUG = 'true'
          }

          const traceId = initializeTelemetry({
            debugEnabled,
            commandArgs,
          })

          if (traceId && isTelemetryEnabled()) {
            emitTelemetryEvent({
              stage: 'start',
              status: 'success',
              attempt: 0,
              command: sanitizedCommand,
              sandbox_verdict: {
                decision: 'allow',
                reason: 'cli_invocation',
                policy_tag: 'command.execution',
              },
              egress_type: 'command',
            })
          }

          // Load config from file
          const configPath = options.settings || getDefaultConfigPath()
          let runtimeConfig = loadConfig(configPath)

          if (!runtimeConfig) {
            logForDebugging(
              `No config found at ${configPath}, using default config`,
            )
            runtimeConfig = getDefaultConfig()
          }

          // Initialize sandbox with config
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize(runtimeConfig)

          // Join command arguments into a single command string
          const command = commandArgs.join(' ')
          logForDebugging(`Original command: ${command}`)

          const commandStart = performance.now()

          logForDebugging(
            JSON.stringify(
              SandboxManager.getNetworkRestrictionConfig(),
              null,
              2,
            ),
          )

          // Wrap the command with sandbox restrictions
          const sandboxedCommand = await SandboxManager.wrapWithSandbox(command)

          // Execute the sandboxed command
          console.log(`Running: ${command}`)
          if (isTelemetryEnabled()) {
            emitTelemetryEvent({
              stage: 'attempt',
              status: 'success',
              attempt: 0,
              command: sanitizedCommand,
              sandbox_verdict: {
                decision: 'allow',
                reason: 'sandbox_wrap',
                policy_tag: 'command.execution',
              },
              egress_type: 'command',
            })
          }

          const child = spawn(sandboxedCommand, {
            shell: true,
            stdio: 'inherit',
          })

          // Handle process exit
          child.on('exit', (code, signal) => {
            const latency = performance.now() - commandStart

            if (signal) {
              console.error(`Process killed by signal: ${signal}`)
              if (isTelemetryEnabled()) {
                emitTelemetryEvent({
                  stage: 'completion',
                  status: 'cancelled',
                  attempt: 0,
                  status_code: null,
                  command: sanitizedCommand,
                  sandbox_verdict: {
                    decision: 'allow',
                    reason: `terminated_by_${signal.toLowerCase()}`,
                    policy_tag: 'command.execution',
                  },
                  latency_ms: latency,
                  egress_type: 'command',
                })
              }

              process.exit(1)
            }

            if (isTelemetryEnabled()) {
              emitTelemetryEvent({
                stage: 'completion',
                status: code === 0 ? 'success' : 'failed',
                attempt: 0,
                status_code: code ?? null,
                command: sanitizedCommand,
                sandbox_verdict: {
                  decision: 'allow',
                  reason: 'process_exit',
                  policy_tag: 'command.execution',
                },
                latency_ms: latency,
                egress_type: 'command',
              })
            }

            process.exit(code ?? 0)
          })

          child.on('error', error => {
            console.error(`Failed to execute command: ${error.message}`)
            if (isTelemetryEnabled()) {
              emitTelemetryEvent({
                stage: 'failure',
                status: 'failed',
                attempt: 0,
                status_code: null,
                command: sanitizedCommand,
                sandbox_verdict: {
                  decision: 'allow',
                  reason: 'process_spawn_error',
                  policy_tag: 'command.execution',
                },
                latency_ms: performance.now() - commandStart,
                egress_type: 'command',
              })
            }
            process.exit(1)
          })

          // Handle cleanup on interrupt
          process.on('SIGINT', () => {
            child.kill('SIGINT')
          })

          process.on('SIGTERM', () => {
            child.kill('SIGTERM')
          })
        } catch (error) {
          console.error(
            `Error: ${error instanceof Error ? error.message : String(error)}`,
          )
          if (isTelemetryEnabled()) {
            emitTelemetryEvent({
              stage: 'failure',
              status: 'failed',
              attempt: 0,
              status_code: null,
              sandbox_verdict: {
                decision: null,
                reason: 'cli_error',
                policy_tag: 'command.execution',
              },
              latency_ms: null,
              egress_type: 'command',
            })
          }
          process.exit(1)
        }
      },
    )

  program.parse()
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
