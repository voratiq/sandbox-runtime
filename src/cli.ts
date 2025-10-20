#!/usr/bin/env node
import { Command } from 'commander'
import { SandboxManager } from './index.js'
import { spawn } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import { setFlagSettingsPath } from './utils/settings.js'

async function main(): Promise<void> {
  const program = new Command()

  program
    .name('srt')
    .description(
      'Run commands in a sandbox with network and filesystem restrictions',
    )
    .version('1.0.0')

  // Default command - run command in sandbox
  program
    .argument('<command...>', 'command to run in the sandbox')
    .option('-d, --debug', 'enable debug logging')
    .option(
      '-s, --settings <path>',
      'path to settings file (default: ~/.claude/settings.json)',
    )
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: { debug?: boolean; settings?: string },
      ) => {
        try {
          // Enable debug logging if requested
          if (options.debug) {
            process.env.DEBUG = 'true'
          }

          // Set flag settings path if provided
          if (options.settings) {
            setFlagSettingsPath(options.settings)
          }

          // Initialize sandbox
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize()

          // Join command arguments into a single command string
          const command = commandArgs.join(' ')
          logForDebugging(`Original command: ${command}`)

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
          const child = spawn(sandboxedCommand, {
            shell: true,
            stdio: 'inherit',
          })

          // Handle process exit
          child.on('exit', (code, signal) => {
            if (signal) {
              console.error(`Process killed by signal: ${signal}`)
              process.exit(1)
            }
            process.exit(code ?? 0)
          })

          child.on('error', error => {
            console.error(`Failed to execute command: ${error.message}`)
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
