> This is the Voratiq-maintained fork of the Anthropic Sandbox Runtime. It tracks `anthropic-experimental/sandbox-runtime` while layering in Voratiq branding, macOS `configd` allowances, and optional debug telemetry.

# Anthropic Sandbox Runtime (srt)

A lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

`srt` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.

> **Beta Research Preview**
>
> The Sandbox Runtime is a research preview developed for [Claude Code](https://www.claude.com/product/claude-code) to enable safer AI agents. It's being made available as an early open source preview to help the broader ecosystem build more secure agentic systems. As this is an early research preview, APIs and configuration formats may evolve. We welcome feedback and contributions to make AI agents safer by default!

## Installation

```bash
npm install -g @voratiq/sandbox-runtime
```
