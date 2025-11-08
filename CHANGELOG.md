# Changelog

All notable changes to this Voratiq-maintained fork are documented here.

## 0.7.0-voratiq1 - 2025-11-10

- Upstream baseline: 1bafa663538b0b7ef62758fce6f03648ca8f605e.
- Rebases Voratiq branding + telemetry work on top of upstream ripgrep customization and dependency preflight checks.
- Keeps macOS sandbox allowance for `com.apple.SystemConfiguration.configd` while adopting upstream sandbox schema changes. This permission is required to run Codex.
- Validation: `npm run build` (pass), `npm run typecheck` (pass), `npm run lint:check` (pass), `bun test`.
