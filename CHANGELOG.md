# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Add opt-in debug telemetry with shared trace IDs, sanitized command logging, TLS instrumentation, and structured sandbox event reporting across the CLI and proxy layers.
- Provide redaction helpers and tests that gate telemetry to protect sensitive data.
- Fix CLI version reporting so `srt --version` reflects the package.json metadata.

## 0.0.3 - 2025-10-28

- Allow macOS sandbox profiles to query `com.apple.SystemConfiguration.configd`

## 0.0.2 - 2025-10-28

- Rebranded the package to `@voratiq/sandbox-runtime`
