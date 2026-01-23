# Changelog

All notable changes to this Voratiq-maintained fork are documented here.

## 0.0.29-voratiq0 - 2026-01-22

- Upstream baseline: b07da4039c1ce9447b812d9ff17dc3fabb270bd1 (0.0.29).
- Updated fork package metadata and documentation for the Voratiq-maintained release line.
- Allowed macOS sandbox to query `configd` for DNS resolution.
- Added network/fs observability events with scrubbing and spawn‑scoped callbacks.

## 0.0.29-voratiq1 - 2026-01-23

- Avoid non-blocking stdout panics by piping child output when stdout is not a TTY.
- Add host/port context to proxy socket error logs for easier debugging.
