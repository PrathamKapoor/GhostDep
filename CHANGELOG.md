# Changelog

All notable changes to this project are documented here.

## [0.1.0] — 2026-09-22

Initial public release:

- Repository discovery with safe ignore defaults + config overrides
- Manifest detection (npm, pip/poetry, Go, Cargo, Maven/Gradle, NuGet,
  Ruby, Composer, Docker, Compose, GitHub Actions) with explicit
  unsupported-type reporting
- Python AST source analysis; heuristic JS/TS + multi-language analysis
  with honestly capped confidence
- External executable, env var (key-only), service, network, Docker, CI analysis
- Evidence graph with deterministic confidence
  (`UNKNOWN < INFERRED < SUPPORTED < STRONG < VERIFIED`) and ghost classification
- `scan`, `why`, `explain`, `trace`, `baseline`/`diff`, `doctor`, `verify`,
  `portable`, `generate contract|docker|devcontainer`
- terminal / versioned JSON / markdown / SARIF output; documented exit codes
- Offline-first, zero runtime dependencies, stdlib-only core
