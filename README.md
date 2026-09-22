# GhostDeps

**What does this repository actually require to execute?**

GhostDeps answers that question. A repo declares some dependencies in manifests —
but software also depends on external executables, system packages, runtimes,
environment variables, services, network endpoints, files, and platform behavior.
GhostDeps discovers these and builds an **Executable Dependency Contract** backed
by an **evidence graph**: every finding carries its detector, file, line, and
confidence. Honest `UNKNOWN` beats a confident lie.

## Why not another scanner?

GhostDeps is not a vulnerability scanner, SBOM generator, unused-import checker,
or environment drift dashboard. It does **dependency forensics**: distinguishing

```text
DECLARED vs PRESENT vs REFERENCED vs OBSERVED vs REQUIRED
```

`ffmpeg` can be *referenced* in code, *present* on your machine, and *nowhere
declared* — that gap is a **ghost dependency**, and it is what breaks fresh
checkouts, CI runners, and containers.

## 30-second example

```bash
pip install ghostdeps
ghostdeps scan .
```

```text
GhostDeps scan: ./my-video-app
files scanned: 2  dependencies: 1  ghosts: 1  conflicts: 0

== Discovered (ghost) dependencies ==
  SYSTEM_BINARY        ffmpeg  [STRONG]  (src/video.py:7)
```

```bash
ghostdeps why ffmpeg
```

```text
ffmpeg  [SYSTEM_BINARY]  confidence=STRONG
  Evidence chain (never invented; only recorded observations):
    +-- src/video.py:7  [python-ast/static-subprocess]
    |   subprocess invocation of 'ffmpeg'
```

## Installation

```bash
pip install ghostdeps        # core has zero runtime dependencies
```

Requires Python 3.10+. Works fully offline: `ghostdeps scan --offline`.

No API keys or accounts are required. The tool is local-only: your own
environment variables and repository files are enough. Optional runtime
tracing runs only the command you pass explicitly.

## Development

```bash
git clone https://github.com/PrathamKapoor/GhostDep.git
cd GhostDep
pip install -e ".[dev]"
ruff check src tests
ruff format --check src tests
python -m pytest tests/ -q
python -m build          # optional: wheel + sdist into dist/
```

## Commands

| Command | Purpose |
|---|---|
| `ghostdeps scan . [--format terminal\|json\|markdown\|sarif] [--offline] [--fail-on GHOST …]` | Full scan (no config needed) |
| `ghostdeps why <name>` / `explain <name>` | Evidence chain / full evidence record |
| `ghostdeps trace -- <cmd>` | Optional runtime tracing (explicit only) |
| `ghostdeps baseline create` / `ghostdeps diff` | Track dependency changes in CI/PRs |
| `ghostdeps doctor` | Actionable fixes (suggests, never auto-edits) |
| `ghostdeps verify [--clean]` | Presence checks: verified / not verified / unavailable / failed |
| `ghostdeps portable --target windows` | Repo-specific portability: BLOCKER / WARNING / SUPPORTED / UNKNOWN |
| `ghostdeps generate contract\|docker\|devcontainer` | Artifacts marked GENERATED, NOT YET VERIFIED |

Exit codes: `0` success · `1` findings match failure criteria · `2` usage/config error.

## What it detects

Packages (npm/pip/Go/Cargo/Maven/Gradle/NuGet/Ruby/Composer), system binaries
via AST-tracked `subprocess`/`child_process`/`exec.Command` calls, system
packages from Dockerfiles, runtimes, env vars (key names only — never values),
services (PostgreSQL/MySQL/MongoDB/Redis/Kafka/RabbitMQ/Elasticsearch/S3/SMTP —
*inferred*, never proven by import alone), network endpoints, Docker/Compose
structure, and GitHub Actions CI-only dependencies (kept `OPTIONAL`, never
misclassified as production).

Confidence is deterministic, not AI-flavored:
`UNKNOWN < INFERRED < SUPPORTED < STRONG < VERIFIED`.

## Architecture

```text
DISCOVER → DETECT → FUSE → REPORT → TRACK/VERIFY/EXPLAIN
```

Modular detectors (`ManifestAnalyzer`, `SourceAnalyzer`, `DockerAnalyzer`,
`CIAnalyzer`, `RuntimeTracer`, …) plug in without touching the core. Start at
`docs/architecture.md`, then `docs/evidence-model.md`.

## Privacy

Local only. No telemetry, no account, no cloud, no source upload. Secrets are
never printed; repository code runs only under explicit `trace`. See
`docs/security.md`.

## Limitations

Static analysis can't prove runtime need; Dockerfiles don't guarantee
production; README mentions are `INFERRED`; JS/non-Python analysis is
heuristic; dynamic commands are `UNKNOWN`. Full list: `docs/limitations.md`.

## Contributing / License

See `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`.
MIT licensed.
