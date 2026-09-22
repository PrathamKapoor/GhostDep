# Detectors

| Detector | Method | Confidence | Notes |
|---|---|---|---|
| `manifest` | JSON/TOML/XML parsing + targeted regex for lockfiles/Gradle | `SUPPORTED` | Lockfile entries are declarations, not proof of need |
| `python-ast` | Real `ast` parsing: imports, `subprocess.*`, `os.system`, `os.getenv`/`os.environ`, URL/connection-string/path literals | `STRONG` (calls/env), `SUPPORTED` (imports/URLs), `INFERRED` (services/paths) | Stdlib imports excluded from `PACKAGE` |
| `js-heuristic` | Regex for `import`/`require`, `child_process`, `process.env`, URLs | `SUPPORTED`/`INFERRED` | Stdlib has no JS parser; honestly weaker, never `STRONG` alone |
| `generic-heuristic` | Regex for Go/Rust/Java/C#/Ruby/PHP/shell/Makefile execution + env + URLs | `SUPPORTED`/`INFERRED` | Same honesty rule as JS |
| `dotenv` | `.env*` key declarations (values never recorded) | `SUPPORTED` | Secret-looking keys → `CREDENTIAL_REFERENCE` |
| `docker` | `FROM`/`RUN`/`ENV`/`ARG`/`EXPOSE`/…; apt/apk/yum package extraction | `SUPPORTED`/`INFERRED` | Declarations are evidence, not runtime proof |
| `compose` | Image→service mapping, env keys, ports, `depends_on` | `INFERRED`/`SUPPORTED` | Service = inferred, not proven |
| `ci` | GitHub Actions: `uses:`, `run:`, services, env blocks | `SUPPORTED`/`INFERRED` | Findings marked CI-only/`OPTIONAL`; never auto-production |
| `network-scan` | URL/endpoint literals in config/text files | `SUPPORTED`/`INFERRED` | No traffic ever sent; known XML-namespace identifiers (Maven POM, XSD) are skipped — they are names, not endpoints |
| `readme-scan` | `requires|needs|depends on|…` mentions | `INFERRED` (capped) | Docs are not proof |
| `presence` | `shutil.which`, env lookup, path existence | `SUPPORTED` | Absence of env vars = `UNKNOWN`, not `NO` |
| `runtime` | Explicit `ghostdeps trace -- <cmd>` only | `VERIFIED` | Only what was actually exercised |

## Manifest coverage

`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
`requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile`, `Pipfile.lock`,
`uv.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `pom.xml`,
`build.gradle`, `build.gradle.kts`, `*.csproj`, `Gemfile`, `Gemfile.lock`,
`composer.json`, `composer.lock`, `Dockerfile`, `docker-compose.yml`,
`compose.yaml`, `.github/workflows/*`.

Any other manifest-like file (e.g. `mix.exs`, `pubspec.yaml`, `CMakeLists.txt`)
produces an explicit *unsupported* notice — never a silent partial result.

## External executables (core feature)

Detected from `child_process.*`, `subprocess.*`, `os.system/popen`,
`exec.Command`, `Runtime.exec`, `ProcessBuilder`, shell scripts, Makefiles,
and `package.json` scripts. Literal commands resolve to `SYSTEM_BINARY`
(`STRONG` via AST); non-literal commands become `BEHAVIOR/dynamic-subprocess`
(`UNKNOWN` executable, `INFERRED`) instead of a guessed name.
Dynamic pseudo-nodes are never classified `GHOST`.

Noise guards (documented, tested): stdlib imports and the repo's own
packages (src layout + pyproject name) are never `PACKAGE` findings;
regex/template fragments are rejected as URLs; XML-namespace identifiers
are names, not endpoints.
