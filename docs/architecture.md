# Architecture

GhostDeps is a modular, local-only developer tool. The pipeline is:

```text
DISCOVER (discovery.py)
   ↓  recursive file inventory, generated/vendor dirs ignored by default
DETECT (analyzers/*)
   ↓  manifest, AST, heuristic, docker, compose, CI, dotenv, network scans
FUSE (fusion.py)
   ↓  merge duplicate nodes, promote confidence, link same-name types,
      presence check, ghost classification
REPORT (reporters/*)
   ↓  terminal / json / markdown / sarif
TRACK (baseline.py) · VERIFY (verify.py) · EXPLAIN (cli why/explain)
```

## Modules

| Module | Responsibility |
|---|---|
| `discovery.py` | File inventory with safe ignore defaults, overridable via config |
| `analyzers/manifests.py` | Extensible manifest detector (JSON/TOML/XML/regex per ecosystem) |
| `analyzers/python_source.py` | Real AST analysis for Python (imports, subprocess, env, URLs, services, paths) |
| `analyzers/js_generic.py` | Heuristic analysis for JS/TS and other languages (explicitly weaker confidence) |
| `analyzers/env_services.py` | dotenv, services, network text, Dockerfile, Compose, GitHub Actions |
| `models.py` | Evidence-graph data model (`Dependency`, `Evidence`, `ScanResult`) |
| `fusion.py` | Merge, deterministic confidence promotion, presence, classification |
| `scanner.py` | Orchestration; one bad file never kills a scan; test-only marking |
| `reporters/` | terminal, versioned JSON, markdown, SARIF |
| `runtime/` | `RuntimeTracer` interface + Linux/Windows/macOS backends |
| `baseline.py` | Baseline create/diff for CI and PRs |
| `verify.py` | Honest presence verification (verified / not verified / unavailable / failed) |
| `portable.py` | Repository-specific portability assessment (not a machine health check) |
| `generate.py` | Contract/Dockerfile/devcontainer generation (always marked unverified) |
| `config.py` | Optional `ghostdeps.toml`/`ghostdeps.json`; never required |
| `cli.py` | Commands, documented exit codes 0/1/2 |

## Adding a detector

1. Create `src/ghostdeps/analyzers/<name>.py` with `handles(path)` and `analyze(path, root)`.
2. Return `Dependency` nodes with at least one `Evidence` each — never bare names.
3. Use `INFERRED`/`SUPPORTED` for heuristics; `STRONG` only for parser-backed
   findings with exact file+line; `VERIFIED` is reserved for runtime observation.
4. Wire it into `scanner._scan_file`.
5. Add a fixture under `tests/fixtures/` and a test asserting on the evidence
   graph (file, line, detector, kind), not just terminal output.

See `docs/detectors.md` and `docs/evidence-model.md`.
