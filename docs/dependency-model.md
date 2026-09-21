# Dependency model

## The central distinction (never collapsed)

```text
DECLARED   — a manifest/config claims it (package.json, Dockerfile, .env.example…)
PRESENT    — it resolves on this machine right now (shutil.which, env set, path exists)
REFERENCED — source/config text refers to it (import, subprocess call, URL literal…)
OBSERVED   — runtime tracing saw it execute/connect during an explicit traced run
REQUIRED   — the tool's verdict, only at STRONG+ confidence, else UNKNOWN/OPTIONAL
```

Example:

```text
ffmpeg — Declared: NO, Present: YES, Referenced: YES, Observed: YES, Required: YES
imagemagick — Declared: YES, Present: YES, Referenced: NO, Observed: NO, Required: UNKNOWN
```

## Types

`PACKAGE`, `SYSTEM_BINARY`, `SYSTEM_PACKAGE`, `RUNTIME`, `SERVICE`,
`ENVIRONMENT_VARIABLE`, `NETWORK_ENDPOINT`, `FILESYSTEM`, `OPERATING_SYSTEM`,
`PLATFORM`, `TOOLCHAIN`, `CONFIGURATION`, `BEHAVIOR`, `CREDENTIAL_REFERENCE`.

Not every type applies to every language; unsupported cases are reported
explicitly (see `docs/limitations.md`), never silently dropped.

## States

`DECLARED`, `DISCOVERED`, `PRESENT`, `OBSERVED`, `REQUIRED`, `GHOST`,
`CONFLICT`, `UNUSED`, `OPTIONAL`, `UNKNOWN`, `VERIFIED`.

Key classifications:

- `GHOST` — referenced or observed but not declared anywhere.
- `UNUSED` — declared but never referenced nor observed.
- `OPTIONAL` — test-only, CI-only, optional extras, platform-specific.
  Dependencies evidenced *only* from `tests/`, `__tests__/`, `spec/`, or
  `.github/workflows` are `OPTIONAL` and never unconditionally `REQUIRED`.
- `CONFLICT` — contradictory declarations (reserved for version-range
  conflicts detected across manifests).
- Service language is deliberate: *client library detected* →
  *service requirement inferred* → *runtime service observed* →
  *service requirement verified*. Importing `psycopg2` never proves PostgreSQL
  is required.

There is no `isDependency` boolean anywhere in this codebase.
