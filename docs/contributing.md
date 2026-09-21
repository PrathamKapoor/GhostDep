# Contributing

## Workflow

Phases land in order: discovery → manifests → static analysis → evidence
model → classification → output → env/service/network/docker/CI →
why/explain → baseline → tracing → verification → portability → contract →
SARIF/action → hardening. Each phase: implement, test, verify, document,
commit with a small meaningful message (`feat: …`, `test: …`, `docs: …`,
`fix: …`).

## Rules

- Every finding needs evidence (detector, kind, file, line when available).
- Stdlib-only core: no new runtime dependencies without justification
  (offline install must keep working).
- Tests assert on the evidence graph, not just terminal output; add fixtures
  for both detections and false positives.
- `ruff check` and `ruff format --check` must pass; `python -m pytest` green.
- Never add fake capabilities — mark `NOT IMPLEMENTED` / `INFERRED` /
  `UNAVAILABLE ON THIS PLATFORM` honestly.
- Privacy: never record secret values, never add network calls to the scan path.

## Releasing

Bump `__version__` (and `schema_version` only on breaking JSON changes),
update `CHANGELOG.md`, tag `vX.Y.Z`, attach build artifacts + checksums
(see CI release job).
