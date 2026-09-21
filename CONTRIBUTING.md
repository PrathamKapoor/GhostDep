# Contributing to GhostDeps

Small, meaningful commits (`feat: …`, `test: …`, `docs: …`, `fix: …`).
Full workflow, detector guide, and release process: `docs/contributing.md`.

Quick checklist for every change:

1. Evidence first — no finding without detector + file + line where available.
2. Honest confidence — heuristics stay `INFERRED`/`SUPPORTED`; only runtime
   observation earns `VERIFIED`.
3. Tests assert on the evidence graph; add fixtures for detections *and*
   false positives.
4. `ruff check src tests`, `ruff format --check src tests`, and
   `python -m pytest` must pass.
5. Update the relevant `docs/` page and `CHANGELOG.md`.
