# Limitations (what GhostDeps cannot prove)

GhostDeps prefers an honest `UNKNOWN` over an unsupported conclusion.

- **Static analysis cannot prove runtime need.** A `subprocess` call on an
  untested branch is `STRONG` evidence, not `VERIFIED` proof.
- **Runtime observation proves only what was exercised.** `trace -- npm test`
  says nothing about untested paths.
- **A Dockerfile guarantees nothing about production.** It is evidence
  (`SUPPORTED`), not proof.
- **A README statement is not proof** (`INFERRED`, capped).
- **Client-library imports do not prove service requirements.**
  `import psycopg2` yields *service requirement inferred*, full stop.
- **JS/TS and non-Python languages use heuristics** (no stdlib parsers);
  confidence is capped accordingly until corroborated.
- **Dynamic commands are `UNKNOWN`.** `subprocess.run(cmd)` with a variable
  becomes `BEHAVIOR/dynamic-subprocess`, never a guessed binary name.
- **Test/CI-only findings are `OPTIONAL`.** Mocks, dead code, conditional and
  platform-specific imports are reported with their (weak) evidence, not as
  unconditional production requirements.
- **Unsupported manifest types and platforms** produce explicit
  `NOT IMPLEMENTED` / `UNAVAILABLE ON THIS PLATFORM` messages, never fake
  results or silent gaps.
- **Verification without Docker** is presence-checking, not reproduction;
  container-isolated verification is not yet implemented.
