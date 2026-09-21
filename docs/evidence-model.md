# Evidence model

Every finding is a node; every relationship has evidence.

```text
APPLICATION
    |
    | requires
    v
  ffmpeg
    ^
    |
    +-------------------+
    |                   |
source evidence      runtime evidence
    |                   |
video.py:42        /usr/bin/ffmpeg
```

## Records

- `Evidence`: detector, kind, message, file, line, snippet (≤300 chars),
  confidence contribution, timestamp.
- `Dependency`: name, type, states, evidences, declared/present/referenced/
  observed/required (each `YES`/`NO`/`UNKNOWN`, required may be `OPTIONAL`),
  confidence, relationships, e.g. `{rel: provided-by, target: ...}`.

## Deterministic confidence rules

| # | Observation | Confidence |
|---|---|---|
| 1 | README/docs mention only | `INFERRED` (capped; docs are not proof) |
| 2 | Single heuristic static finding | `INFERRED` or `SUPPORTED` (per detector) |
| 3 | AST-backed subprocess/env finding | `STRONG` |
| 4 | Manifest declaration (+presence) | `SUPPORTED` (declaration ≠ proof of need) |
| 5 | Two independent evidence kinds agree (e.g. static + docker) | at least `STRONG` |
| 6 | Runtime observation of actual execution | `VERIFIED` (only what was exercised) |

Cross-type corroboration: `apt-get install ffmpeg` (`SYSTEM_PACKAGE`) plus
`subprocess.run(["ffmpeg"])` (`SYSTEM_BINARY`) creates a `provided-by`
relationship and promotes the binary node to `STRONG` (rule 5 across types).

## Strength order

```text
UNKNOWN < INFERRED < SUPPORTED < STRONG < VERIFIED
```

No floats, no AI-style scores. `stronger(a, b)` is a pure max over this order,
so fusion is deterministic: same repository → same graph.

## Honesty rules

- Weak evidence is marked weak (`INFERRED`) or `UNKNOWN`, never upgraded silently.
- `why` traces only recorded observations; if causality is unknown it says so.
- A trustworthy `UNKNOWN` is better than an incorrect `REQUIRED`.
