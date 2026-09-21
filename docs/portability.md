# Portability

```bash
ghostdeps portable --target windows   # or linux, macos
```

Answers: *what about THIS repository constrains the target platform?*
It is not a machine health check.

| Verdict | Meaning |
|---|---|
| `BLOCKER` | Concrete evidence of breakage, e.g. absolute `/etc/…` paths targeting Windows, POSIX-only behavior (`inotify`, `fork`) |
| `WARNING` | Likely friction, e.g. `bash`/`make` on stock Windows |
| `SUPPORTED` | No known constraint found |
| `UNKNOWN` | Not enough evidence (binaries, service reachability) — verify on target |

Never claims universal compatibility. Unknowns are reported, not hidden.
