# Runtime tracing

Optional, explicit, and honest about its limits.

```bash
ghostdeps trace -- npm test
```

## What it captures (where the OS permits)

Process execution, resolved executable paths, exit status, duration, and —
on Linux when `strace` is installed — `execve`/`connect`/`openat` events for
child processes. The raw trace is saved to `.ghostdeps/last-trace.json`.

## Backends

`RuntimeTracer` → `LinuxTracer` / `WindowsTracer` / `MacOSTracer`, selected by
`platform.system()`, with a portable `GenericTracer` fallback. If a backend is
unavailable:

```text
Runtime tracing unavailable on this platform.
Static analysis completed successfully.
```

The scan never crashes because tracing is limited.

## What it does NOT claim

- Without `strace` (or on Windows/macOS), only the top-level process is
  observed; nested children are **not** fully traced. Every trace prints this
  warning explicitly.
- `VERIFIED` confidence applies only to what the traced command actually
  exercised. An untested code path stays `UNKNOWN`.
- Tracing runs the command you give it — it never executes repository code
  during a normal `scan`.
