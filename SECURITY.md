# Security

GhostDeps is local-only by design (see `docs/security.md`): no telemetry,
no uploads, secret values never recorded.

If you find a vulnerability — especially secret leakage into reports,
arbitrary code execution during `scan`, or unsandboxed behavior in `verify` —
please report it via a private GitHub security advisory. Do not open a public
issue with exploit details or leaked secrets.

We aim to acknowledge reports within 3 business days.
