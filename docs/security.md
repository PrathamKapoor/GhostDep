# Security and privacy

Default behavior is `LOCAL ONLY`: no telemetry, no account, no cloud,
no source upload — there is no network code in the scan path at all
(`--offline` additionally skips any future enrichment).

- **Secrets are never printed.** Detectors record key names only
  (`DATABASE_URL`, `AWS_SECRET_ACCESS_KEY`); `.env` values are never read
  into evidence, and snippets are capped at 300 chars.
- **Repository code is never executed during `scan`.** Only explicit commands
  run anything: `ghostdeps trace -- <cmd>` runs exactly the command you pass;
  `verify` performs read-only presence checks.
- **Network endpoints are never probed.** Detection is literal and local;
  verification of endpoints is `unavailable` by design (no traffic sent
  without consent).
- Reports may be shared freely: they contain file paths, dependency names,
  and short code snippets around detections — review before publishing
  if your snippets are sensitive.

See `SECURITY.md` for reporting vulnerabilities.
