# Verification

```bash
ghostdeps verify
ghostdeps verify --clean
```

Docker is **never** required for scanning. Verification re-checks each finding
against the local machine without executing repository code:

| Dependency type | Check | Possible statuses |
|---|---|---|
| `SYSTEM_BINARY` | `shutil.which` | verified / not verified |
| `PACKAGE` (python) | importable without importing | verified / unavailable |
| `PACKAGE` (js) | `node_modules/<pkg>` exists | verified / unavailable |
| env / credential | key set (value never shown) | verified / not verified |
| `FILESYSTEM` | path exists | verified / not verified |
| `SERVICE` | — (needs a live connection test) | verification unavailable |
| `NETWORK_ENDPOINT` | — (no traffic sent without consent) | verification unavailable |

Statuses are exactly: `verified`, `not verified`, `verification unavailable`,
`verification failed`. `--clean` re-runs checks bypassing caches and probes
for Docker; container-isolated verification beyond the presence probe is
explicitly **not yet implemented** and reported as such.
