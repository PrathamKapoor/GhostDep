# Output schema (JSON, v1.0.0)

`ghostdeps scan . --format json` emits a stable, machine-readable contract:

```json
{
  "schema_version": "1.0.0",
  "tool_version": "0.1.0",
  "repo_root": "/path/to/repo",
  "generated_at": 1726800000.0,
  "offline": false,
  "files_scanned": 128,
  "files_skipped": 4,
  "detectors_run": ["ci", "compose", "discovery", "..."],
  "warnings": [],
  "unsupported": [],
  "dependencies": [
    {
      "name": "ffmpeg",
      "type": "SYSTEM_BINARY",
      "states": ["DISCOVERED", "GHOST"],
      "confidence": "STRONG",
      "declared": "NO",
      "present": "YES",
      "referenced": "YES",
      "observed": "UNKNOWN",
      "required": "YES",
      "relationships": [{"rel": "provided-by", "target": "SYSTEM_PACKAGE:ffmpeg"}],
      "evidence": [
        {
          "detector": "python-ast",
          "kind": "static-subprocess",
          "message": "subprocess invocation of 'ffmpeg'",
          "file": "src/video.py",
          "line": 42,
          "snippet": "subprocess.run(ffmpeg ...)",
          "confidence": "STRONG",
          "timestamp": 1726800000.0
        }
      ]
    }
  ]
}
```

Compatibility promise: fields are only added, never renamed or removed,
without a `schema_version` bump. SARIF output follows the SARIF 2.1.0 schema
for GitHub code scanning; terminal and markdown are human conveniences with
no stability guarantee.

Exit codes: `0` success (or success with findings below failure criteria),
`1` findings match `--fail-on`/`fail_on` states, `2` usage/config/runtime error.
