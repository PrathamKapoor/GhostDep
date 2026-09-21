# Configuration

No configuration file is required. The first `ghostdeps scan .` is useful
immediately. Optionally, place `ghostdeps.toml` (or `.ghostdeps.toml`,
`ghostdeps.json`, `.ghostdeps.json`) at the repository root:

```toml
[ghostdeps]
ignore_paths = ["docs/", "examples/"]   # also: glob patterns
ignore_deps = ["lodash"]                # or { lodash = "reason…" } in JSON
severity = "medium"
target_platforms = ["linux"]
fail_on = ["GHOST", "CONFLICT"]         # states causing exit code 1
offline = false
output = "terminal"                     # terminal | json | markdown | sarif
```

Every ignore rule should carry a reason (use the JSON map form for
`ignore_deps`); unexplained ignores are a smell. CLI flags override config:
`--offline`, `--format`, `--project-root`, `--fail-on`, `--verbose`, `--quiet`.
