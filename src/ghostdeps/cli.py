"""GhostDeps CLI.

Exit codes (documented):
    0 = successful scan (or command success), no failure-criteria findings
    1 = findings meeting configured failure criteria (--fail-on / fail_on)
    2 = usage / configuration / runtime error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ghostdeps import __version__
from ghostdeps.baseline import create_baseline, diff_results, load_baseline
from ghostdeps.config import Config
from ghostdeps.generate import generate_contract, generate_devcontainer, generate_docker
from ghostdeps.models import ScanResult
from ghostdeps.portable import assess
from ghostdeps.reporters import FORMATS, render
from ghostdeps.runtime import get_tracer
from ghostdeps.scanner import run_scan
from ghostdeps.verify import verify as verify_result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghostdeps", description="GhostDeps — executable dependency contracts from evidence."
    )
    p.add_argument("--version", action="store_true", help="print version and exit")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--format", choices=list(FORMATS), default="terminal")
    p.add_argument(
        "--offline", action="store_true", help="core analysis without network enrichment"
    )
    p.add_argument("--project-root", default=".", help="repository root to scan")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a repository (default command)")
    s.add_argument("path", nargs="?", default=None)
    s.add_argument(
        "--fail-on", nargs="*", default=None, help="states that cause exit 1, e.g. GHOST CONFLICT"
    )
    # Repeat global flags on `scan` so `ghostdeps scan --offline` works too.
    # SUPPRESS keeps the global value unless the flag is given after `scan`.
    s.add_argument("--verbose", action="store_true", default=argparse.SUPPRESS)
    s.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS)
    s.add_argument("--format", choices=list(FORMATS), default=argparse.SUPPRESS)
    s.add_argument("--offline", action="store_true", default=argparse.SUPPRESS)
    s.add_argument("--project-root", default=argparse.SUPPRESS)

    sub.add_parser("why", help="trace why a dependency is required").add_argument("name")
    sub.add_parser("explain", help="explain a dependency's evidence").add_argument("name")

    t = sub.add_parser("trace", help="trace a command's runtime behavior: ghostdeps trace -- <cmd>")
    t.add_argument("cmd", nargs=argparse.REMAINDER)

    b = sub.add_parser("baseline", help="baseline operations")
    b.add_argument("op", choices=("create",), nargs="?")

    sub.add_parser("diff", help="diff current scan against baseline")

    sub.add_parser("doctor", help="actionable explanations for findings")

    v = sub.add_parser("verify", help="verify findings against this machine")
    v.add_argument("--clean", action="store_true")

    pt = sub.add_parser("portable", help="repository-specific portability report")
    pt.add_argument("--target", default="windows")

    g = sub.add_parser("generate", help="generate artifacts")
    g.add_argument("what", choices=("contract", "docker", "devcontainer"))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"ghostdeps {__version__}")
        return 0
    root = Path(args.project_root).resolve()
    if not root.exists():
        print(f"ghostdeps: error: project root does not exist: {root}", file=sys.stderr)
        return 2
    config, _cfg_path, cfg_error = Config.load(root)
    if cfg_error:
        print(f"ghostdeps: warning: {cfg_error}", file=sys.stderr)
    offline = bool(args.offline or config.offline)

    cmd = args.command or "scan"
    try:
        if cmd == "scan":
            return _cmd_scan(args, root, config, offline)
        if cmd in ("why", "explain"):
            return _cmd_why_explain(args, root, config, offline, args.name, why=(cmd == "why"))
        if cmd == "trace":
            return _cmd_trace(args, root)
        if cmd == "baseline":
            return _cmd_baseline(args, root, config, offline)
        if cmd == "diff":
            return _cmd_diff(args, root, config, offline)
        if cmd == "doctor":
            return _cmd_doctor(args, root, config, offline)
        if cmd == "verify":
            return _cmd_verify(args, root, config, offline)
        if cmd == "portable":
            return _cmd_portable(args, root, config, offline)
        if cmd == "generate":
            return _cmd_generate(args, root, config, offline)
    except KeyboardInterrupt:
        print("ghostdeps: interrupted", file=sys.stderr)
        return 2
    print(f"ghostdeps: error: unknown command '{cmd}'", file=sys.stderr)
    return 2


# ------------------------------------------------------------------ helpers
def _load_scan(root: Path, config: Config, offline: bool) -> ScanResult:
    return run_scan(root, config=config, offline=offline)


def _fail_on_states(args, config: Config) -> list[str]:
    explicit = getattr(args, "fail_on", None)
    if explicit:
        return [s.upper() for s in explicit]
    return list(config.fail_on or [])


def _exit_for(result: ScanResult, fail_on: list[str]) -> int:
    if not fail_on:
        return 0
    for dep in result.dependencies:
        if set(fail_on) & set(dep.states):
            return 1
    return 0


# ------------------------------------------------------------------ commands
def _cmd_scan(args, root: Path, config: Config, offline: bool) -> int:
    target = Path(getattr(args, "path", None) or ".")
    scan_root = (root / target).resolve() if not target.is_absolute() else target.resolve()
    if not scan_root.exists():
        print(f"ghostdeps: error: scan path does not exist: {scan_root}", file=sys.stderr)
        return 2
    result = run_scan(scan_root, config=config, offline=offline)
    fmt = args.format
    if fmt == "terminal":
        from ghostdeps.reporters import render_terminal

        print(render_terminal(result, verbose=args.verbose, quiet=args.quiet), end="")
    else:
        print(render(result, fmt), end="")
    return _exit_for(result, _fail_on_states(args, config))


def _cmd_why_explain(args, root, config, offline, name: str, why: bool) -> int:
    result = _load_scan(root, config, offline)
    matches = result.by_name(name)
    # also allow TYPE/name lookup like SERVICE/postgres
    if not matches and "/" in name:
        _, _, tail = name.partition("/")
        matches = result.by_name(tail)
    if not matches:
        print(f"No dependency named '{name}' found in this repository.")
        print("Run `ghostdeps scan .` to see what was discovered.")
        return 0
    for dep in matches:
        if why:
            print(_render_why(dep))
        else:
            print(_render_explain(dep))
    return 0


def _render_why(dep) -> str:
    L = [f"{dep.name}  [{dep.type}]  confidence={dep.confidence}"]
    if not dep.evidences:
        L.append("  (no evidence recorded — relationship UNKNOWN)")
        return "\n".join(L)
    L.append("  Evidence chain (never invented; only recorded observations):")
    for ev in dep.evidences:
        loc = f"{ev.file}:{ev.line}" if ev.file and ev.line else (ev.file or ev.detector)
        L.append(f"    +-- {loc}  [{ev.detector}/{ev.kind}]")
        L.append(f"    |   {ev.message}")
        if ev.snippet:
            L.append(f"    |   snippet: {ev.snippet[:160]}")
    if len(dep.evidences) == 1 and dep.confidence in ("UNKNOWN", "INFERRED"):
        L.append(
            "  Relationship strength: UNKNOWN — a single weak observation cannot prove causality."
        )
    return "\n".join(L)


def _render_explain(dep) -> str:
    L = [
        f"What:        {dep.name} ({dep.type})",
        f"States:      {', '.join(sorted(dep.states)) or 'none'}",
        f"Confidence:  {dep.confidence}",
        f"Declared:    {dep.declared}",
        f"Present:     {dep.present}",
        f"Referenced:  {dep.referenced}",
        f"Observed:    {dep.observed}",
        f"Required:    {dep.required}",
        "Evidence:",
    ]
    if not dep.evidences:
        L.append("  (none recorded)")
    for ev in dep.evidences:
        loc = f"{ev.file}:{ev.line}" if ev.file and ev.line else (ev.file or ev.detector)
        L.append(f"  - [{ev.confidence}] {ev.detector}/{ev.kind} at {loc}: {ev.message}")
    return "\n".join(L)


def _cmd_trace(args, root: Path) -> int:
    raw = list(getattr(args, "cmd", []) or [])
    if raw and raw[0] == "--":
        raw = raw[1:]
    if not raw:
        print("ghostdeps: error: usage: ghostdeps trace -- <command> [args...]", file=sys.stderr)
        return 2
    tracer = get_tracer()
    ok, note = tracer.available()
    print(f"tracer backend: {tracer.name} ({note})")
    if not ok:
        print(
            "Runtime tracing unavailable on this platform. Static analysis completed successfully."
        )
        return 2
    res = tracer.trace(raw, cwd=str(root))
    print(f"command: {' '.join(res.command)}")
    print(f"exit: {res.exit_code}  duration: {res.duration_s:.2f}s  backend: {res.backend}")
    for ev in res.events[-30:]:
        print(f"  [{ev.kind}] {ev.message}")
    for w in res.warnings:
        print(f"  note: {w}")
    # Persist raw trace next to baseline dir for later correlation.
    try:
        dest = root / ".ghostdeps" / "last-trace.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
        print(f"trace saved to {dest}")
    except OSError:
        pass
    return 0


def _cmd_baseline(args, root, config, offline) -> int:
    result = _load_scan(root, config, offline)
    dest = create_baseline(result, root)
    print(f"baseline created: {dest} ({len(result.dependencies)} dependencies)")
    return 0


def _cmd_diff(args, root, config, offline) -> int:
    old = load_baseline(root)
    if old is None:
        print(
            "ghostdeps: error: no baseline found; run `ghostdeps baseline create` first",
            file=sys.stderr,
        )
        return 2
    new = _load_scan(root, config, offline)
    d = diff_results(old, new)
    print(
        f"baseline diff: +{d['counts']['added']} "
        f"-{d['counts']['removed']} ~{d['counts']['changed']}"
    )
    for item in d["added"][:30]:
        print(f"  + {item['type']} {item['name']} [{item['confidence']}]")
    for item in d["removed"][:30]:
        print(f"  - {item['type']} {item['name']}")
    for item in d["changed"][:30]:
        print(f"  ~ {item['type']} {item['name']}: {item['before']} -> {item['after']}")
    return 0


def _cmd_doctor(args, root, config, offline) -> int:
    result = _load_scan(root, config, offline)
    n = 0
    for dep in result.dependencies:
        suggestion = _suggestion(dep)
        if suggestion is None:
            continue
        n += 1
        print(f"{n}. {dep.name} ({dep.type}, {dep.confidence})")
        print(f"   {_summary(dep)}")
        print(f"   Suggested action: {suggestion}")
        print()
    if n == 0:
        print(
            "No actionable findings. Everything referenced appears declared, "
            "or remaining items are UNKNOWN (honestly uncertain)."
        )
    return 0


def _summary(dep) -> str:
    if "GHOST" in dep.states:
        return "Required or referenced by evidence, but not declared in project manifests."
    if "UNUSED" in dep.states:
        return "Declared but never referenced nor observed in this scan."
    if "CONFLICT" in dep.states:
        return "Conflicting declarations or evidence."
    return f"States: {sorted(dep.states)}; confidence {dep.confidence}."


def _suggestion(dep) -> str | None:
    if "GHOST" in dep.states:
        if dep.type == "SYSTEM_BINARY":
            return f"declare '{dep.name}' as a system dependency (docs/Dockerfile/contract)."
        if dep.type in ("ENVIRONMENT_VARIABLE", "CREDENTIAL_REFERENCE"):
            return (
                f"document '{dep.name}' in .env.example WITHOUT its value "
                f"(key name only; never commit secrets)."
            )
        if dep.type == "SERVICE":
            return (
                f"decide whether '{dep.name}' is really required; a client-library "
                f"import alone does not prove it — confirm with runtime evidence."
            )
        return f"declare or explicitly ignore '{dep.name}' with a reason in ghostdeps.toml."
    if "UNUSED" in dep.states and dep.type == "PACKAGE":
        return (
            f"verify '{dep.name}' is truly unused (false positives possible for "
            f"plugins/dynamic imports) before removing."
        )
    return None


def _cmd_verify(args, root, config, offline) -> int:
    result = _load_scan(root, config, offline)
    out = verify_result(result, root, clean=bool(args.clean))
    print(
        f"verification ({out['mode']}): "
        + ", ".join(f"{k}: {v}" for k, v in out["summary"].items())
    )
    print(out["note"])
    if not args.quiet:
        for item in out["items"][:60]:
            print(f"  [{item['status']}] {item['type']} {item['name']}: {item['detail']}")
        if len(out["items"]) > 60:
            print(f"  ... and {len(out['items']) - 60} more")
    return 0


def _cmd_portable(args, root, config, offline) -> int:
    result = _load_scan(root, config, offline)
    rep = assess(result, args.target)
    print(
        f"portability target: {rep['target']}  supported: {rep['supported_count']}  "
        f"findings: {rep['finding_count']}"
    )
    for f in rep["findings"][:50]:
        print(f"  [{f['verdict']}] {f['type']} {f['name']}: {f['reason']}")
    print(rep["note"])
    return 0


def _cmd_generate(args, root, config, offline) -> int:
    result = _load_scan(root, config, offline)
    if args.what == "contract":
        print(generate_contract(result), end="")
    elif args.what == "docker":
        print(generate_docker(result), end="")
    elif args.what == "devcontainer":
        print(generate_devcontainer(result), end="")
    else:
        print(f"ghostdeps: error: unknown generate target '{args.what}'", file=sys.stderr)
        return 2
    return 0
