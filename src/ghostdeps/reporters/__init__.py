"""Reporters: terminal, json, markdown, sarif."""

from __future__ import annotations

import json

from ghostdeps.models import ScanResult

FORMATS = ("terminal", "json", "markdown", "sarif")


def render(result: ScanResult, fmt: str) -> str:
    fmt = (fmt or "terminal").lower()
    if fmt == "json":
        return render_json(result)
    if fmt == "markdown":
        return render_markdown(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_terminal(result)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False)


# ---------------------------------------------------------------- terminal
def render_terminal(result: ScanResult, verbose: bool = False, quiet: bool = False) -> str:
    deps = result.dependencies
    ghosts = [d for d in deps if "GHOST" in d.states]
    conflicts = [d for d in deps if "CONFLICT" in d.states]
    unverified = [d for d in deps if d.confidence in ("UNKNOWN", "INFERRED")]
    lines: list[str] = []
    lines.append(f"GhostDeps scan: {result.repo_root}")
    lines.append(
        f"files scanned: {result.files_scanned}  dependencies: {len(deps)}  "
        f"ghosts: {len(ghosts)}  conflicts: {len(conflicts)}"
    )
    if result.offline:
        lines.append("mode: OFFLINE (network enrichment skipped)")
    lines.append("")
    if not quiet:
        lines.append("== Declared dependencies ==")
        declared = [d for d in deps if d.declared == "YES"]
        if not declared:
            lines.append("  (none detected)")
        for d in declared[:50]:
            lines.append(f"  {d.type:20} {d.name}  [{d.confidence}]")
        if len(declared) > 50:
            lines.append(f"  ... and {len(declared) - 50} more (see --format json)")
        lines.append("")
        lines.append("== Discovered (ghost) dependencies ==")
        if not ghosts:
            lines.append("  (none — everything referenced appears to be declared)")
        for d in ghosts[:50]:
            ev = d.evidences[0] if d.evidences else None
            where = f"{ev.file}:{ev.line}" if ev and ev.file else "unknown location"
            lines.append(f"  {d.type:20} {d.name}  [{d.confidence}]  ({where})")
        if len(ghosts) > 50:
            lines.append(f"  ... and {len(ghosts) - 50} more")
        lines.append("")
        lines.append("== Services / environment / network / platform ==")
        for dtype in (
            "SERVICE",
            "ENVIRONMENT_VARIABLE",
            "CREDENTIAL_REFERENCE",
            "NETWORK_ENDPOINT",
            "SYSTEM_BINARY",
            "RUNTIME",
            "PLATFORM",
        ):
            group = [d for d in deps if d.type == dtype]
            if group:
                lines.append(
                    f"  {dtype} ({len(group)}): "
                    + ", ".join(d.name for d in group[:12])
                    + (" ..." if len(group) > 12 else "")
                )
        lines.append("")
        if conflicts:
            lines.append(f"== Conflicts ({len(conflicts)}) ==")
            for d in conflicts[:20]:
                lines.append(f"  {d.name}: {[e.message for e in d.evidences[:2]]}")
            lines.append("")
        if unverified:
            lines.append(
                f"Unverified assumptions: {len(unverified)} "
                f"(use `ghostdeps explain <name>` for evidence)"
            )
            lines.append("")
    else:
        for d in ghosts:
            lines.append(f"GHOST {d.type} {d.name} [{d.confidence}]")
    if result.unsupported:
        lines.append("Unsupported / explicit unknowns:")
        for u in result.unsupported[:20]:
            lines.append(f"  - {u}")
        lines.append("")
    if result.warnings and verbose:
        lines.append("Warnings:")
        for w in result.warnings[:20]:
            lines.append(f"  ! {w}")
    if verbose:
        lines.append("")
        lines.append(f"detectors: {', '.join(result.detectors_run)}")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------- markdown
def render_markdown(result: ScanResult) -> str:
    L: list[str] = []
    L.append("# GhostDeps report")
    L.append("")
    L.append(f"- Repository: `{result.repo_root}`")
    L.append(f"- Tool: ghostdeps {result.tool_version} (schema {result.schema_version})")
    L.append(f"- Files scanned: {result.files_scanned}")
    L.append(f"- Dependencies: {len(result.dependencies)}")
    L.append("")
    L.append(
        "| Name | Type | States | Confidence | Declared "
        "| Referenced | Observed | Required | Evidence |"
    )
    L.append("|---|---|---|---|---|---|---|---|---|")
    for d in result.dependencies:
        ev = "; ".join(
            f"{e.detector}:{e.kind} {e.file or ''}{(':' + str(e.line)) if e.line else ''}"
            for e in d.evidences[:3]
        )
        L.append(
            f"| {d.name} | {d.type} | {', '.join(sorted(d.states))} | {d.confidence} | "
            f"{d.declared} | {d.referenced} | {d.observed} | {d.required} | {ev} |"
        )
    L.append("")
    if result.unsupported:
        L.append("## Unsupported (explicit)")
        for u in result.unsupported:
            L.append(f"- {u}")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- sarif
def render_sarif(result: ScanResult) -> str:
    rules = []
    results = []
    seen_rules: dict[str, int] = {}
    for d in result.dependencies:
        if "GHOST" not in d.states and "CONFLICT" not in d.states:
            continue
        rule_id = f"ghostdeps/{d.type.lower()}/{d.name.lower()}"
        if rule_id not in seen_rules:
            seen_rules[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": f"GhostDependency{d.type.title()}",
                    "shortDescription": {
                        "text": f"{d.name} ({d.type}) is referenced but not declared"
                    },
                    "fullDescription": {
                        "text": f"Confidence {d.confidence}; states {sorted(d.states)}"
                    },
                    "help": {"text": f"Run `ghostdeps explain {d.name}` for evidence."},
                }
            )
        ev = d.evidences[0] if d.evidences else None
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning" if "GHOST" in d.states else "error",
                "message": {
                    "text": f"{d.name} [{d.confidence}]: "
                    f"{(ev.message if ev else 'no evidence message')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": (ev.file if ev and ev.file else "unknown")},
                            "region": {"startLine": (ev.line if ev and ev.line else 1)},
                        }
                    }
                ]
                if ev and ev.file
                else [],
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ghostdeps",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/example/ghostdeps",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
