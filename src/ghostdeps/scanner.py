"""Scan orchestration: discovery -> detectors -> fusion -> result."""

from __future__ import annotations

import re
from pathlib import Path

from ghostdeps.analyzers import manifests
from ghostdeps.analyzers.base import safe_read
from ghostdeps.analyzers.env_services import (
    analyze_compose,
    analyze_dockerfile,
    analyze_dotenv,
    analyze_github_workflow,
    analyze_network_text,
    infer_service_from_text,
)
from ghostdeps.analyzers.js_generic import (
    analyze_generic,
    analyze_js,
    handles_generic,
    handles_js,
)
from ghostdeps.analyzers.python_source import analyze as py_analyze
from ghostdeps.analyzers.python_source import handles as py_handles
from ghostdeps.config import Config
from ghostdeps.discovery import discover
from ghostdeps.fusion import check_presence, classify, merge, promote_confidence
from ghostdeps.models import Dependency, Evidence, ScanResult

MAX_FILES = 20_000


def run_scan(root: Path, config: Config | None = None, offline: bool = False) -> ScanResult:
    config = config or Config()
    root = root.resolve()
    discovered = discover(root, extra_ignores=config.ignore_paths)
    result = ScanResult(repo_root=str(root), offline=offline)
    detectors: list[str] = []

    raw: list[Dependency] = []
    files_scanned = 0
    files_skipped = 0

    for path in discovered.files:
        if files_scanned >= MAX_FILES:
            files_skipped += 1
            continue
        rel = _rel(path, root)
        if _ignored(rel, config.ignore_paths):
            files_skipped += 1
            continue
        try:
            found = _scan_file(path, root, result)
        except Exception as exc:  # one bad file must not kill the scan
            result.warnings.append(f"{rel}: analyzer error ({exc}); continued")
            continue
        if found is None:
            files_skipped += 1
            continue
        files_scanned += 1
        raw.extend(found)

    detectors = sorted(
        {
            "discovery",
            "manifest",
            "python-ast",
            "js-heuristic",
            "generic-heuristic",
            "dotenv",
            "docker",
            "compose",
            "ci",
            "network-scan",
            "readme-scan",
            "presence",
        }
    )
    result.detectors_run = detectors
    result.files_scanned = files_scanned
    result.files_skipped = files_skipped + max(
        0, len(discovered.files) - files_scanned - files_skipped
    )

    merged = merge(raw)
    _mark_test_only(merged)
    promote_confidence(merged)
    check_presence(merged, root)
    classify(merged)
    _apply_ignores(merged, config)
    merged.sort(key=lambda d: (d.type, d.name.lower()))
    result.dependencies = merged
    return result


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path).replace("\\", "/")


def _ignored(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if not pat:
            continue
        if rel == pat or rel.startswith(pat.rstrip("/") + "/"):
            return True
        try:
            if Path(rel).match(pat):
                return True
        except Exception:
            continue
    return False


def _scan_file(path: Path, root: Path, result: ScanResult) -> list[Dependency] | None:
    name = path.name
    suffix = path.suffix
    rel = _rel(path, root)

    # Manifests (incl. explicit unsupported reporting for manifest-like files)
    if manifests.is_manifest(path) or _looks_manifest_like(path):
        deps, unsupported = manifests.analyze_manifest(path, root)
        if unsupported and "not implemented" in unsupported:
            result.unsupported.append(unsupported)
        out = list(deps)
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            out.extend(analyze_dockerfile(path, root))
        if name in (
            "docker-compose.yml",
            "docker-compose.yaml",
            "docker-compose.override.yml",
            "compose.yaml",
            "compose.yml",
        ):
            out.extend(analyze_compose(path, root))
        if ".github" in path.parts and "workflows" in path.parts:
            out.extend(analyze_github_workflow(path, root))
        return out

    # Docker / compose / CI matched by path even if manifest check missed
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return analyze_dockerfile(path, root)
    if name in (
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.override.yml",
        "compose.yaml",
        "compose.yml",
    ):
        return analyze_compose(path, root)
    if ".github" in path.parts and "workflows" in path.parts and suffix in (".yml", ".yaml"):
        return analyze_github_workflow(path, root)

    # .env files
    if name.startswith(".env"):
        return analyze_dotenv(path, root)

    # Python AST
    if py_handles(path):
        out = py_analyze(path, root)
        out.extend(_readme_style_scan(path, root, "python-ast-extra"))
        return out

    # JS/TS heuristics
    if handles_js(path):
        return analyze_js(path, root)

    # Other source languages
    if handles_generic(path):
        return analyze_generic(path, root)

    # README / docs: weak INFERRED mentions only
    if name.lower().startswith(("readme", "contributing", "install")) or suffix in (
        ".md",
        ".rst",
        ".txt",
    ):
        return _docs_scan(path, root)

    # Config-ish text: network/service inference
    if suffix in (".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".example", ".template"):
        out = analyze_network_text(path, root)
        text = safe_read(path)
        if text:
            out.extend(infer_service_from_text(text, rel, "config-scan"))
        return out

    # Shell scripts with other extensions / no extension: check shebang
    if suffix == "" or suffix in (".sh",):
        try:
            head = safe_read(path)[:200]
        except Exception:
            head = ""
        if "bin/sh" in head or "bin/bash" in head:
            return analyze_generic(path, root)

    return []  # recognized-but-uninteresting file


def _looks_manifest_like(path: Path) -> bool:
    n = path.name.lower()
    return n in (
        "gemfile",
        "rakefile",
        "makefile",
        "cmakelists.txt",
        "build.xml",
        "package.yaml",
        "stack.yaml",
        "pubspec.yaml",
        "project.clj",
        "mix.exs",
        "rebar.config",
        "cpanfile",
        "build.sbt",
        "deps.edn",
    )


def _docs_scan(path: Path, root: Path) -> list[Dependency]:
    rel = _rel(path, root)
    text = safe_read(path)
    if not text:
        return []
    out: list[Dependency] = []
    # Explicit "requires/requires/depends on/prerequisites" lines -> weak env/binary hints.
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(
            r"(?:requires|needs|depends on|prerequisite|install)\s+([a-z][a-z0-9_\-]{1,40})",
            line,
            re.I,
        )
        if m:
            word = m.group(1).lower()
            if word in {"to", "you", "the", "a", "an", "and", "or", "for", "with", "this"}:
                continue
            d = Dependency(
                name=word,
                type="SYSTEM_PACKAGE",
                states={"DISCOVERED"},
                referenced="YES",
                required="UNKNOWN",
                confidence="INFERRED",
            )
            d.add_evidence(
                Evidence(
                    detector="readme-scan",
                    kind="docs-mention",
                    message=f"documentation mentions '{word}' (INFERRED only; docs are not proof)",
                    file=rel,
                    line=i,
                    snippet=line.strip()[:200],
                    confidence="INFERRED",
                )
            )
            out.append(d)
            if len(out) > 40:
                break
    return out


def _readme_style_scan(path: Path, root: Path, detector: str) -> list[Dependency]:
    _ = (path, root, detector)
    return []


def _apply_ignores(merged: list[Dependency], config: Config) -> None:
    ignored = {name.lower() for name in config.ignore_deps}
    if not ignored:
        return
    kept: list[Dependency] = []
    for dep in merged:
        if dep.name.lower() in ignored:
            continue
        kept.append(dep)
    merged[:] = kept


def _mark_test_only(merged: list[Dependency]) -> None:
    """Deps evidenced ONLY from test/CI paths are OPTIONAL, never REQUIRED."""
    for dep in merged:
        files = [(e.file or "") for e in dep.evidences]
        if not files:
            continue
        if all(_is_test_only_path(f) for f in files):
            dep.states.add("OPTIONAL")
            if dep.required == "YES":
                dep.required = "OPTIONAL"
            elif dep.required == "UNKNOWN" and dep.confidence in ("STRONG", "VERIFIED"):
                dep.required = "OPTIONAL"


def _is_test_only_path(rel: str) -> bool:
    low = rel.replace("\\", "/").lower()
    parts = low.split("/")
    return (
        any(p in {"tests", "test", "__tests__", "spec", "specs", "e2e"} for p in parts)
        or low.startswith("tests/")
        or low.startswith("test/")
        or ".github/workflows" in low
        or low.startswith(".github/")
    )
