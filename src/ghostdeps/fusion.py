"""Evidence fusion: merge duplicate nodes, promote confidence, classify states.

Deterministic promotion rules (documented in docs/evidence-model.md):

1. README/docs-only mention            -> INFERRED (never higher on its own)
2. Single heuristic static finding     -> INFERRED or SUPPORTED (per detector)
3. AST-backed subprocess/env finding   -> STRONG
4. Manifest declaration + presence     -> SUPPORTED (declaration is not proof of need)
5. Two independent evidence kinds agree (e.g. static + docker) -> at least STRONG
6. Runtime observation of execution    -> VERIFIED (only for what was actually exercised)

Classification:
- GHOST    = referenced/observed but NOT declared anywhere
- UNUSED   = declared but never referenced nor observed
- CONFLICT = contradictory declarations (e.g. two version ranges)
- OPTIONAL = test/CI-only, optional deps, platform-specific
- VERIFIED = runtime-observed + statically referenced
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ghostdeps.models import CONFIDENCE_RANK, Dependency, Evidence

DOC_DETECTORS = {"readme-scan", "docs-scan"}
INDEPENDENT_KINDS = {
    "static-subprocess",
    "static-shell",
    "static-env",
    "static-url",
    "manifest",
    "docker",
    "compose",
    "ci",
    "runtime",
    "dotenv",
}


def merge(deps: list[Dependency]) -> list[Dependency]:
    """Merge findings with the same (type, normalized name) into one node."""
    grouped: dict[tuple[str, str], Dependency] = {}
    for dep in deps:
        key = dep.key()
        if key not in grouped:
            grouped[key] = Dependency(
                name=dep.name,
                type=dep.type,
                declared=dep.declared,
                present=dep.present,
                referenced=dep.referenced,
                observed=dep.observed,
                required=dep.required,
            )
        node = grouped[key]
        node.states.update(dep.states)
        for ev in dep.evidences:
            node.add_evidence(ev)
        for rel in dep.relationships:
            if rel not in node.relationships:
                node.relationships.append(rel)
        # Boolean-ish rollups: YES wins over UNKNOWN; NO only if nothing says YES.
        for attr in ("declared", "present", "referenced", "observed"):
            v = getattr(dep, attr)
            cur = getattr(node, attr)
            if v == "YES":
                setattr(node, attr, "YES")
            elif v == "NO" and cur == "UNKNOWN":
                setattr(node, attr, "NO")
        if dep.required != "UNKNOWN" and node.required == "UNKNOWN":
            node.required = dep.required
    _link_same_name_across_types(grouped)
    return list(grouped.values())


def _link_same_name_across_types(grouped: dict[tuple[str, str], Dependency]) -> None:
    """Connect SYSTEM_PACKAGE <-> SYSTEM_BINARY nodes sharing a name.

    `apt-get install ffmpeg` (SYSTEM_PACKAGE) plus `subprocess.run(["ffmpeg"])`
    (SYSTEM_BINARY) are two nodes — one declaration, one reference — linked by
    a `provided-by` relationship. The link corroborates the binary node.
    """
    by_name: dict[str, list[Dependency]] = {}
    for node in grouped.values():
        by_name.setdefault(node.name.lower(), []).append(node)
    for name, nodes in by_name.items():
        pkgs = [n for n in nodes if n.type == "SYSTEM_PACKAGE"]
        bins = [n for n in nodes if n.type == "SYSTEM_BINARY"]
        if not pkgs or not bins:
            continue
        docker_pkg = any(
            e.detector in ("docker", "compose", "ci") for p in pkgs for e in p.evidences
        )
        for b in bins:
            rel = {
                "rel": "provided-by",
                "target": f"SYSTEM_PACKAGE:{name}",
                "via": "system package declaration (e.g. Dockerfile RUN)",
            }
            if rel not in b.relationships:
                b.relationships.append(rel)
            if docker_pkg and CONFIDENCE_RANK[b.confidence] < CONFIDENCE_RANK["STRONG"]:
                b.confidence = "STRONG"


def promote_confidence(deps: list[Dependency]) -> None:
    for dep in deps:
        kinds = {e.kind for e in dep.evidences}
        detectors = {e.detector for e in dep.evidences}
        # Rule 5: two independent evidence kinds -> at least STRONG.
        independent = kinds & {
            "static-subprocess",
            "manifest",
            "docker-system-package",
            "compose-service",
            "runtime-exec",
            "static-env",
            "env-declaration",
        }
        if len(independent) >= 2 or (len(kinds) >= 2 and _cross_source(detectors)):
            if CONFIDENCE_RANK[dep.confidence] < CONFIDENCE_RANK["STRONG"]:
                dep.confidence = "STRONG"
        # Rule 6: runtime observation -> VERIFIED (only with a runtime evidence).
        if any(
            e.kind in ("runtime-exec", "runtime-connection", "runtime-file") for e in dep.evidences
        ):
            dep.confidence = "VERIFIED"
            dep.states.add("VERIFIED")
        # Rule 1 cap: docs-only stays INFERRED.
        if detectors and detectors <= DOC_DETECTORS:
            dep.confidence = "INFERRED"


def _cross_source(detectors: set[str]) -> bool:
    groups = 0
    for family in (
        {"python-ast", "js-heuristic", "generic-heuristic", "network-scan"},
        {"manifest"},
        {"docker", "compose", "ci", "dotenv"},
    ):
        if detectors & family:
            groups += 1
    return groups >= 2


def check_presence(deps: list[Dependency], root: Path) -> None:
    """Best-effort local presence check. Honest UNKNOWN when undecidable."""
    for dep in deps:
        if dep.type == "SYSTEM_BINARY":
            found = shutil.which(dep.name) if _safe_bin_name(dep.name) else None
            if found:
                dep.present = "YES"
                dep.states.add("PRESENT")
                dep.add_evidence(
                    Evidence(
                        detector="presence",
                        kind="presence-which",
                        message=f"'{dep.name}' resolves to {found}",
                        confidence="SUPPORTED",
                    )
                )
            elif _safe_bin_name(dep.name):
                dep.present = "NO"
            else:
                dep.present = "UNKNOWN"
        elif dep.type == "ENVIRONMENT_VARIABLE":
            import os

            if dep.name in os.environ:
                dep.present = "YES"
                dep.states.add("PRESENT")
            else:
                dep.present = "UNKNOWN"  # absence in this shell proves nothing
        elif dep.type == "FILESYSTEM":
            p = Path(dep.name)
            if not p.is_absolute():
                p = root / dep.name
            dep.present = "YES" if p.exists() else "UNKNOWN"
        elif dep.type == "PACKAGE":
            dep.present = "UNKNOWN"  # resolved properly by verify step


def classify(deps: list[Dependency]) -> None:
    for dep in deps:
        declared = dep.declared == "YES"
        referenced = dep.referenced == "YES"
        observed = dep.observed == "YES"
        if (referenced or observed) and not declared:
            # Pseudo-nodes and docs-only mentions are never GHOSTs.
            if dep.name == "dynamic-subprocess":
                dep.states.add("UNKNOWN")
            # Docs-only INFERRED mentions are "unverified assumptions", not ghosts.
            elif dep.confidence == "INFERRED" and all(
                e.detector in DOC_DETECTORS for e in dep.evidences
            ):
                dep.states.add("UNKNOWN")
                if dep.required == "UNKNOWN":
                    dep.required = "UNKNOWN"
            else:
                dep.states.add("GHOST")
        if declared and not referenced and not observed:
            dep.states.add("UNUSED")
        if "OPTIONAL" in dep.states and dep.required == "UNKNOWN":
            dep.required = "OPTIONAL"
        # REQUIRED vs UNKNOWN: only claim REQUIRED with STRONG+ evidence.
        if dep.required == "UNKNOWN":
            if dep.confidence in ("STRONG", "VERIFIED") and (referenced or observed):
                dep.required = "YES"
        if not dep.states or dep.states == {"DISCOVERED"}:
            dep.states.add("UNKNOWN")


def _safe_bin_name(name: str) -> bool:
    return (
        bool(name)
        and "/" not in name
        and "\\" not in name
        and " " not in name
        and name not in ("dynamic-subprocess",)
    )
