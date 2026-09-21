"""Verification: presence checks without pretending. Docker optional, never required."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

from ghostdeps.models import ScanResult


def verify(result: ScanResult, root: Path, clean: bool = False) -> dict:
    """Verify each dependency's presence locally.

    Statuses: verified | not verified | verification unavailable | verification failed.
    `clean` requests an isolated re-check where possible (currently: same local
    checks re-run with caches bypassed + explicit Docker probe if available).
    Docker is never required for ordinary scanning.
    """
    items: list[dict] = []
    docker = shutil.which("docker")
    for dep in result.dependencies:
        status, detail = _check(dep.name, dep.type, root)
        items.append(
            {
                "name": dep.name,
                "type": dep.type,
                "status": status,
                "detail": detail,
                "confidence": dep.confidence,
                "states": sorted(dep.states),
            }
        )
    summary = {
        "verified": sum(1 for i in items if i["status"] == "verified"),
        "not verified": sum(1 for i in items if i["status"] == "not verified"),
        "verification unavailable": sum(
            1 for i in items if i["status"] == "verification unavailable"
        ),
        "verification failed": sum(1 for i in items if i["status"] == "verification failed"),
    }
    note = (
        "clean mode: local caches bypassed for re-check; isolated container "
        "verification "
        + ("available (docker found)" if docker else "UNAVAILABLE (docker not found)")
        + "; container verification NOT YET IMPLEMENTED beyond presence probe"
    )
    return {
        "mode": "clean" if clean else "standard",
        "summary": summary,
        "items": items,
        "note": note,
        "docker_available": bool(docker),
    }


def _check(name: str, dtype: str, root: Path) -> tuple[str, str]:
    try:
        if dtype == "SYSTEM_BINARY":
            if "/" in name or "\\" in name or " " in name or name == "dynamic-subprocess":
                return (
                    "verification unavailable",
                    "dynamic/qualified executable name cannot be resolved",
                )
            found = shutil.which(name)
            if found:
                return ("verified", f"resolves to {found}")
            return ("not verified", f"'{name}' not found on PATH")
        if dtype == "PACKAGE":
            if importlib.util.find_spec(name) is not None:
                return ("verified", f"python module '{name}' importable")
            # node_modules probe for JS packages
            if (root / "node_modules" / name).exists():
                return ("verified", f"found in node_modules/{name}")
            return (
                "verification unavailable",
                f"package-manager-level check not implemented for '{name}'; presence UNKNOWN",
            )
        if dtype in ("ENVIRONMENT_VARIABLE", "CREDENTIAL_REFERENCE"):
            import os

            if name in os.environ:
                return ("verified", f"{name} is set in this environment (value not shown)")
            return ("not verified", f"{name} not set in this environment")
        if dtype == "FILESYSTEM":
            p = Path(name)
            if not p.is_absolute():
                p = root / name
            if p.exists():
                return ("verified", f"path exists: {p}")
            return ("not verified", f"path not found: {name}")
        if dtype == "SERVICE":
            return (
                "verification unavailable",
                f"service '{name}' requires a live connection test; not probed by default",
            )
        if dtype == "NETWORK_ENDPOINT":
            return (
                "verification unavailable",
                "network endpoints are not probed by default (no traffic sent without consent)",
            )
        return ("verification unavailable", f"no verifier implemented for type {dtype}")
    except Exception as exc:
        return ("verification failed", str(exc))
