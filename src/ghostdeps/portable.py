"""Portability: what about THIS repo constrains a target platform?"""

from __future__ import annotations

from ghostdeps.models import ScanResult

WINDOWS_BLOCKERS = {
    "fork",
    "execv",
    "symlink",
    "/proc",
    "/etc/",
    "/usr/bin/",
    "inotify",
}
POSIX_PATH_HINTS = ("/etc/", "/usr/", "/var/", "/proc/", "/tmp/")


def assess(result: ScanResult, target: str) -> dict:
    target = target.lower()
    if target in ("win", "win32"):
        target = "windows"
    elif target in ("mac", "osx", "darwin"):
        target = "macos"
    findings: list[dict] = []
    for dep in result.dependencies:
        verdict, reason = _verdict(dep.name, dep.type, target)
        if verdict != "SUPPORTED":
            findings.append(
                {
                    "name": dep.name,
                    "type": dep.type,
                    "verdict": verdict,
                    "reason": reason,
                    "confidence": dep.confidence,
                }
            )
    supported = sum(
        1 for d in result.dependencies if _verdict(d.name, d.type, target)[0] == "SUPPORTED"
    )
    return {
        "target": target,
        "supported_count": supported,
        "finding_count": len(findings),
        "findings": findings,
        "note": (
            "Repository-specific portability analysis only; NOT a machine health check. "
            "UNKNOWN means GhostDeps lacks evidence, not that the target works."
        ),
    }


def _verdict(name: str, dtype: str, target: str) -> tuple[str, str]:
    low = name.lower()
    if dtype == "FILESYSTEM":
        if target == "windows" and name.startswith(tuple(POSIX_PATH_HINTS)):
            return ("BLOCKER", f"absolute POSIX path '{name}' does not exist on Windows")
        if target != "windows" and len(name) >= 3 and name[1:3] == ":\\":
            return ("BLOCKER", f"Windows path '{name}' is invalid on {target}")
        return ("SUPPORTED", "no platform-specific path issue detected")
    if dtype == "SYSTEM_BINARY":
        if target == "windows" and low in {"bash", "sh", "zsh", "make", "grep", "sed", "awk"}:
            return ("WARNING", f"'{name}' is not available on stock Windows (needs WSL/Git-Bash)")
        return ("UNKNOWN", f"binary '{name}' portability to {target} not proven; verify on target")
    if dtype == "RUNTIME":
        if "windows" in low and target != "windows":
            return ("WARNING", f"runtime hint '{name}' may be Windows-specific")
        return ("SUPPORTED", "runtime portability needs target-side check; no blocker found")
    if dtype == "BEHAVIOR" and ("symlink" in low or "fork" in low or "inotify" in low):
        if target == "windows":
            return ("BLOCKER", f"behavior '{name}' relies on POSIX semantics missing on Windows")
        return ("WARNING", f"behavior '{name}' may differ on {target}")
    if dtype in ("SERVICE", "NETWORK_ENDPOINT"):
        return ("UNKNOWN", "service/endpoint reachability from target not probed")
    return ("SUPPORTED", "no known constraint for this target")
