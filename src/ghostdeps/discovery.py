"""Repository discovery: recursive file inventory with safe defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "bower_components",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",  # rust build output (still scan Cargo.toml at root)
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".idea",
    ".vscode",
    ".ghostdeps",  # ghostdeps' own baseline/trace output (would self-scan)
    ".pytest-tmp",
}

# NOTE: `target`/`dist`/`build` are ignored as *directories*; manifest files
# at the repo root with the same names are still handled by detectors.


@dataclass
class DiscoveredRepo:
    root: Path
    files: list[Path] = field(default_factory=list)
    skipped_dirs: list[str] = field(default_factory=list)
    total_files_seen: int = 0


def discover(root: Path, extra_ignores: list[str] | None = None) -> DiscoveredRepo:
    """Recursively list files under root, skipping generated/vendor dirs."""
    root = root.resolve()
    ignores = set(DEFAULT_IGNORE_DIRS)
    for extra in extra_ignores or []:
        ignores.add(extra.strip().strip("/"))
    found: list[Path] = []
    skipped: list[str] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune ignored directories in-place so os.walk does not descend.
        pruned = [d for d in dirnames if d in ignores]
        if pruned:
            skipped.extend(pruned)
        dirnames[:] = [d for d in dirnames if d not in ignores]
        for fn in filenames:
            seen += 1
            found.append(Path(dirpath) / fn)
    found.sort()
    return DiscoveredRepo(
        root=root, files=found, skipped_dirs=sorted(set(skipped)), total_files_seen=seen
    )


def relative_to_root(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
