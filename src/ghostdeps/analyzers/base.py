"""Analyzer interfaces. New languages/platforms plug in here."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Protocol

from ghostdeps.models import Dependency


class Analyzer(Protocol):
    name: str

    def handles(self, path: Path) -> bool: ...
    def analyze(self, path: Path, root: Path) -> list[Dependency]: ...


def evidence_file(path: Path, root: Path) -> str:
    """Repository-relative evidence path with forward slashes (stable across OSes)."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix() if not path.is_absolute() else str(path).replace("\\", "/")


def safe_read(path: Path, limit_bytes: int = 1_000_000) -> str:
    try:
        if path.stat().st_size > limit_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@lru_cache(maxsize=64)
def own_package_names(root: str) -> frozenset:
    """Top-level packages owned by the scanned repo itself (never third-party).

    Derived from the src/ layout and pyproject distribution name, so
    `import ghostdeps.x` inside the ghostdeps repo is not reported as a
    PACKAGE dependency.
    """
    names: set[str] = set()
    base = Path(root)
    src = base / "src"
    if src.is_dir():
        for child in src.iterdir():
            if child.is_dir() and (child / "__init__.py").is_file():
                names.add(child.name)
            elif child.suffix == ".py":
                names.add(child.stem)
    for child in base.iterdir():
        if child.is_dir() and (child / "__init__.py").is_file() and child.name != "tests":
            names.add(child.name)
    try:
        text = (base / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        import re

        m = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
        if m:
            names.add(m.group(1).lower().replace("-", "_"))
            names.add(m.group(1).lower().replace("-", "-"))
    except OSError:
        pass
    return frozenset(names)
