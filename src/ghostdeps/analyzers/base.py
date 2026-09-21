"""Analyzer interfaces. New languages/platforms plug in here."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ghostdeps.models import Dependency


class Analyzer(Protocol):
    name: str

    def handles(self, path: Path) -> bool: ...
    def analyze(self, path: Path, root: Path) -> list[Dependency]: ...


def evidence_file(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def safe_read(path: Path, limit_bytes: int = 1_000_000) -> str:
    try:
        if path.stat().st_size > limit_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
