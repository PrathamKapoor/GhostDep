"""Optional configuration file. Never required for a first scan."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILENAMES = ("ghostdeps.toml", ".ghostdeps.toml", "ghostdeps.json", ".ghostdeps.json")


@dataclass
class Config:
    ignore_paths: list[str] = field(default_factory=list)
    ignore_deps: list[str] = field(default_factory=list)
    ignore_reasons: dict[str, str] = field(default_factory=dict)
    severity: str = "medium"
    target_platforms: list[str] = field(default_factory=list)
    fail_on: list[str] = field(default_factory=list)  # e.g. ["GHOST", "CONFLICT"]
    offline: bool = False
    output_format: str = "terminal"

    @classmethod
    def load(cls, root: Path) -> tuple[Config, Path | None]:
        for name in CONFIG_FILENAMES:
            candidate = root / name
            if candidate.is_file():
                try:
                    if candidate.suffix == ".json":
                        data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
                    else:
                        data = _parse_simple_toml(
                            candidate.read_text(encoding="utf-8", errors="replace")
                        )
                    return (cls.from_dict(data), candidate)
                except Exception:
                    return (cls(), None)
        return (cls(), None)

    @classmethod
    def from_dict(cls, data: dict) -> Config:
        ghost = data.get("ghostdeps", data) if isinstance(data, dict) else {}
        if not isinstance(ghost, dict):
            ghost = {}
        ignores = ghost.get("ignore_deps", [])
        if isinstance(ignores, dict):
            # {name: reason} form
            reasons = {str(k): str(v) for k, v in ignores.items()}
            ignore_list = list(reasons)
        else:
            reasons = {}
            ignore_list = [str(x) for x in (ignores or [])]
        return cls(
            ignore_paths=[str(x) for x in ghost.get("ignore_paths", []) or []],
            ignore_deps=ignore_list,
            ignore_reasons=reasons,
            severity=str(ghost.get("severity", "medium")),
            target_platforms=[str(x) for x in ghost.get("target_platforms", []) or []],
            fail_on=[str(x).upper() for x in ghost.get("fail_on", []) or []],
            offline=bool(ghost.get("offline", False)),
            output_format=str(ghost.get("output", ghost.get("output_format", "terminal"))),
        )


def _parse_simple_toml(text: str) -> dict:
    """Minimal TOML-subset parser for the [ghostdeps] table (stdlib only).

    Supports string, bool, and simple string-list values. Anything more
    complex should use ghostdeps.json instead.
    """
    current: str | None = None
    out: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            out.setdefault(current, {})
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        parsed: object = value
        if value.startswith("["):
            items = []
            inner = value.strip()[1:]
            if inner.endswith("]"):
                inner = inner[:-1]
            for part in inner.split(","):
                part = part.strip().strip('"').strip("'")
                if part:
                    items.append(part)
            parsed = items
        elif (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            parsed = value[1:-1]
        elif value.lower() in ("true", "false"):
            parsed = value.lower() == "true"
        table = out.setdefault(current or "ghostdeps", {})
        table[key] = parsed
    return out
