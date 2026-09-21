"""Baseline create / diff for CI and pull requests."""

from __future__ import annotations

import json
from pathlib import Path

from ghostdeps.models import ScanResult

BASELINE_DIR = ".ghostdeps"
BASELINE_FILE = "baseline.json"


def baseline_path(root: Path) -> Path:
    return root / BASELINE_DIR / BASELINE_FILE


def create_baseline(result: ScanResult, root: Path) -> Path:
    dest = baseline_path(root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return dest


def load_baseline(root: Path) -> ScanResult | None:
    dest = baseline_path(root)
    if not dest.is_file():
        return None
    try:
        return ScanResult.from_dict(json.loads(dest.read_text(encoding="utf-8")))
    except Exception:
        return None


def diff_results(old: ScanResult, new: ScanResult) -> dict:
    def sig(d) -> tuple[str, str]:
        return (d.type, d.name.lower())

    old_map = {sig(d): d for d in old.dependencies}
    new_map = {sig(d): d for d in new.dependencies}
    added = [new_map[k].to_dict() for k in new_map if k not in old_map]
    removed = [old_map[k].to_dict() for k in old_map if k not in new_map]
    changed = []
    for k in new_map:
        if k in old_map:
            a, b = old_map[k], new_map[k]
            if (
                sorted(a.states) != sorted(b.states)
                or a.confidence != b.confidence
                or a.required != b.required
                or len(a.evidences) != len(b.evidences)
            ):
                changed.append(
                    {
                        "name": b.name,
                        "type": b.type,
                        "before": {
                            "states": sorted(a.states),
                            "confidence": a.confidence,
                            "required": a.required,
                            "evidence": len(a.evidences),
                        },
                        "after": {
                            "states": sorted(b.states),
                            "confidence": b.confidence,
                            "required": b.required,
                            "evidence": len(b.evidences),
                        },
                    }
                )
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
    }
