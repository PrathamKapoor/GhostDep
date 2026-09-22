"""Core evidence-graph data model.

Central distinction (never collapsed):

    DECLARED vs PRESENT vs REFERENCED vs OBSERVED vs REQUIRED

Every finding is a Dependency node with attached Evidence records.
Confidence uses deterministic categories, never ai-style floats:

    UNKNOWN < INFERRED < SUPPORTED < STRONG < VERIFIED
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Vocabulary (kept as plain str constants so JSON stays stable)
# ---------------------------------------------------------------------------

DEP_TYPES = (
    "PACKAGE",
    "SYSTEM_BINARY",
    "SYSTEM_PACKAGE",
    "RUNTIME",
    "SERVICE",
    "ENVIRONMENT_VARIABLE",
    "NETWORK_ENDPOINT",
    "FILESYSTEM",
    "OPERATING_SYSTEM",
    "PLATFORM",
    "TOOLCHAIN",
    "CONFIGURATION",
    "BEHAVIOR",
    "CREDENTIAL_REFERENCE",
)

STATES = (
    "DECLARED",
    "DISCOVERED",
    "PRESENT",
    "OBSERVED",
    "REQUIRED",
    "GHOST",
    "CONFLICT",
    "UNUSED",
    "OPTIONAL",
    "UNKNOWN",
    "VERIFIED",
)

CONFIDENCE_ORDER = ("UNKNOWN", "INFERRED", "SUPPORTED", "STRONG", "VERIFIED")

CONFIDENCE_RANK = {name: i for i, name in enumerate(CONFIDENCE_ORDER)}


def stronger(a: str, b: str) -> str:
    """Return the stronger of two confidence categories (deterministic)."""
    if a not in CONFIDENCE_RANK:
        a = "UNKNOWN"
    if b not in CONFIDENCE_RANK:
        b = "UNKNOWN"
    return a if CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] else b


def _tool_version() -> str:
    from ghostdeps import __version__

    return __version__


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """One observation supporting (or weakening) a dependency node."""

    detector: str
    kind: str  # e.g. "static-subprocess", "manifest", "docker", "runtime", ...
    message: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    confidence: str = "SUPPORTED"
    timestamp: float = field(default_factory=lambda: time.time())

    def __post_init__(self) -> None:
        if self.confidence not in CONFIDENCE_RANK:
            self.confidence = "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "kind": self.kind,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "snippet": (self.snippet[:300] if self.snippet else None),
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Evidence:
        return cls(
            detector=d.get("detector", "unknown"),
            kind=d.get("kind", "unknown"),
            message=d.get("message", ""),
            file=d.get("file"),
            line=d.get("line"),
            snippet=d.get("snippet"),
            confidence=d.get("confidence", "UNKNOWN"),
            timestamp=d.get("timestamp", 0.0),
        )


# ---------------------------------------------------------------------------
# Dependency node
# ---------------------------------------------------------------------------


@dataclass
class Dependency:
    """A single dependency node in the evidence graph."""

    name: str
    type: str
    states: set[str] = field(default_factory=set)
    evidences: list[Evidence] = field(default_factory=list)
    confidence: str = "UNKNOWN"
    declared: str = "UNKNOWN"  # YES | NO | UNKNOWN
    present: str = "UNKNOWN"  # YES | NO | UNKNOWN
    referenced: str = "UNKNOWN"  # YES | NO | UNKNOWN
    observed: str = "UNKNOWN"  # YES | NO | UNKNOWN
    required: str = "UNKNOWN"  # YES | NO | UNKNOWN | OPTIONAL
    relationships: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.type not in DEP_TYPES:
            # Keep unknown types explicit instead of silently coercing.
            self.type = "CONFIGURATION" if not self.type else self.type
        for s in list(self.states):
            if s not in STATES:
                self.states.discard(s)
        if self.confidence not in CONFIDENCE_RANK:
            self.confidence = "UNKNOWN"

    def add_evidence(self, ev: Evidence) -> None:
        self.evidences.append(ev)
        self.confidence = stronger(self.confidence, ev.confidence)

    def key(self) -> tuple[str, str]:
        return (self.type, self.name.lower())

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "states": sorted(self.states),
            "confidence": self.confidence,
            "declared": self.declared,
            "present": self.present,
            "referenced": self.referenced,
            "observed": self.observed,
            "required": self.required,
            "relationships": self.relationships,
            "evidence": [e.to_dict() for e in self.evidences],
        }

    @classmethod
    def from_dict(cls, d: dict) -> Dependency:
        dep = cls(
            name=d.get("name", ""),
            type=d.get("type", "CONFIGURATION"),
            states=set(d.get("states", [])),
            confidence=d.get("confidence", "UNKNOWN"),
            declared=d.get("declared", "UNKNOWN"),
            present=d.get("present", "UNKNOWN"),
            referenced=d.get("referenced", "UNKNOWN"),
            observed=d.get("observed", "UNKNOWN"),
            required=d.get("required", "UNKNOWN"),
            relationships=d.get("relationships", []),
        )
        dep.evidences = [Evidence.from_dict(e) for e in d.get("evidence", [])]
        return dep


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    repo_root: str
    dependencies: list[Dependency] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    detectors_run: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    offline: bool = False
    tool_version: str = field(default_factory=_tool_version)
    schema_version: str = "1.0.0"
    generated_at: float = field(default_factory=lambda: time.time())

    def by_name(self, name: str) -> list[Dependency]:
        lowered = name.lower()
        return [d for d in self.dependencies if d.name.lower() == lowered]

    def ghosts(self) -> list[Dependency]:
        return [d for d in self.dependencies if "GHOST" in d.states]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "repo_root": self.repo_root,
            "generated_at": self.generated_at,
            "offline": self.offline,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "detectors_run": self.detectors_run,
            "warnings": self.warnings,
            "unsupported": self.unsupported,
            "dependencies": [d.to_dict() for d in self.dependencies],
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScanResult:
        from ghostdeps import __version__ as ver

        r = cls(
            repo_root=d.get("repo_root", "."),
            files_scanned=d.get("files_scanned", 0),
            files_skipped=d.get("files_skipped", 0),
            detectors_run=d.get("detectors_run", []),
            warnings=d.get("warnings", []),
            unsupported=d.get("unsupported", []),
            offline=d.get("offline", False),
            tool_version=d.get("tool_version", ver),
            schema_version=d.get("schema_version", "1.0.0"),
            generated_at=d.get("generated_at", 0.0),
        )
        r.dependencies = [Dependency.from_dict(x) for x in d.get("dependencies", [])]
        return r
