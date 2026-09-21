"""Runtime tracing interface with per-platform backends (explicit, honest)."""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class TraceEvent:
    kind: str  # exec | exit | note
    message: str
    executable: str | None = None
    resolved_path: str | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class TraceResult:
    command: list[str]
    exit_code: int | None
    duration_s: float
    backend: str
    events: list[TraceEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3),
            "backend": self.backend,
            "events": [
                {
                    "kind": e.kind,
                    "message": e.message,
                    "executable": e.executable,
                    "resolved_path": e.resolved_path,
                    "timestamp": e.timestamp,
                }
                for e in self.events
            ],
            "warnings": self.warnings,
        }


class RuntimeTracer:
    name = "base"

    def available(self) -> tuple[bool, str]:
        return (True, "generic subprocess backend")

    def trace(
        self, command: list[str], cwd: str | None = None, timeout_s: int = 300
    ) -> TraceResult:
        raise NotImplementedError


class GenericTracer(RuntimeTracer):
    """Portable fallback: runs the command, resolves the binary, records exit.

    Does NOT claim syscall-level visibility. On Linux, if `strace` exists it
    is used opportunistically to observe execve; otherwise the trace records
    only the top-level execution (and says so explicitly).
    """

    name = "generic"

    def trace(self, command: list[str], cwd=None, timeout_s: int = 300) -> TraceResult:
        start = time.time()
        events: list[TraceEvent] = []
        warnings: list[str] = []
        resolved = shutil.which(command[0]) if command else None
        events.append(
            TraceEvent(
                kind="exec",
                message=f"executing: {' '.join(command)}",
                executable=command[0] if command else None,
                resolved_path=resolved,
            )
        )
        if resolved is None and command:
            warnings.append(
                f"executable '{command[0]}' not found on PATH; attempting direct execution anyway"
            )
        strace = shutil.which("strace")
        use_strace = strace is not None and platform.system() == "Linux"
        if use_strace:
            warnings.append("strace backend: execve events will be captured (Linux only)")
        else:
            warnings.append(
                "syscall tracing unavailable on this platform/backend; "
                "only top-level process execution is observed, "
                "nested child processes are NOT fully traced"
            )
        wrapped = (
            (
                [
                    "strace",
                    "-f",
                    "-e",
                    "trace=execve,connect,openat",
                    "-o",
                    "/tmp/ghostdeps-strace.log",
                ]
                + command
            )
            if use_strace
            else command
        )
        try:
            proc = subprocess.run(
                wrapped, cwd=cwd, timeout=timeout_s, capture_output=True, text=True
            )
            code: int | None = proc.returncode
            events.append(TraceEvent(kind="exit", message=f"exit status {proc.returncode}"))
            if use_strace:
                events.extend(_parse_strace_log())
        except FileNotFoundError:
            code = None
            warnings.append(
                f"execution failed: executable not found: {command[0] if command else '?'}"
            )
        except subprocess.TimeoutExpired:
            code = None
            warnings.append(f"execution timed out after {timeout_s}s")
        return TraceResult(
            command=command,
            exit_code=code,
            duration_s=time.time() - start,
            backend="strace" if use_strace else "generic",
            events=events,
            warnings=warnings,
        )


class LinuxTracer(GenericTracer):
    name = "linux"


class WindowsTracer(GenericTracer):
    name = "windows"

    def available(self):
        return (
            True,
            "Windows: generic backend (no syscall tracing; "
            "nested child processes are NOT fully traced)",
        )


class MacOSTracer(GenericTracer):
    name = "macos"

    def available(self):
        return (
            True,
            "macOS: generic backend (no syscall tracing; "
            "nested child processes are NOT fully traced)",
        )


def get_tracer() -> RuntimeTracer:
    system = platform.system()
    if system == "Linux":
        return LinuxTracer()
    if system == "Windows":
        return WindowsTracer()
    if system == "Darwin":
        return MacOSTracer()
    return GenericTracer()


def _parse_strace_log() -> list[TraceEvent]:
    import re

    events: list[TraceEvent] = []
    try:
        with open("/tmp/ghostdeps-strace.log", encoding="utf-8", errors="replace") as fh:
            for line in fh.readlines()[-500:]:
                m = re.search(r'execve\("([^"]+)"', line)
                if m:
                    exe = m.group(1)
                    events.append(
                        TraceEvent(
                            kind="exec",
                            message=f"execve: {exe}",
                            executable=exe.split("/")[-1],
                            resolved_path=exe,
                        )
                    )
                m2 = re.search(
                    r"connect\(\d+,\s*\{sa_family=AF_INET.*?sin_port=htons\((\d+)\)", line
                )
                if m2:
                    events.append(
                        TraceEvent(
                            kind="note", message=f"outbound connection to port {m2.group(1)}"
                        )
                    )
    except OSError:
        pass
    return events
