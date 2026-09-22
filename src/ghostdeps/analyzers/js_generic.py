"""Heuristic source analyzer for JS/TS and other languages.

Honesty note: the stdlib has no JS/TS parser, so JS/TS findings are
regex-based heuristics reported at INFERRED/SUPPORTED confidence — never
STRONG — unless corroborated by another detector (see fusion rules).
Python uses the real AST analyzer instead.
"""

from __future__ import annotations

import re
from pathlib import Path

from ghostdeps.analyzers.base import evidence_file, safe_read
from ghostdeps.analyzers.python_source import (
    _looks_secret,
    is_namespace_url,
    is_plausible_url,
)
from ghostdeps.models import Dependency, Evidence

JS_EXEC_RE = re.compile(
    r"""(?:child_process\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)|
        \bexec\s*\(|\bspawn\s*\(|\bexecSync\s*\(|\bexecFile\s*\()""",
    re.X,
)
JS_EXEC_ARG = re.compile(r"""(?:exec|spawn|execFile|fork)\s*\(\s*['"`]([^'"`]+)['"`]""")
JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:.*?\s+from\s+)?['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s*\(\s*['"]([^'"]+)['"]\s*\))"""
)
JS_ENV_RE = re.compile(
    r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[['"]([^'"]+)['"]\]"""
)
GENERIC_SUBPROCESS = re.compile(
    r"""(?:exec\s*\.\s*Command|Runtime\s*\.\s*exec|ProcessBuilder|Command\s*::\s*new|
        os\s*\.\s*system|os\s*\.\s*popen|system\s*\(|popen\s*\(|ShellExecute)""",
    re.X,
)
GENERIC_ENV = re.compile(
    r"""(?:System\s*\.\s*getenv|std\s*::\s*env\s*::\s*var|Environment\s*::\s*GetEnvironmentVariable|
        getenv\s*\(|Getenv\s*\()\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""",
    re.X,
)
GENERIC_ENV2 = re.compile(r"""\benv\s*::\s*var\s*\(\s*["']([^"']+)["']""")
FS_HINT = re.compile(
    r"""(?:fs\s*\.\s*(readFile|writeFile|open|createReadStream)|open\s*\(|File\s*\.\s*open|os\s*\.\s*Open)"""
)
URL_RE = re.compile(
    r"""https?://[^\s"'`<>]+|wss?://[^\s"'`<>]+|(?:redis|postgres(?:ql)?|mongodb|amqp|kafka|smtp)://[^\s"'`<>]+""",
    re.I,
)

SERVICE_PORT = {
    5432: "PostgreSQL",
    5433: "PostgreSQL",
    3306: "MySQL",
    27017: "MongoDB",
    6379: "Redis",
    6380: "Redis",
    9092: "Kafka",
    5672: "RabbitMQ",
    9200: "Elasticsearch",
    25: "SMTP",
    587: "SMTP",
}

SHELL_FILES = {".sh", ".bash", ".zsh"}
MAKE_NAMES = {"Makefile", "makefile", "GNUmakefile"}


def handles_js(path: Path) -> bool:
    return path.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def handles_generic(path: Path) -> bool:
    return (
        path.suffix
        in (
            ".go",
            ".rs",
            ".java",
            ".cs",
            ".rb",
            ".php",
            ".sh",
            ".bash",
            ".kt",
            ".swift",
            ".c",
            ".cc",
            ".cpp",
            ".h",
            ".hpp",
            ".pl",
        )
        or path.name in MAKE_NAMES
    )


def analyze_js(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    text = safe_read(path)
    if not text:
        return []
    deps: list[Dependency] = []

    def emit(name, dtype, line, kind, msg, conf, snippet=None):
        d = Dependency(
            name=name,
            type=dtype,
            states={"DISCOVERED"},
            referenced="YES",
            required="UNKNOWN",
            confidence=conf,
        )
        d.add_evidence(
            Evidence(
                detector="js-heuristic",
                kind=kind,
                message=msg,
                file=rel,
                line=line,
                snippet=snippet,
                confidence=conf,
            )
        )
        deps.append(d)

    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for m in JS_IMPORT_RE.finditer(line):
            mod = m.group(1) or m.group(2) or m.group(3)
            if not mod or mod.startswith((".", "/")):
                continue
            if len(mod) > 200:
                continue
            emit(
                mod,
                "PACKAGE",
                i,
                "import",
                f"JS import/require of '{mod}' (heuristic)",
                "SUPPORTED",
                snippet=line.strip()[:200],
            )
        for m in JS_EXEC_ARG.finditer(line):
            cmd = m.group(1).strip().split()[0]
            if cmd and len(cmd) < 100 and not cmd.startswith((".", "/")) or "/" in cmd:
                emit(
                    cmd,
                    "SYSTEM_BINARY",
                    i,
                    "static-subprocess",
                    f"child_process invocation of '{cmd}' (heuristic)",
                    "SUPPORTED",
                    snippet=line.strip()[:200],
                )
        if JS_EXEC_RE.search(line) and not JS_EXEC_ARG.search(line):
            emit(
                "dynamic-subprocess",
                "BEHAVIOR",
                i,
                "static-subprocess-dynamic",
                "child_process call with non-literal command (executable UNKNOWN, heuristic)",
                "INFERRED",
                snippet=line.strip()[:200],
            )
        for m in JS_ENV_RE.finditer(line):
            key = m.group(1) or m.group(2)
            if key:
                emit(
                    key,
                    "CREDENTIAL_REFERENCE" if _looks_secret(key) else "ENVIRONMENT_VARIABLE",
                    i,
                    "static-env",
                    f"process.env access '{key}' (heuristic)",
                    "SUPPORTED",
                    snippet=line.strip()[:200],
                )
        for m in URL_RE.finditer(line):
            u = m.group(0).rstrip(".,;)")
            if len(u) < 300 and not is_namespace_url(u) and is_plausible_url(u):
                emit(
                    u,
                    "NETWORK_ENDPOINT",
                    i,
                    "static-url",
                    f"URL literal '{u}' (heuristic)",
                    "SUPPORTED",
                    snippet=line.strip()[:200],
                )
    return deps


def analyze_generic(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    text = safe_read(path)
    if not text:
        return []
    # package.json scripts are handled by manifest analyzer; shell/Makefiles here.
    deps: list[Dependency] = []

    def emit(name, dtype, line, kind, msg, conf, snippet=None):
        d = Dependency(
            name=name,
            type=dtype,
            states={"DISCOVERED"},
            referenced="YES",
            required="UNKNOWN",
            confidence=conf,
        )
        d.add_evidence(
            Evidence(
                detector="generic-heuristic",
                kind=kind,
                message=msg,
                file=rel,
                line=line,
                snippet=snippet,
                confidence=conf,
            )
        )
        deps.append(d)

    for i, line in enumerate(text.splitlines(), 1):
        if GENERIC_SUBPROCESS.search(line):
            m = re.search(r'"([^"]+)"', line)
            if m:
                first = m.group(1).strip().split()[0]
                if first and len(first) < 120:
                    emit(
                        first,
                        "SYSTEM_BINARY",
                        i,
                        "static-subprocess",
                        f"native execution references '{first}' (heuristic)",
                        "SUPPORTED",
                        snippet=line.strip()[:200],
                    )
            else:
                emit(
                    "dynamic-subprocess",
                    "BEHAVIOR",
                    i,
                    "static-subprocess-dynamic",
                    "native execution with non-literal command (UNKNOWN, heuristic)",
                    "INFERRED",
                    snippet=line.strip()[:200],
                )
        for m in GENERIC_ENV.finditer(line):
            emit(
                m.group(1),
                "CREDENTIAL_REFERENCE" if _looks_secret(m.group(1)) else "ENVIRONMENT_VARIABLE",
                i,
                "static-env",
                f"env access '{m.group(1)}' (heuristic)",
                "SUPPORTED",
                snippet=line.strip()[:200],
            )
        for m in GENERIC_ENV2.finditer(line):
            emit(
                m.group(1),
                "CREDENTIAL_REFERENCE" if _looks_secret(m.group(1)) else "ENVIRONMENT_VARIABLE",
                i,
                "static-env",
                f"env access '{m.group(1)}' (heuristic)",
                "SUPPORTED",
                snippet=line.strip()[:200],
            )
        for m in URL_RE.finditer(line):
            u = m.group(0).rstrip(".,;)")
            if len(u) < 300 and not is_namespace_url(u) and is_plausible_url(u):
                emit(
                    u,
                    "NETWORK_ENDPOINT",
                    i,
                    "static-url",
                    f"URL literal '{u}' (heuristic)",
                    "SUPPORTED",
                    snippet=line.strip()[:200],
                )
        _ = FS_HINT
    return deps
