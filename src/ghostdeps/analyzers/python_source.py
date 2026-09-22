"""AST-based Python source analyzer (imports, subprocess, env, fs, network, services)."""

from __future__ import annotations

import ast
import sys
import warnings
from pathlib import Path

from ghostdeps.analyzers.base import evidence_file, own_package_names, safe_read
from ghostdeps.models import Dependency, Evidence
from ghostdeps.util import normalize_executable, redact_url_credentials

# Standard-library modules are never third-party PACKAGE dependencies.
# (sys.stdlib_module_names exists on Python 3.10+.)
STDLIB_MODULES = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}

# Known stdlib/service client module -> service inference (explicitly "inferred").
CLIENT_MODULE_SERVICE = {
    "psycopg2": "PostgreSQL",
    "psycopg": "PostgreSQL",
    "asyncpg": "PostgreSQL",
    "pymysql": "MySQL",
    "MySQLdb": "MySQL",
    "pymongo": "MongoDB",
    "motor": "MongoDB",
    "redis": "Redis",
    "kafka": "Kafka",
    "kafka-python": "Kafka",
    "confluent_kafka": "Kafka",
    "pika": "RabbitMQ",
    "elasticsearch": "Elasticsearch",
    "elastic_transport": "Elasticsearch",
    "boto3": "S3-compatible storage",
    "botocore": "S3-compatible storage",
    "smtplib": "SMTP",
}

SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
OS_EXEC_FUNCS = {"system", "popen", "execv", "execve", "execl", "spawnl", "spawnlp", "startfile"}


def handles(path: Path) -> bool:
    return path.suffix == ".py"


def analyze(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    text = safe_read(path)
    if not text:
        return []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text, filename=rel)
    except SyntaxError:
        return []
    visitor = _Visitor(rel, own_package_names(str(root)))
    visitor.visit(tree)
    return visitor.deps


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str, own_names: frozenset = frozenset()) -> None:
        self.rel = rel
        self.own_names = {n.lower() for n in own_names}
        self.deps: list[Dependency] = []

    # -- helpers ---------------------------------------------------------
    def _emit(
        self,
        name: str,
        dtype: str,
        node: ast.AST,
        detector: str,
        kind: str,
        message: str,
        confidence: str,
        snippet: str | None = None,
    ) -> Dependency:
        dep = Dependency(
            name=name,
            type=dtype,
            states={"DISCOVERED"},
            referenced="YES",
            required="UNKNOWN",
            confidence=confidence,
        )
        dep.add_evidence(
            Evidence(
                detector=detector,
                kind=kind,
                message=message,
                file=self.rel,
                line=getattr(node, "lineno", None),
                snippet=snippet,
                confidence=confidence,
            )
        )
        self.deps.append(dep)
        return dep

    @staticmethod
    def _const_str(node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    # -- imports ----------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top not in STDLIB_MODULES and top.lower() not in self.own_names:
                self._emit(
                    top,
                    "PACKAGE",
                    node,
                    "python-ast",
                    "import",
                    f"import {alias.name}",
                    "SUPPORTED",
                    snippet=f"import {alias.name}",
                )
            if top in CLIENT_MODULE_SERVICE:
                self._emit(
                    CLIENT_MODULE_SERVICE[top],
                    "SERVICE",
                    node,
                    "python-ast",
                    "service-client-import",
                    f"client library '{top}' suggests {CLIENT_MODULE_SERVICE[top]} "
                    f"(service requirement INFERRED, not proven)",
                    "INFERRED",
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split(".")[0]
            if top not in STDLIB_MODULES and top.lower() not in self.own_names:
                self._emit(
                    top,
                    "PACKAGE",
                    node,
                    "python-ast",
                    "import",
                    f"from {node.module} import ...",
                    "SUPPORTED",
                )
            if top in CLIENT_MODULE_SERVICE:
                self._emit(
                    CLIENT_MODULE_SERVICE[top],
                    "SERVICE",
                    node,
                    "python-ast",
                    "service-client-import",
                    f"client library '{top}' suggests {CLIENT_MODULE_SERVICE[top]} "
                    f"(service requirement INFERRED, not proven)",
                    "INFERRED",
                )
        self.generic_visit(node)

    # -- calls ------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        dotted = ""
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                dotted = f"{func.value.id}.{func.attr}"
            else:
                dotted = func.attr
        elif isinstance(func, ast.Name):
            dotted = func.id

        # subprocess.run(["ffmpeg", ...]) / Popen / call / check_*
        if dotted in {f"subprocess.{f}" for f in SUBPROCESS_FUNCS} or dotted in SUBPROCESS_FUNCS:
            exe = self._first_exec_arg(node)
            if exe:
                resolved = normalize_executable(exe)
                if resolved is None:
                    # Repo-relative script path: not an external system binary.
                    pass
                else:
                    self._emit(
                        resolved,
                        "SYSTEM_BINARY",
                        node,
                        "python-ast",
                        "static-subprocess",
                        f"subprocess invocation of '{resolved}'",
                        "STRONG",
                        snippet=f"{dotted}({resolved} ...)",
                    )
            else:
                self._emit(
                    "dynamic-subprocess",
                    "BEHAVIOR",
                    node,
                    "python-ast",
                    "static-subprocess-dynamic",
                    "subprocess invocation with non-literal command (executable UNKNOWN)",
                    "INFERRED",
                )
        # os.system("ffmpeg ...") / os.popen
        if dotted in {f"os.{f}" for f in OS_EXEC_FUNCS} or dotted in OS_EXEC_FUNCS:
            arg = self._const_str(node.args[0]) if node.args else None
            if arg and arg.strip():
                first = arg.strip().split()[0].strip("\"'")
                resolved = normalize_executable(first)
                if resolved is not None:
                    self._emit(
                        resolved,
                        "SYSTEM_BINARY",
                        node,
                        "python-ast",
                        "static-shell",
                        f"shell execution references '{resolved}'",
                        "SUPPORTED",
                        snippet=redact_url_credentials(arg[:200]),
                    )
        # os.getenv("X") / os.environ["X"] / os.environ.get("X")
        if dotted in {"os.getenv", "os.environ.get", "getenv"}:
            key = self._const_str(node.args[0]) if node.args else None
            if key:
                self._emit_env(key, node, f'{dotted}("{key}")')
        if dotted in {"socket.gethostbyname", "socket.create_connection"}:
            pass
        # env::var / System.getenv handled by generic analyzer for other langs.
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # os.environ["DATABASE_URL"]
        val = node.value
        dotted = ""
        if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
            dotted = f"{val.value.id}.{val.attr}"
        if dotted == "os.environ":
            key = self._const_str(node.slice)
            if key:
                self._emit_env(key, node, f'os.environ["{key}"]')
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            s = node.value
            for url in _find_urls(s):
                if is_namespace_url(url) or not is_plausible_url(url):
                    continue  # namespace identifier or regex fragment, not an endpoint
                self._emit(
                    redact_url_credentials(url),
                    "NETWORK_ENDPOINT",
                    node,
                    "python-ast",
                    "static-url",
                    f"URL literal references '{redact_url_credentials(url)}'",
                    "SUPPORTED",
                    snippet=redact_url_credentials(s[:200]),
                )
            for svc, _marker in (
                ("PostgreSQL", "postgres"),
                ("MySQL", "mysql"),
                ("MongoDB", "mongodb"),
                ("Redis", "redis"),
                ("Kafka", "kafka"),
                ("RabbitMQ", "amqp"),
                ("Elasticsearch", "elasticsearch"),
                ("SMTP", "smtp"),
            ):
                low = s.lower()
                if low.startswith(
                    (
                        "postgres://",
                        "postgresql://",
                        "mysql://",
                        "mongodb://",
                        "redis://",
                        "rediss://",
                        "amqp://",
                        "kafka://",
                        "smtp://",
                    )
                ):
                    self._emit(
                        svc,
                        "SERVICE",
                        node,
                        "python-ast",
                        "connection-string",
                        f"connection string suggests {svc} (INFERRED, not proven)",
                        "INFERRED",
                        snippet=redact_url_credentials(s[:120]),
                    )
                    break
            # filesystem access hints
            if (
                s.startswith(("/etc/", "/var/", "/usr/", "/tmp/", "/data", "/mnt/"))
                and len(s) < 300
            ):
                self._emit(
                    s,
                    "FILESYSTEM",
                    node,
                    "python-ast",
                    "static-path",
                    f"absolute filesystem path '{s}'",
                    "INFERRED",
                    snippet=s[:200],
                )
        self.generic_visit(node)

    # -- helpers ---------------------------------------------------------
    def _emit_env(self, key: str, node: ast.AST, expr: str) -> None:
        dtype = "CREDENTIAL_REFERENCE" if _looks_secret(key) else "ENVIRONMENT_VARIABLE"
        conf = "SUPPORTED"
        self._emit(
            key,
            dtype,
            node,
            "python-ast",
            "static-env",
            f"environment access {expr}",
            conf,
            snippet=expr,
        )

    def _first_exec_arg(self, node: ast.Call) -> str | None:
        if not node.args:
            return None
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.strip().split()[0] if first.value.strip() else None
        if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            s = self._const_str(first.elts[0])
            if s:
                return s.strip().split()[0] if s.strip() else None
        return None


def _looks_secret(name: str) -> bool:
    n = name.upper()
    return any(
        k in n
        for k in ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "PRIVATE_KEY", "AWS_SECRET", "JWT")
    )


# URL-shaped identifiers that are XML namespaces, not network dependencies.
NAMESPACE_MARKERS = ("maven.apache.org/pom", "www.w3.org/", "schemas.xmlsoap.org/")


def is_namespace_url(url: str) -> bool:
    low = url.lower()
    return any(m in low for m in NAMESPACE_MARKERS)


def is_plausible_url(url: str) -> bool:
    """Reject regex/template fragments (contain \\, [, ], |, ^) that the URL
    pattern can match inside pattern literals and docs."""
    return not any(ch in url for ch in ("\\", "[", "]", "|", "^", "{", "}"))


def _find_urls(s: str) -> list[str]:
    import re

    found = []
    spans: list[tuple[int, int]] = []
    for m in re.finditer(
        r"https?://[^\s\"'<>]+|wss?://[^\s\"'<>]+|redis://[^\s\"'<>]+|"
        r"postgres(?:ql)?://[^\s\"'<>]+|mongodb://[^\s\"'<>]+",
        s,
    ):
        u = m.group(0).rstrip(".,;)")
        if len(u) < 300:
            found.append(u)
            spans.append((m.start(), m.start() + len(u)))
    # localhost refs without scheme, but not inside an already-matched URL
    for m in re.finditer(r"localhost:\d{2,5}|127\.0\.0\.1:\d{2,5}", s):
        if any(a <= m.start() < b for a, b in spans):
            continue
        found.append("http://" + m.group(0))
    return found
