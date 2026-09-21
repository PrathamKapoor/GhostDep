"""Environment, service, network, Docker, and CI analyzers (stdlib only)."""

from __future__ import annotations

import re
from pathlib import Path

from ghostdeps.analyzers.base import evidence_file, safe_read
from ghostdeps.analyzers.python_source import _looks_secret
from ghostdeps.analyzers.python_source import is_namespace_url as _is_ns
from ghostdeps.models import Dependency, Evidence


def _emit(detector, kind, name, dtype, rel, line, msg, conf, snippet=None):
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
            detector=detector,
            kind=kind,
            message=msg,
            file=rel,
            line=line,
            snippet=snippet,
            confidence=conf,
        )
    )
    return d


# ---------------------------------------------------------------- env files
def analyze_dotenv(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    if path.name not in (
        ".env",
        ".env.example",
        ".env.template",
        ".env.sample",
    ) and not path.name.startswith(".env."):
        return []
    deps: list[Dependency] = []
    for i, line in enumerate(safe_read(path).splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key = s.split("=", 1)[0].strip().strip("export ").strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            dtype = "CREDENTIAL_REFERENCE" if _looks_secret(key) else "ENVIRONMENT_VARIABLE"
            d = _emit(
                "dotenv",
                "env-declaration",
                key,
                dtype,
                rel,
                i,
                f"declared in {path.name}: {key} (value never recorded)",
                "SUPPORTED",
            )
            d.states.add("DECLARED")
            d.declared = "YES"
            deps.append(d)
    return deps


# ---------------------------------------------------------------- services
SERVICE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "PostgreSQL",
        re.compile(r"postgres(?:ql)?://|psycopg|asyncpg|pg8000|port\s*5432", re.I),
        "connection-string-or-port",
    ),
    (
        "MySQL",
        re.compile(r"mysql://|pymysql|MySQLdb|port\s*3306", re.I),
        "connection-string-or-port",
    ),
    (
        "MongoDB",
        re.compile(r"mongodb://|pymongo|motor|port\s*27017", re.I),
        "connection-string-or-port",
    ),
    (
        "Redis",
        re.compile(r"redis://|rediss://|import\s+redis|require\(['\"]redis['\"]|port\s*6379", re.I),
        "connection-string-or-port",
    ),
    (
        "Kafka",
        re.compile(r"kafka://|confluent.?kafka|kafka-python|port\s*9092", re.I),
        "connection-string-or-port",
    ),
    ("RabbitMQ", re.compile(r"amqp://|pika|port\s*5672", re.I), "connection-string-or-port"),
    ("Elasticsearch", re.compile(r"elasticsearch|port\s*9200", re.I), "connection-string-or-port"),
    (
        "S3-compatible storage",
        re.compile(r"s3://|boto3|botocore|moto\b", re.I),
        "connection-string-or-lib",
    ),
    (
        "SMTP",
        re.compile(r"smtp://|smtplib|nodemailer|port\s*(25|587|465)", re.I),
        "connection-string-or-port",
    ),
]

COMPOSE_SERVICE_IMAGE = {
    "postgres": "PostgreSQL",
    "postgis": "PostgreSQL",
    "mysql": "MySQL",
    "mongo": "MongoDB",
    "redis": "Redis",
    "kafka": "Kafka",
    "rabbitmq": "RabbitMQ",
    "elasticsearch": "Elasticsearch",
    "localstack": "S3-compatible storage",
    "minio": "S3-compatible storage",
    "mailhog": "SMTP",
    "mailpit": "SMTP",
}


def infer_service_from_text(text: str, rel: str, detector: str) -> list[Dependency]:
    out: list[Dependency] = []
    for svc, rx, _kind in SERVICE_PATTERNS:
        m = rx.search(text)
        if m:
            d = _emit(
                detector,
                "service-inference",
                svc,
                "SERVICE",
                rel,
                None,
                f"'{svc}' inferred from configuration/text match "
                f"(service requirement INFERRED, not proven)",
                "INFERRED",
                snippet=m.group(0)[:120],
            )
            out.append(d)
    return out


# ---------------------------------------------------------------- network
def analyze_network_text(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    if path.suffix not in (
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".rb",
        ".php",
        ".cs",
        ".yaml",
        ".yml",
        ".toml",
        ".json",
        ".env",
        ".example",
        ".md",
        ".txt",
    ):
        return []
    if path.suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        return []  # covered by dedicated source analyzers
    text = safe_read(path)
    if not text:
        return []
    out: list[Dependency] = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in re.finditer(
            r"https?://[^\s\"'<>]+|wss?://[^\s\"'<>]+|"
            r"(?:redis|postgres(?:ql)?|mongodb|amqp|kafka|smtp)://[^\s\"'<>]+",
            line,
            re.I,
        ):
            u = m.group(0).rstrip(".,;)")
            if 4 < len(u) < 300 and not _is_ns(u):
                out.append(
                    _emit(
                        "network-scan",
                        "static-url",
                        u,
                        "NETWORK_ENDPOINT",
                        rel,
                        i,
                        f"network reference '{u}'",
                        "SUPPORTED",
                        snippet=line.strip()[:200],
                    )
                )
        for m in re.finditer(
            r"(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal)(:\d{2,5})?", line
        ):
            host = m.group(0)
            out.append(
                _emit(
                    "network-scan",
                    "static-local-endpoint",
                    f"http://{host}",
                    "NETWORK_ENDPOINT",
                    rel,
                    i,
                    f"local endpoint '{host}'",
                    "INFERRED",
                    snippet=line.strip()[:200],
                )
            )
    return out


# ---------------------------------------------------------------- docker
APT_INSTALL = re.compile(r"apt(?:-get)?\s+install[^&|;]*", re.I)
APK_ADD = re.compile(r"apk\s+add[^&|;]*", re.I)
YUM_INSTALL = re.compile(r"(?:yum|dnf|microdnf)\s+install[^&|;]*", re.I)


def analyze_dockerfile(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    if path.name != "Dockerfile" and not path.name.startswith("Dockerfile."):
        return []
    deps: list[Dependency] = []
    for i, raw in enumerate(safe_read(path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^FROM\s+(\S+)", line, re.I)
        if m:
            image = m.group(1)
            deps.append(
                _emit(
                    "docker",
                    "docker-from",
                    image,
                    "PLATFORM",
                    rel,
                    i,
                    f"base image '{image}' (evidence, not runtime proof)",
                    "SUPPORTED",
                )
            )
            base = image.split(":")[0].lower()
            if any(
                k in base
                for k in ("python", "node", "go", "rust", "ruby", "php", "openjdk", "dotnet")
            ):
                deps.append(
                    _emit(
                        "docker",
                        "docker-runtime",
                        base,
                        "RUNTIME",
                        rel,
                        i,
                        f"base image suggests runtime '{base}' (INFERRED)",
                        "INFERRED",
                    )
                )
        m = re.match(
            r"^(RUN|ENV|ARG|EXPOSE|ENTRYPOINT|CMD|COPY|VOLUME|WORKDIR|USER)\b(.*)", line, re.I
        )
        if m:
            directive, rest = m.group(1).upper(), m.group(2).strip()
            if directive in ("ENV", "ARG"):
                kv = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*[= ]", rest)
                if kv:
                    key = kv.group(1)
                    dtype = "CREDENTIAL_REFERENCE" if _looks_secret(key) else "ENVIRONMENT_VARIABLE"
                    deps.append(
                        _emit(
                            "docker",
                            "docker-env",
                            key,
                            dtype,
                            rel,
                            i,
                            f"Docker {directive} declares '{key}' (value never recorded)",
                            "SUPPORTED",
                        )
                    )
            if directive == "EXPOSE":
                for port in re.findall(r"\d{2,5}", rest):
                    deps.append(
                        _emit(
                            "docker",
                            "docker-expose",
                            f"port:{port}",
                            "NETWORK_ENDPOINT",
                            rel,
                            i,
                            f"Docker EXPOSE {port}",
                            "INFERRED",
                        )
                    )
            for pkg in _system_packages_from_run(rest):
                deps.append(
                    _emit(
                        "docker",
                        "docker-system-package",
                        pkg,
                        "SYSTEM_PACKAGE",
                        rel,
                        i,
                        f"Docker installs system package '{pkg}' (evidence, not runtime proof)",
                        "SUPPORTED",
                        snippet=raw.strip()[:200],
                    )
                )
            for exe in _exes_from_run(rest):
                deps.append(
                    _emit(
                        "docker",
                        "docker-exec",
                        exe,
                        "SYSTEM_BINARY",
                        rel,
                        i,
                        f"Docker RUN references executable '{exe}'",
                        "INFERRED",
                        snippet=raw.strip()[:200],
                    )
                )
    return deps


def _system_packages_from_run(rest: str) -> list[str]:
    found: list[str] = []
    for rx in (APT_INSTALL, APK_ADD, YUM_INSTALL):
        for m in rx.finditer(rest):
            chunk = m.group(0)
            for tok in re.split(r"\s+", chunk):
                tok = tok.strip().strip(",;")
                if (
                    not tok
                    or tok.startswith("-")
                    or "/" in tok
                    or tok
                    in {
                        "install",
                        "add",
                        "apt-get",
                        "apt",
                        "apk",
                        "yum",
                        "dnf",
                        "microdnf",
                        "update",
                        "upgrade",
                        "&&",
                        "||",
                        ";",
                    }
                ):
                    continue
                if re.match(r"^[a-z0-9][a-z0-9+._\-]*$", tok) and len(tok) < 60:
                    found.append(tok)
    # pip/npm installs inside Docker also count as declared packages
    for m in re.finditer(r"pip\s+install\s+([A-Za-z0-9_.\-\[\]]+)", rest):
        found.append("pip:" + m.group(1))
    return found[:20]


def _exes_from_run(rest: str) -> list[str]:
    exes: list[str] = []
    for chunk in re.split(r"&&|\|\||;", rest):
        chunk = chunk.strip()
        if not chunk:
            continue
        first = chunk.split()[0].strip()
        if re.match(r"^[a-z][a-z0-9_\-]*$", first) and first not in {
            "run",
            "echo",
            "cd",
            "export",
            "set",
            "if",
            "then",
            "fi",
            "apt-get",
            "apt",
            "apk",
            "yum",
            "pip",
            "npm",
            "yarn",
            "mkdir",
            "cp",
            "mv",
            "rm",
        }:
            exes.append(first)
    return exes[:10]


def analyze_compose(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    if path.name not in (
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.override.yml",
        "compose.yaml",
        "compose.yml",
    ):
        return []
    text = safe_read(path)
    if not text:
        return []
    deps: list[Dependency] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*image\s*:\s*(\S+)", line)
        if m:
            image = m.group(1).strip("\"'")
            deps.append(
                _emit(
                    "compose",
                    "compose-image",
                    image,
                    "PLATFORM",
                    rel,
                    i,
                    f"compose image '{image}' (evidence, not runtime proof)",
                    "SUPPORTED",
                )
            )
            low = image.lower()
            for key, svc in COMPOSE_SERVICE_IMAGE.items():
                if key in low:
                    deps.append(
                        _emit(
                            "compose",
                            "compose-service",
                            svc,
                            "SERVICE",
                            rel,
                            i,
                            f"compose image suggests {svc} "
                            "(service requirement INFERRED, not proven)",
                            "INFERRED",
                            snippet=line.strip()[:160],
                        )
                    )
                    break
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\S.*)?$", line)
        # env-ish lines inside compose: `KEY: value` under environment — heuristic, weak.
        if re.match(r"\s*-\s*[A-Za-z_][A-Za-z0-9_]*=", line):
            key = re.match(r"\s*-\s*([A-Za-z_][A-Za-z0-9_]*?)=", line).group(1)  # type: ignore[union-attr]
            dtype = "CREDENTIAL_REFERENCE" if _looks_secret(key) else "ENVIRONMENT_VARIABLE"
            deps.append(
                _emit(
                    "compose",
                    "compose-env",
                    key,
                    dtype,
                    rel,
                    i,
                    f"compose declares '{key}' (value never recorded)",
                    "SUPPORTED",
                )
            )
        m2 = re.match(r'\s*"(?:\d+\.)?\d+:\d+"|\s*-\s*"(\d+):(\d+)"', line)
        if m2:
            pass
        mp = re.search(r'"(\d{2,5}):(\d{2,5})"', line)
        if mp and "ports" in text[max(0, text.find(line) - 200) : text.find(line)]:
            deps.append(
                _emit(
                    "compose",
                    "compose-port",
                    f"port:{mp.group(2)}",
                    "NETWORK_ENDPOINT",
                    rel,
                    i,
                    f"compose maps port {mp.group(1)}->{mp.group(2)}",
                    "INFERRED",
                )
            )
    deps.extend(infer_service_from_text(text, rel, "compose"))
    # depends_on / healthcheck markers as behavior evidence
    if "depends_on" in text:
        deps.append(
            _emit(
                "compose",
                "compose-depends-on",
                "compose-depends_on",
                "CONFIGURATION",
                rel,
                None,
                "compose uses depends_on (service ordering evidence)",
                "INFERRED",
            )
        )
    return deps


# ---------------------------------------------------------------- CI (GitHub Actions first)
def analyze_github_workflow(path: Path, root: Path) -> list[Dependency]:
    rel = evidence_file(path, root)
    parts = path.parts
    if ".github" not in parts or "workflows" not in parts:
        return []
    text = safe_read(path)
    if not text:
        return []
    deps: list[Dependency] = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        m = re.match(r"uses\s*:\s*(\S+)", s, re.I) or re.match(r"-\s*uses\s*:\s*(\S+)", s, re.I)
        if m:
            action = m.group(1).strip("\"'")
            deps.append(
                _emit(
                    "ci",
                    "ci-action",
                    action,
                    "TOOLCHAIN",
                    rel,
                    i,
                    f"workflow uses action '{action}' (CI-only evidence)",
                    "SUPPORTED",
                )
            )
            low = action.lower()
            if "setup-python" in low:
                deps.append(
                    _emit(
                        "ci",
                        "ci-runtime",
                        "python (ci)",
                        "RUNTIME",
                        rel,
                        i,
                        "workflow sets up Python (CI-only runtime evidence)",
                        "SUPPORTED",
                    )
                )
            if "setup-node" in low:
                deps.append(
                    _emit(
                        "ci",
                        "ci-runtime",
                        "node (ci)",
                        "RUNTIME",
                        rel,
                        i,
                        "workflow sets up Node (CI-only runtime evidence)",
                        "SUPPORTED",
                    )
                )
            if "setup-go" in low:
                deps.append(
                    _emit(
                        "ci",
                        "ci-runtime",
                        "go (ci)",
                        "RUNTIME",
                        rel,
                        i,
                        "workflow sets up Go (CI-only runtime evidence)",
                        "SUPPORTED",
                    )
                )
            if "setup-java" in low:
                deps.append(
                    _emit(
                        "ci",
                        "ci-runtime",
                        "java (ci)",
                        "RUNTIME",
                        rel,
                        i,
                        "workflow sets up Java (CI-only runtime evidence)",
                        "SUPPORTED",
                    )
                )
        m = re.match(r"(?:-\s*)?run\s*:\s*(.+)", s, re.I)
        if m:
            cmd = m.group(1).strip()[:200]
            for tool in (
                "pytest",
                "npm",
                "yarn",
                "pnpm",
                "pip",
                "poetry",
                "cargo",
                "go",
                "gradle",
                "mvn",
                "docker",
                "apt-get",
                "brew",
                "choco",
            ):
                if re.search(rf"\b{re.escape(tool)}\b", cmd):
                    d = _emit(
                        "ci",
                        "ci-command",
                        f"{tool} (ci)",
                        "TOOLCHAIN",
                        rel,
                        i,
                        f"workflow runs '{tool}' "
                        "(CI-only; do not classify as production "
                        "without more evidence)",
                        "INFERRED",
                        snippet=cmd,
                    )
                    d.states.add("OPTIONAL")
                    deps.append(d)
                    break
            for pkg in _system_packages_from_run(cmd):
                if not pkg.startswith("pip:"):
                    d = _emit(
                        "ci",
                        "ci-system-package",
                        f"{pkg} (ci)",
                        "SYSTEM_PACKAGE",
                        rel,
                        i,
                        f"workflow installs system package '{pkg}' (CI-only evidence)",
                        "SUPPORTED",
                        snippet=cmd,
                    )
                    d.states.add("OPTIONAL")
                    deps.append(d)
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\S+", s)
        if re.match(r"\s*env\s*:\s*$", line):
            deps.append(
                _emit(
                    "ci",
                    "ci-env-block",
                    "ci-env",
                    "CONFIGURATION",
                    rel,
                    i,
                    "workflow defines an env: block (see following keys)",
                    "INFERRED",
                )
            )
    # services: block
    if re.search(r"^\s*services\s*:\s*$", text, re.M):
        for svc in ("postgres", "mysql", "mongo", "redis", "kafka", "rabbit", "elastic"):
            if re.search(rf"\b{svc}\b", text, re.I):
                label = {
                    "postgres": "PostgreSQL",
                    "mysql": "MySQL",
                    "mongo": "MongoDB",
                    "redis": "Redis",
                    "kafka": "Kafka",
                    "rabbit": "RabbitMQ",
                    "elastic": "Elasticsearch",
                }[svc]
                d = _emit(
                    "ci",
                    "ci-service",
                    f"{label} (ci)",
                    "SERVICE",
                    rel,
                    None,
                    f"workflow service '{svc}' suggests {label} for CI (CI-only, INFERRED)",
                    "INFERRED",
                )
                d.states.add("OPTIONAL")
                deps.append(d)
    return deps
