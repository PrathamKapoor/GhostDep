"""Manifest detector (extensible). stdlib only; unsupported types are explicit."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ghostdeps.analyzers.base import evidence_file, safe_read
from ghostdeps.models import Dependency, Evidence

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

SUPPORTED_MANIFESTS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "*.csproj",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "Dockerfile",
    "docker-compose.yml",
    "compose.yaml",
    ".github/workflows/*",
)


def is_manifest(path: Path) -> bool:
    name = path.name
    if name in SUPPORTED_MANIFESTS:
        return True
    if name.endswith(".csproj"):
        return True
    if name in ("docker-compose.yaml", "docker-compose.override.yml"):
        return True
    if path.suffix in (".gemspec",):
        return False
    return False


def analyze_manifest(path: Path, root: Path) -> tuple[list[Dependency], str | None]:
    """Return (deps, unsupported_message)."""
    rel = evidence_file(path, root)
    name = path.name
    try:
        if name == "package.json":
            return (_from_package_json(path, rel), None)
        if name == "package-lock.json":
            return (_from_package_lock(path, rel), None)
        if name in ("yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock"):
            return (_from_lockfile_lines(path, rel, name), None)
        if name == "requirements.txt":
            return (_from_requirements(path, rel), None)
        if name == "pyproject.toml":
            return (_from_pyproject(path, rel), None)
        if name in ("Pipfile", "Pipfile.lock", "composer.json", "composer.lock"):
            return (_from_json_deps(path, rel, name), None)
        if name in ("go.mod", "go.sum"):
            return (_from_go(path, rel, name), None)
        if name in ("Cargo.toml", "Cargo.lock"):
            return (_from_cargo(path, rel, name), None)
        if name == "pom.xml":
            return (_from_pom(path, rel), None)
        if name in ("build.gradle", "build.gradle.kts"):
            return (_from_gradle(path, rel), None)
        if name.endswith(".csproj"):
            return (_from_csproj(path, rel), None)
        if name in ("Gemfile", "Gemfile.lock"):
            return (_from_gemfile(path, rel, name), None)
        if name == "Dockerfile":
            return ([], None)  # handled by DockerAnalyzer
        if "docker-compose" in name or name in ("compose.yaml", "compose.yml"):
            return ([], None)  # handled by DockerAnalyzer
    except Exception as exc:  # never crash a scan on one manifest
        return (
            ([], None)
            if False
            else ([], f"{rel}: manifest parse failed ({exc}); treated as UNKNOWN")
        )
    # Unknown manifest-like file explicitly reported by caller.
    return (
        [],
        f"{rel}: manifest type not implemented; reported as unsupported (not silently skipped)",
    )


def _decl(name: str, dtype: str, rel: str, detail: str, line: int | None = None) -> Dependency:
    dep = Dependency(
        name=name,
        type=dtype,
        states={"DECLARED", "DISCOVERED"},
        declared="YES",
        referenced="UNKNOWN",
        required="UNKNOWN",
        confidence="SUPPORTED",
    )
    dep.add_evidence(
        Evidence(
            detector="manifest",
            kind="manifest",
            message=detail,
            file=rel,
            line=line,
            confidence="SUPPORTED",
        )
    )
    return dep


def _from_package_json(path: Path, rel: str) -> list[Dependency]:
    data = json.loads(safe_read(path) or "{}")
    out: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(section, {}) or {}
        for pkg, ver in block.items():
            d = _decl(pkg, "PACKAGE", rel, f"package.json [{section}]: {pkg} {ver}")
            if section in ("devDependencies",):
                d.states.add("OPTIONAL")
            if section in ("optionalDependencies",):
                d.states.add("OPTIONAL")
                d.required = "OPTIONAL"
            d.relationships.append(
                {"rel": "declared-by", "target": "package.json", "section": section}
            )
            out.append(d)
    engines = data.get("engines", {}) or {}
    for eng, ver in engines.items():
        d = _decl(eng, "RUNTIME", rel, f"package.json engines: {eng} {ver}")
        out.append(d)
    scripts = data.get("scripts", {}) or {}
    for script, cmd in scripts.items():
        if isinstance(cmd, str) and cmd.strip():
            d = Dependency(
                name=f"npm-script:{script}",
                type="BEHAVIOR",
                states={"DECLARED", "DISCOVERED"},
                declared="YES",
                referenced="YES",
                required="UNKNOWN",
                confidence="INFERRED",
            )
            d.add_evidence(
                Evidence(
                    detector="manifest",
                    kind="package-script",
                    message=f"package.json script '{script}' runs: {cmd[:160]}",
                    file=rel,
                    snippet=cmd[:300],
                    confidence="INFERRED",
                )
            )
            out.append(d)
    return out


def _from_package_lock(path: Path, rel: str) -> list[Dependency]:
    data = json.loads(safe_read(path) or "{}")
    out: list[Dependency] = []
    packages = data.get("packages") or {}
    deps = data.get("dependencies") or {}
    if packages:
        for key, _meta in packages.items():
            if not key or key == "":
                continue
            pkg = key.split("node_modules/")[-1]
            if pkg:
                out.append(_decl(pkg, "PACKAGE", rel, f"package-lock packages: {pkg}"))
    elif deps:
        for pkg, _meta in deps.items():
            out.append(_decl(pkg, "PACKAGE", rel, f"package-lock dependencies: {pkg}"))
    return out


def _from_lockfile_lines(path: Path, rel: str, kind: str) -> list[Dependency]:
    text = safe_read(path)
    out: list[Dependency] = []
    seen: set[str] = set()
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*"?(@?[^"\s:;,]+)"?\s*[:@]', line)
        if not m:
            continue
        candidate = m.group(1).strip().strip('"').strip("'")
        if not candidate or candidate.startswith(("#", "-", " ", "[")):
            continue
        if "/" in candidate and not candidate.startswith("@"):
            continue
        if candidate in seen or len(candidate) > 120:
            continue
        if re.match(r"^(version|resolved|integrity|dependencies|spec|name)\b", candidate):
            continue
        seen.add(candidate)
        out.append(_decl(candidate, "PACKAGE", rel, f"{kind} entry: {candidate}", line=i))
        if len(seen) > 2000:
            break
    return out


def _from_requirements(path: Path, rel: str) -> list[Dependency]:
    out: list[Dependency] = []
    for i, raw in enumerate(safe_read(path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\s*[=<>!~;].*)?$", line)
        if m:
            out.append(_decl(m.group(1), "PACKAGE", rel, f"requirements.txt: {line}", line=i))
    return out


def _from_pyproject(path: Path, rel: str) -> list[Dependency]:
    text = safe_read(path)
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
        except Exception:
            data = {}
    else:
        data = {}
    out: list[Dependency] = []
    project = data.get("project", {}) if isinstance(data, dict) else {}
    for req in project.get("dependencies", []) or []:
        m = re.match(r"^([A-Za-z0-9_.\-]+)", str(req))
        if m:
            out.append(_decl(m.group(1), "PACKAGE", rel, f"pyproject dependencies: {req}"))
    for group, reqs in (project.get("optional-dependencies", {}) or {}).items():
        for req in reqs or []:
            m = re.match(r"^([A-Za-z0-9_.\-]+)", str(req))
            if m:
                d = _decl(m.group(1), "PACKAGE", rel, f"pyproject optional [{group}]: {req}")
                d.states.add("OPTIONAL")
                d.required = "OPTIONAL"
                out.append(d)
    if not data and text:
        # Fallback regex when tomllib missing/unparseable: still report honestly.
        for m in re.finditer(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M):
            for pkg in re.findall(r'"([A-Za-z0-9_.\-]+)', m.group(1)):
                out.append(_decl(pkg, "PACKAGE", rel, f"pyproject (heuristic): {pkg}"))
    tool_poetry = (data.get("tool", {}) or {}).get("poetry", {}) if isinstance(data, dict) else {}
    for section in ("dependencies", "dev-dependencies", "group"):
        block = tool_poetry.get(section, {}) if isinstance(tool_poetry, dict) else {}
        if isinstance(block, dict):
            for pkg in block:
                if pkg.lower() != "python":
                    out.append(_decl(pkg, "PACKAGE", rel, f"pyproject poetry [{section}]: {pkg}"))
    # requires-python -> RUNTIME
    rp = project.get("requires-python") if isinstance(project, dict) else None
    if rp:
        out.append(_decl("python", "RUNTIME", rel, f"pyproject requires-python: {rp}"))
    return out


def _from_json_deps(path: Path, rel: str, kind: str) -> list[Dependency]:
    try:
        data = json.loads(safe_read(path) or "{}")
    except Exception:
        return []
    out: list[Dependency] = []
    sections = []
    if kind == "Pipfile":
        for section in ("packages", "dev-packages"):
            block = data.get(section, {}) or {}
            for pkg in block:
                out.append(_decl(pkg, "PACKAGE", rel, f"Pipfile [{section}]: {pkg}"))
        _ = sections
        return out
    # Pipfile.lock / composer.json / composer.lock
    for section in ("packages", "require", "require-dev", "default", "develop"):
        block = data.get(section, {}) or {}
        if isinstance(block, dict):
            for pkg in block:
                d = _decl(pkg, "PACKAGE", rel, f"{kind} [{section}]: {pkg}")
                if "dev" in section:
                    d.states.add("OPTIONAL")
                out.append(d)
        elif isinstance(block, list):
            for item in block:
                if isinstance(item, dict) and item.get("name"):
                    out.append(_decl(str(item["name"]), "PACKAGE", rel, f"{kind}: {item['name']}"))
    return out


def _from_go(path: Path, rel: str, kind: str) -> list[Dependency]:
    out: list[Dependency] = []
    if kind == "go.mod":
        text = safe_read(path)
        m = re.search(r"^go\s+(\S+)", text, re.M)
        if m:
            out.append(_decl("go", "RUNTIME", rel, f"go.mod toolchain: go {m.group(1)}"))
        for m in re.finditer(r"^\s*([A-Za-z0-9_.\-/]+)\s+v\S+", text, re.M):
            mod = m.group(1)
            if "." in mod and "/" in mod:
                out.append(_decl(mod, "PACKAGE", rel, f"go.mod require: {mod}"))
    else:
        for line in safe_read(path).splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-/]+)\s+v\S+", line.strip())
            if m and "." in m.group(1):
                out.append(_decl(m.group(1), "PACKAGE", rel, f"go.sum: {m.group(1)}"))
                if len(out) > 2000:
                    break
    return out


def _from_cargo(path: Path, rel: str, kind: str) -> list[Dependency]:
    text = safe_read(path)
    out: list[Dependency] = []
    if kind == "Cargo.toml":
        if tomllib is not None:
            try:
                data = tomllib.loads(text)
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    block = data.get(section, {}) or data.get("workspace", {})
                    _ = block
                for scope in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for table in (data.get(scope, {}),):
                        if isinstance(table, dict):
                            for pkg in table:
                                out.append(
                                    _decl(pkg, "PACKAGE", rel, f"Cargo.toml [{scope}]: {pkg}")
                                )
                pkg = (
                    ((data.get("package", {}) or {}).get("rust-version"))
                    if isinstance(data, dict)
                    else None
                )
                if pkg:
                    out.append(_decl("rust", "RUNTIME", rel, f"Cargo.toml rust-version: {pkg}"))
                return out
            except Exception:
                pass
        in_deps = False
        for i, line in enumerate(text.splitlines(), 1):
            if re.match(r"^\s*\[.*dependencies.*\]", line):
                in_deps = True
                continue
            if line.strip().startswith("["):
                in_deps = False
            if in_deps:
                m = re.match(r"^\s*([A-Za-z0-9_\-]+)\s*=", line)
                if m:
                    out.append(
                        _decl(m.group(1), "PACKAGE", rel, f"Cargo.toml: {m.group(1)}", line=i)
                    )
    else:  # Cargo.lock
        for m in re.finditer(r"^name\s*=\s*\"([^\"]+)\"", text, re.M):
            out.append(_decl(m.group(1), "PACKAGE", rel, f"Cargo.lock: {m.group(1)}"))
    return out


def _from_pom(path: Path, rel: str) -> list[Dependency]:
    out: list[Dependency] = []
    try:
        root = ET.fromstring(safe_read(path) or "<x/>")
    except Exception:
        return out
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    for dep in list(root.findall(".//m:dependency", ns)) + list(root.findall(".//dependency")):
        gid = dep.find("m:groupId", ns)
        aid = dep.find("m:artifactId", ns)
        if aid is None:
            aid = dep.find("artifactId")
        if aid is not None and aid.text:
            gid_text = gid.text if gid is not None and gid.text else ""
            name = f"{gid_text}:{aid.text}" if gid_text else (aid.text or "")
            scope = dep.find("m:scope", ns)
            d = _decl(name.strip(), "PACKAGE", rel, f"pom.xml dependency: {name.strip()}")
            scope_text = (scope.text if scope is not None else None) or (
                dep.findtext("scope") or ""
            )
            if scope_text.strip() == "test":
                d.states.add("OPTIONAL")
            out.append(d)
    return out


def _from_gradle(path: Path, rel: str) -> list[Dependency]:
    out: list[Dependency] = []
    text = safe_read(path)
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(
            r"""(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['"]([^'"]+)['"]""",
            line,
        )
        if m:
            out.append(
                _decl(m.group(2), "PACKAGE", rel, f"gradle {m.group(1)}: {m.group(2)}", line=i)
            )
    return out


def _from_csproj(path: Path, rel: str) -> list[Dependency]:
    out: list[Dependency] = []
    try:
        root = ET.fromstring(safe_read(path) or "<x/>")
    except Exception:
        return out
    for ref in list(root.findall(".//PackageReference")):
        inc = ref.get("Include")
        if inc:
            out.append(_decl(inc, "PACKAGE", rel, f"csproj PackageReference: {inc}"))
    tf = root.findtext(".//TargetFramework") or root.findtext(".//TargetFrameworks") or ""
    if tf:
        out.append(_decl("dotnet", "RUNTIME", rel, f"csproj target: {tf.strip()}"))
    return out


def _from_gemfile(path: Path, rel: str, kind: str) -> list[Dependency]:
    out: list[Dependency] = []
    text = safe_read(path)
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"""\s*gem\s+['"]([^'"]+)['"]""", line)
        if m:
            out.append(_decl(m.group(1), "PACKAGE", rel, f"{kind}: {m.group(1)}", line=i))
        m2 = re.match(r"""\s*([A-Za-z0-9_\-]+)\s+\(([^)]+)\)""", line)
        if (
            kind == "Gemfile.lock"
            and m2
            and not line.strip().startswith(("GEM", "PLATFORMS", "DEPENDENCIES", "SPEC"))
        ):
            out.append(_decl(m2.group(1), "PACKAGE", rel, f"Gemfile.lock: {m2.group(1)}", line=i))
    return out
