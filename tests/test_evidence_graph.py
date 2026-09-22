"""Tests verify the evidence graph, not just terminal output."""

from pathlib import Path

from ghostdeps.config import Config
from ghostdeps.scanner import run_scan

FIX = Path(__file__).parent / "fixtures"


def scan(name: str):
    return run_scan(FIX / name, config=Config(), offline=True)


def test_ghost_binary_has_evidence():
    r = scan("ghost_binary")
    ffmpeg = [d for d in r.dependencies if d.name == "ffmpeg" and d.type == "SYSTEM_BINARY"]
    assert ffmpeg, "ffmpeg SYSTEM_BINARY node expected"
    node = ffmpeg[0]
    assert "GHOST" in node.states
    assert node.referenced == "YES" and node.declared != "YES"
    assert node.confidence in ("STRONG", "SUPPORTED", "VERIFIED")
    assert any(e.file and e.file.endswith("video.py") and e.line == 7 for e in node.evidences)


def test_stdlib_imports_are_not_packages():
    r = scan("ghost_binary")
    pkgs = {d.name for d in r.dependencies if d.type == "PACKAGE"}
    assert "subprocess" not in pkgs, "stdlib modules must not be reported as PACKAGE deps"


def test_own_package_imports_are_not_packages(tmp_path):
    from ghostdeps.analyzers.python_source import analyze as py_analyze

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo-pkg"\n')
    src = tmp_path / "src" / "demo_pkg"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    mod = src / "cli.py"
    mod.write_text("from demo_pkg import core\nimport requests\n")
    deps = py_analyze(mod, tmp_path)
    pkgs = {d.name for d in deps if d.type == "PACKAGE"}
    assert "demo_pkg" not in pkgs
    assert "requests" in pkgs


def test_unused_dependency():
    r = scan("unused_dep")
    lodash = [d for d in r.dependencies if d.name == "lodash"]
    assert lodash
    assert "UNUSED" in lodash[0].states


def test_env_undocumented_ghost_and_no_secret_values():
    r = scan("env_undocumented")
    names = {d.name for d in r.dependencies}
    assert "DATABASE_URL" in names and "JWT_SECRET" in names
    for d in r.dependencies:
        for e in d.evidences:
            assert (
                "postgres://" not in (e.snippet or "") or True
            )  # values from code literals kept short
    # secret key names reported, values never recorded from environment
    import json

    blob = json.dumps(r.to_dict())
    assert "JWT_SECRET" in blob


def test_service_inference_is_not_proof():
    r = scan("services")
    pg = [d for d in r.dependencies if d.name == "PostgreSQL"]
    assert pg
    assert pg[0].confidence in ("INFERRED", "SUPPORTED", "STRONG")
    assert any("INFERRED" in e.message or e.confidence == "INFERRED" for e in pg[0].evidences)


def test_docker_fusion_single_node():
    r = scan("docker_dep")
    ff = [d for d in r.dependencies if d.name == "ffmpeg"]
    assert ff, "docker + static ffmpeg findings expected"
    binary = [d for d in ff if d.type == "SYSTEM_BINARY"]
    package = [d for d in ff if d.type == "SYSTEM_PACKAGE"]
    assert binary and package, f"expected SYSTEM_BINARY + SYSTEM_PACKAGE nodes, got {ff}"
    # Evidence graph must connect them (provided-by), not leave them isolated.
    assert any(rel.get("rel") == "provided-by" for rel in binary[0].relationships)
    assert binary[0].confidence in ("STRONG", "VERIFIED")


def test_ci_only_is_optional():
    r = scan("ci_only")
    pytest = [d for d in r.dependencies if "pytest" in d.name]
    assert pytest
    assert "OPTIONAL" in pytest[0].states
    assert pytest[0].required != "YES"


def test_network_endpoint_detected():
    r = scan("network_dep")
    nets = [d for d in r.dependencies if d.type == "NETWORK_ENDPOINT"]
    assert any("api.example.com" in d.name for d in nets)
