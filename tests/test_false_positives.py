"""False-positive discipline: honest UNKNOWN beats wrong REQUIRED."""

from pathlib import Path

from ghostdeps.config import Config
from ghostdeps.scanner import run_scan

FIX = Path(__file__).parent / "fixtures"


def test_docs_only_mention_is_not_required():
    r = run_scan(FIX / "false_positive", config=Config(), offline=True)
    # test-only ffmpeg usage must be OPTIONAL, never unconditional REQUIRED
    ff = [d for d in r.dependencies if d.name == "ffmpeg"]
    assert ff
    node = ff[0]
    assert node.required != "YES" or "OPTIONAL" in node.states or node.confidence != "VERIFIED"
    # docs-only SYSTEM_PACKAGE mention stays INFERRED
    docs_nodes = [
        d for d in r.dependencies if any(e.detector == "readme-scan" for e in d.evidences)
    ]
    for d in docs_nodes:
        if len(d.evidences) == 1:
            assert d.confidence == "INFERRED"
            assert d.required in ("UNKNOWN", "OPTIONAL")


def test_cross_platform_filesystem_flagged():
    from ghostdeps.portable import assess

    r = run_scan(FIX / "cross_platform", config=Config(), offline=True)
    fs = [d for d in r.dependencies if d.type == "FILESYSTEM"]
    assert fs, "absolute /etc path should yield FILESYSTEM evidence"
    rep = assess(r, "windows")
    assert any(f["verdict"] == "BLOCKER" for f in rep["findings"])


def test_dynamic_plugin_is_unknown_not_required():
    r = run_scan(FIX / "runtime_only", config=Config(), offline=True)
    assert r.dependencies  # scan completes; dynamic import is not claimed as proven
    for d in r.dependencies:
        if d.type == "PACKAGE":
            assert d.required in ("UNKNOWN", "OPTIONAL")


def test_namespace_urls_are_not_network_deps():
    from ghostdeps.analyzers.python_source import is_namespace_url

    assert is_namespace_url("http://maven.apache.org/POM/4.0.0")
    assert is_namespace_url("http://www.w3.org/2001/XMLSchema")
    assert not is_namespace_url("https://api.example.com/v1")


def test_dynamic_subprocess_is_never_ghost():
    from ghostdeps.fusion import classify
    from ghostdeps.models import Dependency, Evidence

    dep = Dependency(
        name="dynamic-subprocess",
        type="BEHAVIOR",
        states={"DISCOVERED"},
        referenced="YES",
        confidence="INFERRED",
    )
    dep.add_evidence(
        Evidence(
            detector="python-ast",
            kind="static-subprocess-dynamic",
            message="dynamic",
            confidence="INFERRED",
        )
    )
    classify([dep])
    assert "GHOST" not in dep.states
