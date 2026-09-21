"""CLI, output formats, baseline, verify, portability, generation."""

import json
from pathlib import Path

from ghostdeps.baseline import create_baseline, diff_results, load_baseline
from ghostdeps.cli import main
from ghostdeps.config import Config
from ghostdeps.generate import generate_contract, generate_devcontainer, generate_docker
from ghostdeps.portable import assess
from ghostdeps.reporters import render
from ghostdeps.scanner import run_scan
from ghostdeps.verify import verify as verify_result

FIX = Path(__file__).parent / "fixtures"


def test_json_schema_stable(capsys):
    r = run_scan(FIX / "ghost_binary", config=Config(), offline=True)
    blob = json.loads(render(r, "json"))
    assert blob["schema_version"] == "1.0.0"
    assert "dependencies" in blob
    dep = blob["dependencies"][0]
    for key in (
        "name",
        "type",
        "states",
        "confidence",
        "declared",
        "present",
        "referenced",
        "observed",
        "required",
        "evidence",
    ):
        assert key in dep


def test_markdown_and_sarif_render():
    r = run_scan(FIX / "ghost_binary", config=Config(), offline=True)
    md = render(r, "markdown")
    assert "# GhostDeps report" in md
    sarif = json.loads(render(r, "sarif"))
    assert sarif["version"] == "2.1.0"


def test_cli_scan_exit_codes(tmp_path):
    assert main(["--project-root", str(FIX / "ghost_binary"), "scan", "."]) == 0
    assert (
        main(["--project-root", str(FIX / "ghost_binary"), "scan", ".", "--fail-on", "GHOST"]) == 1
    )
    assert main(["--project-root", str(tmp_path / "nope"), "scan", "."]) == 2


def test_cli_why_explain(capsys):
    assert main(["--project-root", str(FIX / "ghost_binary"), "why", "ffmpeg"]) == 0
    out = capsys.readouterr().out
    assert "ffmpeg" in out and "video.py" in out
    assert main(["--project-root", str(FIX / "ghost_binary"), "explain", "ffmpeg"]) == 0
    out = capsys.readouterr().out
    assert "Declared" in out and "Evidence" in out


def test_baseline_diff(tmp_path):
    import shutil

    work = tmp_path / "w"
    shutil.copytree(FIX / "ghost_binary", work)
    r1 = run_scan(work, config=Config(), offline=True)
    create_baseline(r1, work)
    assert load_baseline(work) is not None
    (work / "src" / "extra.py").write_text('import os\nos.getenv("NEW_VAR")\n')
    r2 = run_scan(work, config=Config(), offline=True)
    d = diff_results(load_baseline(work), r2)
    assert d["counts"]["added"] >= 1


def test_verify_statuses_honest():
    r = run_scan(FIX / "ghost_binary", config=Config(), offline=True)
    out = verify_result(r, FIX / "ghost_binary")
    allowed = {"verified", "not verified", "verification unavailable", "verification failed"}
    for item in out["items"]:
        assert item["status"] in allowed


def test_portable_and_generate():
    r = run_scan(FIX / "cross_platform", config=Config(), offline=True)
    rep = assess(r, "windows")
    assert rep["target"] == "windows"
    contract = generate_contract(r)
    assert "GENERATED FROM OBSERVED EVIDENCE" in contract and "environment:" in contract
    assert "GENERATED FROM OBSERVED EVIDENCE" in generate_docker(r)
    dev = json.loads(generate_devcontainer(r))
    assert "NOT YET VERIFIED" in dev["$comment"]


def test_runtime_tracer_honest(tmp_path):
    from ghostdeps.runtime import get_tracer

    tracer = get_tracer()
    res = tracer.trace(["python", "--version"], cwd=str(tmp_path))
    assert res.exit_code == 0
    assert any("NOT fully traced" in w or "strace" in w for w in res.warnings)
