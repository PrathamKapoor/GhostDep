"""Regression tests for v0.1.0 hardening fixes."""

from pathlib import Path

from ghostdeps.analyzers.base import evidence_file
from ghostdeps.analyzers.env_services import analyze_dotenv
from ghostdeps.config import Config
from ghostdeps.util import normalize_executable, redact_url_credentials


def test_dotenv_export_prefix_not_mangled(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "export DATABASE_URL=postgres://db\nexport REMOTE_HOST=h\npostgres_url=x\ntoken=y\n",
        encoding="utf-8",
    )
    deps = analyze_dotenv(env, tmp_path)
    names = {d.name for d in deps}
    assert names == {"DATABASE_URL", "REMOTE_HOST", "postgres_url", "token"}


def test_normalize_executable_paths():
    assert normalize_executable("ffmpeg") == "ffmpeg"
    assert normalize_executable("/usr/bin/ffmpeg") == "ffmpeg"
    assert normalize_executable(r"C:\Tools\ffmpeg.exe") == "ffmpeg.exe"
    assert normalize_executable("./scripts/run.sh") is None
    assert normalize_executable("tools/build") is None
    assert normalize_executable("") is None


def test_url_credentials_redacted():
    assert redact_url_credentials("postgres://user:pass@host/db") == ("postgres://***:***@host/db")
    assert redact_url_credentials("https://api.example.com/v1") == ("https://api.example.com/v1")
    assert redact_url_credentials("") == ""


def test_evidence_file_posix(tmp_path):
    nested = tmp_path / "sub" / "dir"
    nested.mkdir(parents=True)
    f = nested / "mod.py"
    f.write_text("x = 1\n", encoding="utf-8")
    rel = evidence_file(f, tmp_path)
    assert rel == "sub/dir/mod.py"
    assert "\\" not in rel


def test_config_load_parse_error_surfaced(tmp_path):
    (tmp_path / "ghostdeps.json").write_text("{not json", encoding="utf-8")
    cfg, path, err = Config.load(tmp_path)
    assert path is not None
    assert err is not None and "failed to parse" in err
    assert cfg.ignore_deps == []


def test_config_load_non_dict_root(tmp_path):
    (tmp_path / "ghostdeps.json").write_text("[1, 2]", encoding="utf-8")
    cfg, path, err = Config.load(tmp_path)
    assert path is not None and err is not None
    assert cfg == Config()


def test_config_load_valid(tmp_path):
    (tmp_path / "ghostdeps.json").write_text(
        '{"ghostdeps": {"ignore_deps": ["lodash"]}}', encoding="utf-8"
    )
    cfg, path, err = Config.load(tmp_path)
    assert err is None and path is not None
    assert cfg.ignore_deps == ["lodash"]


def test_tool_version_factory():
    from ghostdeps.models import ScanResult

    a = ScanResult(repo_root=".")
    b = ScanResult(repo_root=".")
    assert a.tool_version == b.tool_version
    assert a.tool_version  # non-empty


def test_strace_log_path_uses_tempdir():
    import tempfile

    from ghostdeps.runtime.tracer import strace_log_path

    p = strace_log_path()
    assert str(p.parent) == str(Path(tempfile.gettempdir()))
    assert p.name.startswith("ghostdeps-strace")


def test_js_url_credentials_redacted_in_name_and_snippet(tmp_path):
    from ghostdeps.analyzers.js_generic import analyze_js

    f = tmp_path / "a.js"
    f.write_text(
        'process.env.http_proxy = "http://user:pass@127.0.0.1:8030";\n'
        'fetch("http://user:pass@127.0.0.1:9");\n',
        encoding="utf-8",
    )
    deps = analyze_js(f, tmp_path)
    blob_parts = []
    for d in deps:
        blob_parts.append(d.name)
        for e in d.evidences:
            blob_parts.append(e.message or "")
            blob_parts.append(e.snippet or "")
    blob = "\n".join(blob_parts)
    assert "user:pass@" not in blob
    assert "***:***@" in blob


def test_python_url_name_redacted(tmp_path):
    from ghostdeps.analyzers.python_source import analyze as py_analyze

    f = tmp_path / "a.py"
    f.write_text('URL = "http://user:pass@host/x"\n', encoding="utf-8")
    deps = py_analyze(f, tmp_path)
    names = [d.name for d in deps]
    assert any("user:pass@" not in n for n in names)
    assert not any("user:pass@" in n for n in names)
    assert any("***:***@" in n for n in names)


def test_ast_parse_syntaxwarning_suppressed(tmp_path, capfd):
    import warnings

    from ghostdeps.analyzers.python_source import analyze as py_analyze

    f = tmp_path / "warn.py"
    # invalid escape sequence emits SyntaxWarning on 3.12+
    f.write_text('x = "\\$"\n', encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        py_analyze(f, tmp_path)
    err = capfd.readouterr().err
    assert "SyntaxWarning" not in err


def test_js_url_fixture_still_detected():
    from ghostdeps.analyzers.js_generic import analyze_js

    fix = Path(__file__).parent / "fixtures" / "network_dep" / "app.js"
    deps = analyze_js(fix, fix.parent)
    nets = [d.name for d in deps if d.type == "NETWORK_ENDPOINT"]
    assert any("api.example.com" in n for n in nets)
