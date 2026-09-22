"""Small shared helpers for analyzers (pure functions, stdlib only)."""

from __future__ import annotations

import re

_URL_USERINFO = re.compile(r"(://)[^/\s:@]+:[^/\s@]+@")


def normalize_executable(cmd: str) -> str | None:
    """Map a command token to an external system binary name, or None.

    - Bare names ("ffmpeg", "python3") are external binaries as-is.
    - Absolute paths ("/usr/bin/ffmpeg", "C:\\\\Tools\\\\ffmpeg.exe") reduce
      to their basename: the binary is external even if the path is absolute.
    - Repo-relative paths ("./scripts/run.sh", "tools/build") are NOT external
      system dependencies; return None so callers do not claim a GHOST binary.
    """
    cmd = cmd.strip()
    if not cmd:
        return None
    posix = cmd.replace("\\", "/")
    if posix.startswith("/") or re.match(r"^[A-Za-z]:/", posix):
        base = posix.rsplit("/", 1)[-1]
        return base or None
    if "/" in posix or cmd.startswith("."):
        return None
    if " " in cmd:
        return cmd.split()[0]
    return cmd


def redact_url_credentials(text: str) -> str:
    """Replace userinfo credentials in URL-shaped substrings: user:pass@ -> ***:***@"""
    if not text:
        return text
    return _URL_USERINFO.sub(r"\1***:***@", text)
