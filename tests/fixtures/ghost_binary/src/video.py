"""Transcode uploaded video (fixture: undeclared ffmpeg ghost)."""

import subprocess


def transcode_video(src: str, dest: str) -> None:
    subprocess.run(["ffmpeg", "-i", src, dest], check=True)
