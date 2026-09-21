import subprocess


def test_video():
    subprocess.run(["ffmpeg", "-version"], check=True)
