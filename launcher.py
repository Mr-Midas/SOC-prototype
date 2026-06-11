"""One-click launcher for Endpoint SOC Copilot."""

from __future__ import annotations

import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def python_executable() -> str:
    venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def ensure_env_file() -> None:
    env_file = ROOT / ".env"
    example = ROOT / ".env.example"
    if not env_file.exists() and example.exists():
        env_file.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")


def main() -> int:
    ensure_env_file()
    python_bin = python_executable()
    print("=" * 56)
    print(" Copilot SOC")
    print("=" * 56)
    print("Starting app (refactored multi-tenant backend)...")
    print("Login:   http://127.0.0.1:8000/login")
    print("Docs:    http://127.0.0.1:8000/docs")
    print("Press Ctrl+C to stop.")
    print()

    process = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "copilot_soc.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(ROOT),
    )
    time.sleep(2)
    webbrowser.open("http://127.0.0.1:8000/login")

    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
