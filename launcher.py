"""One-click launcher for Copilot SOC.

Automatically:
  1. Starts Docker Desktop + PostgreSQL + Redis via Docker Compose
  2. Starts the FastAPI server (which auto-bootstraps schema + seed on startup)
  3. Opens the login page in the browser
"""

from __future__ import annotations

import os
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


def load_env_file() -> None:
    """Load .env file into os.environ so child processes inherit the vars."""
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def docker_daemon_running() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def start_docker_desktop() -> None:
    if docker_daemon_running():
        return
    docker_exe = Path(r"C:\Program Files\Docker\Docker\Docker Desktop.exe")
    if not docker_exe.exists():
        print("  ERROR: Docker Desktop not found. Install it from https://docker.com/products/docker-desktop")
        sys.exit(1)
    print("  Starting Docker Desktop...")
    subprocess.Popen([str(docker_exe)], cwd=str(docker_exe.parent))
    for i in range(120):
        time.sleep(1)
        if docker_daemon_running():
            print(f"  Docker ready ({i+1}s)")
            return
        if i % 10 == 9:
            print(f"  Waiting for Docker... ({i+1}s)")
    print("  ERROR: Docker did not start in time. Start Docker Desktop manually.")
    sys.exit(1)


def postgres_ready() -> bool:
    try:
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "postgres", "pg_isready", "-U", "copilot", "-d", "copilot_soc"],
            capture_output=True, timeout=10, cwd=str(ROOT),
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def start_infrastructure() -> None:
    start_docker_desktop()
    if postgres_ready():
        print("  PostgreSQL already running")
        return
    print("  Starting PostgreSQL + Redis...")
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "postgres", "redis"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr.strip()}")
        sys.exit(1)
    for i in range(60):
        time.sleep(1)
        if postgres_ready():
            print(f"  PostgreSQL ready ({i+1}s)")
            return
    print("  ERROR: PostgreSQL did not start in time")
    sys.exit(1)


def kill_stale_port(port: int = 8000) -> None:
    try:
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                pid = line.strip().split()[-1]
                subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, timeout=5)
                print(f"  Killed stale process on port {port} (PID {pid})")
                time.sleep(1)
                break
    except Exception:
        pass


def main() -> int:
    ensure_env_file()
    load_env_file()
    python_bin = python_executable()

    print("=" * 56)
    print(" Copilot SOC")
    print("=" * 56)
    print()

    print("[1/3] Infrastructure...")
    start_infrastructure()

    print("[2/3] Starting server...")
    kill_stale_port()

    print("[3/3] Done!")
    print()
    print("  Login:   http://127.0.0.1:8000/login")
    print("  Docs:    http://127.0.0.1:8000/docs")
    print("  Email:   admin@copilot-soc.local")
    print("  Pass:    ChangeMe123!")
    print("  Press Ctrl+C to stop.")
    print()

    process = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "copilot_soc.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    time.sleep(3)
    webbrowser.open("http://127.0.0.1:8000/login")

    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
