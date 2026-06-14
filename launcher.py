"""One-click launcher for Arbiterion.

Automatically:
  1. Starts Docker Desktop + PostgreSQL + Redis via Docker Compose
  2. Installs Sysmon if not present (silent, with SwiftOnSecurity config)
  3. Starts the FastAPI server (which auto-bootstraps schema + seed on startup)
  4. Opens the login page in the browser
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import webbrowser
import urllib.request
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
            ["docker", "compose", "exec", "-T", "postgres", "pg_isready", "-U", "arbiterion", "-d", "arbiterion"],
            capture_output=True, timeout=10, cwd=str(ROOT),
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


SYSMON_URL = "https://live.sysinternals.com/Sysmon64.exe"
SYSMON_CONFIG_URL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
SYSMON_DIR = ROOT / "sysmon"
SYSMON_EXE = SYSMON_DIR / "Sysmon64.exe"
SYSMON_CONFIG = SYSMON_DIR / "sysmonconfig-export.xml"


def ensure_sysmon_dir() -> None:
    SYSMON_DIR.mkdir(exist_ok=True)


def download_sysmon() -> bool:
    """Download Sysmon64.exe if not present."""
    if SYSMON_EXE.exists():
        return True
    print("  Downloading Sysmon...")
    ensure_sysmon_dir()
    try:
        urllib.request.urlretrieve(SYSMON_URL, SYSMON_EXE)
        print(f"  Downloaded to {SYSMON_EXE}")
        return True
    except Exception as e:
        print(f"  ERROR downloading Sysmon: {e}")
        return False


def download_sysmon_config() -> bool:
    """Download SwiftOnSecurity Sysmon config if not present."""
    if SYSMON_CONFIG.exists():
        return True
    print("  Downloading Sysmon config...")
    ensure_sysmon_dir()
    try:
        urllib.request.urlretrieve(SYSMON_CONFIG_URL, SYSMON_CONFIG)
        print(f"  Downloaded config to {SYSMON_CONFIG}")
        return True
    except Exception as e:
        print(f"  ERROR downloading Sysmon config: {e}")
        return False


def sysmon_installed() -> bool:
    """Check if Sysmon service is installed."""
    try:
        result = subprocess.run(
            ["sc", "query", "Sysmon64"],
            capture_output=True, timeout=10, text=True
        )
        return "RUNNING" in result.stdout or "STOPPED" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def sysmon_running() -> bool:
    """Check if Sysmon service is running."""
    try:
        result = subprocess.run(
            ["sc", "query", "Sysmon64"],
            capture_output=True, timeout=10, text=True
        )
        return "RUNNING" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def install_sysmon() -> bool:
    """Install Sysmon silently with SwiftOnSecurity config."""
    if not download_sysmon() or not download_sysmon_config():
        return False
    if sysmon_installed():
        print("  Sysmon already installed")
        return True
    print("  Installing Sysmon (silent)...")
    try:
        result = subprocess.run(
            [str(SYSMON_EXE), "-accepteula", "-i", str(SYSMON_CONFIG), "-n"],
            capture_output=True, timeout=60, cwd=str(SYSMON_DIR), text=True
        )
        if result.returncode == 0:
            print("  Sysmon installed successfully")
            return True
        print(f"  ERROR installing Sysmon: {result.stderr.strip()}")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  ERROR installing Sysmon: {e}")
        return False


def start_sysmon() -> bool:
    """Start Sysmon service if installed but not running."""
    if not sysmon_installed():
        return False
    if sysmon_running():
        print("  Sysmon already running")
        return True
    print("  Starting Sysmon service...")
    try:
        result = subprocess.run(
            ["sc", "start", "Sysmon64"],
            capture_output=True, timeout=30, text=True
        )
        if result.returncode == 0:
            print("  Sysmon started")
            return True
        print(f"  WARNING: Could not start Sysmon: {result.stderr.strip()}")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  WARNING: Could not start Sysmon: {e}")
        return False


def ensure_sysmon() -> None:
    """Ensure Sysmon is installed and running (Windows only)."""
    if sys.platform.lower() != "win32":
        return
    print("[Sysmon] Checking...")
    if not install_sysmon():
        print("  WARNING: Sysmon install failed; collector will use Security log only")
        return
    start_sysmon()


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
    print(" Arbiterion")
    print("=" * 56)
    print()

    print("[1/3] Infrastructure...")
    start_infrastructure()

    print("[2/3] Sysmon...")
    ensure_sysmon()

    print("[3/3] Starting server...")
    kill_stale_port()

    print("[4/3] Done!")
    print()
    print("  Login:   http://127.0.0.1:8000/login")
    print("  Docs:    http://127.0.0.1:8000/docs")
    print("  Email:   admin@arbiterion.local")
    print("  Pass:    ChangeMe123!")
    print("  Press Ctrl+C to stop.")
    print()

    process = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "arbiterion.main:app", "--host", "127.0.0.1", "--port", "8000"],
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

