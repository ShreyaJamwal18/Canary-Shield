"""
Canary Shield — Background Service & Daemon Manager.

Provides headless daemon execution and Windows Service-style management:
- Spawns Canary Shield in an isolated background process (DETACHED_PROCESS).
- Maintains PID lockfile (canary_shield.pid) for clean lifecycle management.
- Handles status queries, health checks, and graceful shutdown (SIGINT / Terminate).
"""

import os
import sys
import time
import subprocess
import psutil
import logging
from typing import Optional

from config import BASE_DIR, LOG_FILE, get_watched_directories, is_test_mode

logger = logging.getLogger("canary_shield.service")
PID_FILE = os.path.join(BASE_DIR, "canary_shield.pid")


def get_daemon_pid() -> Optional[int]:
    """Retrieve the PID of the active Canary Shield background daemon if running."""
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            if "python" in p.name().lower() and p.is_running():
                return pid
        # Clean up stale PID file if process already exited
        try:
            os.remove(PID_FILE)
        except Exception:
            pass
    except Exception:
        pass
    return None


def start_daemon(env: Optional[dict] = None) -> bool:
    """Spawn Canary Shield as a persistent, headless background process."""
    current_pid = get_daemon_pid()
    if current_pid:
        print(f"[Canary Shield Service] Daemon is already running with PID: {current_pid}")
        return True

    python_exe = sys.executable
    main_py = os.path.join(BASE_DIR, "main.py")

    # Windows creation flag for fully detached background process
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)

    exec_env = os.environ.copy() if env is None else env

    try:
        # Spawn detached background process
        proc = subprocess.Popen(
            [python_exe, main_py, "_run_monitor"],
            cwd=BASE_DIR,
            creationflags=creation_flags,
            close_fds=True,
            env=exec_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(proc.pid))

        time.sleep(1.0)
        if proc.poll() is None:
            print(f"[Canary Shield Service] Background daemon successfully launched with PID: {proc.pid}")
            print(f"[Canary Shield Service] Logging output directed to: {LOG_FILE}")
            return True
        else:
            if os.path.exists(PID_FILE):
                try:
                    os.remove(PID_FILE)
                except Exception:
                    pass
            print(f"[Canary Shield Service] Daemon process failed to remain active (Exit code: {proc.returncode}).")
            return False
    except Exception as exc:
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass
        print(f"[Canary Shield Service] Failed to spawn background daemon: {exc}")
        return False


def stop_daemon() -> bool:
    """Gracefully terminate the background Canary Shield daemon."""
    pid = get_daemon_pid()
    if not pid:
        print("[Canary Shield Service] No active background daemon is running.")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return True

    try:
        proc = psutil.Process(pid)
        print(f"[Canary Shield Service] Stopping background daemon (PID {pid})...")
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except psutil.TimeoutExpired:
            proc.kill()

        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        print("[Canary Shield Service] Daemon stopped successfully.")
        return True
    except psutil.NoSuchProcess:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        print("[Canary Shield Service] Daemon process had already terminated.")
        return True
    except Exception as exc:
        print(f"[Canary Shield Service] Failed to stop daemon PID {pid}: {exc}")
        return False


def print_status() -> None:
    """Print complete diagnostic status of Canary Shield and protected endpoints."""
    pid = get_daemon_pid()
    print("=" * 70)
    print("                  CANARY SHIELD — SYSTEM STATUS")
    print("=" * 70)
    if pid:
        p = psutil.Process(pid)
        uptime = round(time.time() - p.create_time(), 1)
        print(f"Service State:        ACTIVE (Running in Background)")
        print(f"Daemon PID:           {pid}")
        print(f"Uptime:               {uptime} seconds")
        print(f"Memory Usage:         {round(p.memory_info().rss / 1024 / 1024, 2)} MB")
    else:
        print("Service State:        INACTIVE (Not running in background)")

    mode_str = "TEST MODE (Safe Sandbox)" if is_test_mode() else "PRODUCTION MODE (Enterprise)"
    print(f"Execution Mode:       {mode_str}")
    print(f"Log File:             {LOG_FILE}")

    watched = get_watched_directories()
    print(f"\nProtected Directories ({len(watched)}):")
    total_canaries = 0
    for d in watched:
        if os.path.exists(d):
            canary_count = len([f for f in os.listdir(d) if any(f.startswith(p) for p in ["!_", "~$", "00_"])])
            total_canaries += canary_count
            print(f"  • {d} (Canaries active: {canary_count})")
        else:
            print(f"  • {d} [Directory not created yet]")

    print(f"Total Active Honeytokens: {total_canaries}")
    print("=" * 70)
