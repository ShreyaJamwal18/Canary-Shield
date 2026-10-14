"""
Canary Shield — Enterprise Main Entry Point & CLI.

Central command center for deception-based zero-day ransomware mitigation:
- Foreground and headless background daemon monitoring.
- Multi-directory protection across enterprise endpoints.
- Real-time VSS anti-recovery guard, malware quarantine, and desktop alerts.
- Enforces Hard Rule 1 (printing sandbox path) and Hard Rule 2 (allowlist status).
"""

import sys
import os
import argparse
import subprocess

from config import (
    TEST_SANDBOX_DIR,
    print_target_path,
    is_test_mode,
    get_active_allowlist,
    get_watched_directories,
    LOG_FILE,
    INCIDENTS_DIR,
    QUARANTINE_DIR,
)
from decoy import deploy_decoys, cleanup_decoys
from monitor import start_monitoring
from service_runner import start_daemon, stop_daemon, print_status
from incident_manager import list_incidents


def run_monitor_loop(block: bool = True) -> None:
    """Executes the core decoy deployment and real-time monitoring loop."""
    print("=" * 70)
    print("           CANARY SHIELD — Zero-Day Ransomware Mitigation")
    print("=" * 70)

    # HARD RULE 1: Explicitly print the full target sandbox directory path
    print_target_path("Initialization")

    # HARD RULE 2: Explicitly state the allowlist status
    if is_test_mode():
        print("[Canary Shield] EXECUTION MODE: TEST MODE (CANARY_TEST_MODE=1)")
        print("[Canary Shield] Note: python.exe is permitted for attack simulation.")
    else:
        print("[Canary Shield] EXECUTION MODE: PRODUCTION MODE (Enterprise Endpoint Protection)")
        print("[Canary Shield] Note: All system processes and python runtimes are strictly protected.")

    active_allowlist = get_active_allowlist()
    print(f"[Canary Shield] Protected Allowlist Size: {len(active_allowlist)} processes")
    print(f"[Canary Shield] Log File: {LOG_FILE}\n")

    # Step 1: Deploy decoys into protected directories
    print("[Canary Shield] Step 1: Planting realistic decoy canary files in protected directories...")
    canary_paths = deploy_decoys()
    print(f"[Canary Shield] Successfully armed {len(canary_paths)} decoy tripwires across {len(get_watched_directories())} directories.\n")

    # Step 2: Start monitoring and VSS protection
    print("[Canary Shield] Step 2: Activating real-time OS filesystem monitoring & VSS guard...")
    print("[Canary Shield] System is armed and guarding endpoints. Press Ctrl+C to stop.\n")
    start_monitoring(canary_paths, block=block)


def list_forensic_incidents() -> None:
    """Displays recorded forensic incident telemetry and quarantine vault records."""
    incidents = list_incidents()
    print("=" * 70)
    print("             CANARY SHIELD — FORENSIC INCIDENT LOG")
    print("=" * 70)
    if not incidents:
        print("No security incidents recorded yet. System clean.")
        print("=" * 70)
        return

    print(f"Total Incidents Recorded: {len(incidents)}\n")
    for inc in incidents:
        print(f"Incident ID:    {inc.get('incident_id')}")
        print(f"Timestamp:      {inc.get('timestamp_iso')}")
        print(f"Threat Process: {inc.get('proc_name')} (PID: {inc.get('pid')})")
        print(f"Target Decoy:   {inc.get('target_path')}")
        print(f"Attribution:    {inc.get('method')} ({inc.get('confidence')} Confidence, {inc.get('latency_ms', 0):.1f}ms)")
        if inc.get("quarantine"):
            print(f"Quarantined:    {inc['quarantine'].get('quarantine_path')}")
            print(f"SHA-256 Hash:   {inc['quarantine'].get('sha256')}")
        html_report = os.path.join(INCIDENTS_DIR, f"{inc.get('incident_id')}.html")
        if os.path.exists(html_report):
            print(f"HTML Report:    {html_report}")
        print("-" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Canary Shield — Enterprise Zero-Day Ransomware Mitigation System",
        epilog="Run without arguments to launch real-time monitoring directly."
    )
    subparsers = parser.add_subparsers(dest="command")

    # Subcommand: start
    start_parser = subparsers.add_parser("start", help="Start Canary Shield monitoring engine")
    start_parser.add_argument("--daemon", action="store_true", help="Run detached as a headless background daemon")

    # Subcommand: stop
    subparsers.add_parser("stop", help="Stop running background daemon")

    # Subcommand: status
    subparsers.add_parser("status", help="Query system and background service status")

    # Subcommand: arm
    subparsers.add_parser("arm", help="Deploy realistic decoys across watched directories")

    # Flag: --gui
    parser.add_argument("--gui", action="store_true", help="Launch the Canary Shield Desktop Application (GUI)")

    # Subcommand: gui
    subparsers.add_parser("gui", help="Launch the Canary Shield Desktop Application (GUI)")

    # Subcommand: disarm
    subparsers.add_parser("disarm", help="Safely clean up decoys from watched directories")

    # Subcommand: incidents
    subparsers.add_parser("incidents", help="View security incident forensic reports and quarantine vault")

    # Subcommand: test
    subparsers.add_parser("test", help="Run automated safe sandbox verification pipeline")

    # Hidden subcommand for internal daemon worker
    subparsers.add_parser("_run_monitor", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Launch GUI if requested
    if args.gui or args.command == "gui":
        from app import main as launch_gui
        launch_gui()
        return

    # Default action (no subcommand given): run monitor directly in foreground for 100% backward compatibility
    if args.command is None:
        run_monitor_loop(block=True)
    elif args.command == "start":
        if args.daemon:
            start_daemon()
        else:
            run_monitor_loop(block=True)
    elif args.command == "_run_monitor":
        run_monitor_loop(block=True)
    elif args.command == "stop":
        stop_daemon()
    elif args.command == "status":
        print_status()
    elif args.command == "arm":
        paths = deploy_decoys()
        print(f"[Canary Shield] Deployed {len(paths)} canaries across {len(get_watched_directories())} directories.")
    elif args.command == "disarm":
        cleaned = cleanup_decoys()
        print(f"[Canary Shield] Removed {cleaned} decoy files.")
    elif args.command == "incidents":
        list_forensic_incidents()
    elif args.command == "test":
        env = os.environ.copy()
        env["CANARY_TEST_MODE"] = "1"
        subprocess.run([sys.executable, "run_full_e2e_test.py"], env=env)


if __name__ == "__main__":
    main()
