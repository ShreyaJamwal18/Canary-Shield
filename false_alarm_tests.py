"""
Canary Shield — False Alarm (Benign Activity) Test Harness.

Tests whether legitimate Windows operations trigger false tripwires
when the deception engine is armed. ALL tests run in test mode against
test_sandbox ONLY.

SAFETY:
  - contain.kill_process is monkeypatched to a stub that records
    "would terminate PID x (name)" without actually killing anything.
  - Everything runs inside test_sandbox (HARD RULE 1).
  - No real processes are ever terminated.
"""

import os
import sys
import time
import json
import shutil
import hashlib
import tempfile
import subprocess
import threading
import logging
from typing import Dict, Any, List, Optional

# Force test mode before any other import
os.environ["CANARY_TEST_MODE"] = "1"

# Project root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from config import TEST_SANDBOX_DIR, BASE_DIR as CFG_BASE_DIR
from decoy import deploy_decoys, cleanup_decoys, load_decoy_manifest
from monitor import CanaryEventHandler, _normalize_path
from process_id import find_offending_pid, get_last_attribution_record, start_process_cache, stop_process_cache
from watchdog.observers import Observer

# =========================================================================
# SAFETY: Monkeypatch contain.kill_process BEFORE anything else imports it
# =========================================================================
import contain as _contain_module

_containment_log: List[Dict[str, Any]] = []
_original_kill_process = _contain_module.kill_process


def _stub_kill_process(pid=None, confidence="HIGH", method="direct_handle",
                       target_path=None, latency_ms=None,
                       t_event_received=None, t_attr_start=None, t_attr_end=None):
    """Stub: records what WOULD have been killed. Never actually kills."""
    import psutil
    proc_name = "unknown"
    try:
        if pid is not None:
            proc_name = psutil.Process(pid).name()
    except Exception:
        pass
    entry = {
        "action": "WOULD_TERMINATE",
        "pid": pid,
        "proc_name": proc_name,
        "confidence": confidence,
        "method": method,
        "target_path": target_path,
        "latency_ms": latency_ms,
        "timestamp": time.time(),
    }
    _containment_log.append(entry)
    print(f"  [STUB] Would terminate PID {pid} ({proc_name}) — confidence={confidence} method={method}")
    return True  # Pretend it succeeded


# Apply the monkeypatch
_contain_module.kill_process = _stub_kill_process
# Also patch the reference in monitor module
import monitor as _monitor_module
_monitor_module.kill_process = _stub_kill_process


# =========================================================================
# EVENT CAPTURE: Wrap the event handler to record events
# =========================================================================
_event_log: List[Dict[str, Any]] = []


class InstrumentedEventHandler(CanaryEventHandler):
    """Wraps CanaryEventHandler to capture every tripwire event for analysis."""

    def _handle_event(self, event_type: str, raw_path: str) -> None:
        norm_path = _normalize_path(raw_path)
        # Only log canary paths (the real handler filters too)
        if norm_path in self.canary_paths:
            if time.time() >= self._arm_time and not self._should_debounce(norm_path):
                _event_log.append({
                    "event_type": event_type,
                    "path": norm_path,
                    "timestamp": time.time(),
                })
                # Reset debounce so the real handler also fires
                # (we need it to run attribution & stub kill)
                del self._recent_triggers[norm_path]
        # Call the real handler (which will re-debounce)
        super()._handle_event(event_type, raw_path)


# =========================================================================
# TEST INFRASTRUCTURE
# =========================================================================
SANDBOX = TEST_SANDBOX_DIR
RESULTS: List[Dict[str, Any]] = []
REPEAT_COUNT = 3


def _clear_logs():
    """Clear event and containment logs between tests."""
    _event_log.clear()
    _containment_log.clear()


def _wait_for_events(seconds: float = 3.0):
    """Wait for filesystem events to settle."""
    time.sleep(seconds)


def _record_result(activity: str, run: int):
    """Snapshot current event and containment logs into results."""
    tripwire_fired = len(_event_log) > 0
    event_types = list(set(e["event_type"] for e in _event_log))
    attributed = []
    for c in _containment_log:
        attributed.append({
            "pid": c["pid"],
            "proc_name": c["proc_name"],
            "method": c["method"],
            "confidence": c["confidence"],
        })
    would_contain = len(_containment_log) > 0

    result = {
        "activity": activity,
        "run": run,
        "tripwire_fired": tripwire_fired,
        "event_count": len(_event_log),
        "event_types": event_types,
        "attributed_processes": attributed,
        "would_containment_act": would_contain,
        "events_raw": list(_event_log),
        "containment_raw": list(_containment_log),
    }
    RESULTS.append(result)
    status = "FIRED" if tripwire_fired else "silent"
    print(f"    Result: {status} | events={len(_event_log)} types={event_types} "
          f"| contain={would_contain} | attributed={[a['proc_name'] for a in attributed]}")


def _restore_sandbox(canary_paths: List[str]):
    """Re-deploy decoys and mock user files if any were damaged."""
    # Restore locked decoys
    for cp in canary_paths:
        locked = cp + ".locked"
        if os.path.exists(locked):
            try:
                os.replace(locked, cp)
            except Exception:
                pass
        if not os.path.exists(cp):
            try:
                with open(cp, "wb") as f:
                    f.write(os.urandom(8192))
            except Exception:
                pass
    # Re-seed user files
    from simulate_attack import seed_mock_user_files
    seed_mock_user_files(SANDBOX)


# =========================================================================
# INDIVIDUAL TEST ACTIVITIES
# =========================================================================

def test_robocopy_e(canary_paths):
    """Test a: robocopy test_sandbox to a temp folder with /E"""
    with tempfile.TemporaryDirectory(prefix="canary_robocopy_") as tmp:
        dest = os.path.join(tmp, "copy")
        subprocess.run(
            ["robocopy", SANDBOX, dest, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/NP"],
            capture_output=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def test_robocopy_m(canary_paths):
    """Test b: robocopy with /M (resets archive attribute on source)"""
    with tempfile.TemporaryDirectory(prefix="canary_robo_m_") as tmp:
        dest = os.path.join(tmp, "copy")
        subprocess.run(
            ["robocopy", SANDBOX, dest, "/E", "/M", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/NP"],
            capture_output=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def test_compress_archive(canary_paths):
    """Test c: Compress-Archive of test_sandbox"""
    with tempfile.TemporaryDirectory(prefix="canary_zip_") as tmp:
        zip_path = os.path.join(tmp, "sandbox.zip")
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Compress-Archive -Path '{SANDBOX}\\*' -DestinationPath '{zip_path}' -Force"],
            capture_output=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def test_read_hash(canary_paths):
    """Test d: Get-FileHash and a Python script that reads every file"""
    # PowerShell Get-FileHash
    subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"Get-ChildItem '{SANDBOX}' -File | Get-FileHash -Algorithm SHA256 | Out-Null"],
        capture_output=True, timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    # Python read-all
    for entry in os.listdir(SANDBOX):
        fpath = os.path.join(SANDBOX, entry)
        if os.path.isfile(fpath):
            try:
                with open(fpath, "rb") as f:
                    _ = f.read()
            except Exception:
                pass


def test_defender_scan(canary_paths):
    """Test e: Windows Defender custom scan of test_sandbox"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"try {{ Start-MpScan -ScanType CustomScan -ScanPath '{SANDBOX}' -ErrorAction Stop }} "
         f"catch {{ Write-Output 'Defender not available' }}"],
        capture_output=True, timeout=60, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if "not available" in (result.stdout or ""):
        print("    [NOTE] Windows Defender not available, skipping.")


def test_timestamp_attrib(canary_paths):
    """Test f: changing timestamps and toggling archive attribute on decoys"""
    for cp in canary_paths:
        if os.path.exists(cp):
            try:
                # Touch LastWriteTime
                os.utime(cp, (time.time(), time.time()))
            except Exception:
                pass
    # Toggle archive attribute via attrib
    subprocess.run(
        ["attrib", "+A", os.path.join(SANDBOX, "*.*")],
        capture_output=True, timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    subprocess.run(
        ["attrib", "-A", os.path.join(SANDBOX, "*.*")],
        capture_output=True, timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def test_copy_item(canary_paths):
    """Test g: copying the sandbox folder with Copy-Item -Recurse"""
    with tempfile.TemporaryDirectory(prefix="canary_copy_") as tmp:
        dest = os.path.join(tmp, "sandbox_copy")
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Copy-Item -Path '{SANDBOX}' -Destination '{dest}' -Recurse -Force"],
            capture_output=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def test_control_attack(canary_paths):
    """Test h: CONTROL — the real simulator must still be detected every time."""
    proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE_DIR, "simulate_attack.py"),
         "--target", SANDBOX, "--delay", "0.08", "--hold-handle", "0.3"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# =========================================================================
# MAIN TEST RUNNER
# =========================================================================

ACTIVITIES = [
    ("a. robocopy /E (read-only copy)", test_robocopy_e),
    ("b. robocopy /M (reset archive bit)", test_robocopy_m),
    ("c. Compress-Archive (zip)", test_compress_archive),
    ("d. Get-FileHash + Python read", test_read_hash),
    ("e. Windows Defender custom scan", test_defender_scan),
    ("f. Touch timestamps + attrib", test_timestamp_attrib),
    ("g. Copy-Item -Recurse", test_copy_item),
    ("h. CONTROL: simulate_attack.py", test_control_attack),
]


def run_all_tests():
    print("=" * 70)
    print("    CANARY SHIELD — FALSE ALARM TEST HARNESS")
    print("=" * 70)
    print(f"Sandbox: {SANDBOX}")
    print(f"Repeat count: {REPEAT_COUNT}")
    print(f"contain.kill_process: MONKEYPATCHED (stub, never kills)\n")

    # Step 1: Deploy decoys
    print("[Setup] Deploying decoys...")
    cleanup_decoys()
    canary_paths = deploy_decoys([SANDBOX])
    print(f"[Setup] Deployed {len(canary_paths)} decoys.")

    # Seed mock user files
    from simulate_attack import seed_mock_user_files
    seed_mock_user_files(SANDBOX)

    # Step 2: Start process cache
    start_process_cache()

    # Step 3: Start monitor
    handler = InstrumentedEventHandler(canary_paths)
    observer = Observer()
    observer.schedule(handler, SANDBOX, recursive=True)
    observer.start()
    print("[Setup] Monitor armed. Waiting 2s for NTFS flush grace period...\n")
    time.sleep(2.0)

    # Step 4: Run each activity
    for activity_name, activity_func in ACTIVITIES:
        print(f"\n{'='*60}")
        print(f"TEST: {activity_name}")
        print(f"{'='*60}")

        for run in range(1, REPEAT_COUNT + 1):
            print(f"  Run {run}/{REPEAT_COUNT}:")
            _clear_logs()

            # Restore sandbox state before each run
            _restore_sandbox(canary_paths)
            time.sleep(0.5)
            _clear_logs()  # Clear any restore-triggered events

            try:
                activity_func(canary_paths)
            except Exception as exc:
                print(f"    [ERROR] Activity failed: {exc}")

            _wait_for_events(3.0)
            _record_result(activity_name, run)

    # Step 5: Teardown
    print("\n[Teardown] Stopping monitor...")
    observer.stop()
    observer.join()
    stop_process_cache()

    # Step 6: Write results
    _write_results()
    _write_markdown_report()


def _write_results():
    """Write raw JSON results."""
    out_path = os.path.join(BASE_DIR, "false_alarm_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2, default=str)
    print(f"\n[Output] Raw results: {out_path}")


def _write_markdown_report():
    """Write docs/FALSE_ALARM_RESULTS.md with table and summary."""
    docs_dir = os.path.join(BASE_DIR, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    md_path = os.path.join(docs_dir, "FALSE_ALARM_RESULTS.md")

    # Aggregate results by activity
    agg: Dict[str, Dict] = {}
    for r in RESULTS:
        name = r["activity"]
        if name not in agg:
            agg[name] = {
                "runs": 0, "fires": 0,
                "event_types": set(), "processes": set(),
                "would_contain": 0,
            }
        a = agg[name]
        a["runs"] += 1
        if r["tripwire_fired"]:
            a["fires"] += 1
        for et in r["event_types"]:
            a["event_types"].add(et)
        for ap in r["attributed_processes"]:
            a["processes"].add(f'{ap["proc_name"]} ({ap["method"]}, {ap["confidence"]})')
        if r["would_containment_act"]:
            a["would_contain"] += 1

    lines = [
        "# Canary Shield — False Alarm Test Results\n",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M')}\n",
        f"**Sandbox:** `{SANDBOX}`\n",
        f"**Runs per activity:** {REPEAT_COUNT}\n",
        f"**contain.kill_process:** Monkeypatched stub (never kills)\n\n",
        "## Results Table\n\n",
        "| Activity | Tripwire Fired | Event Type(s) | Attributed Process | Would Contain? |",
        "|----------|---------------|---------------|-------------------|----------------|",
    ]

    false_alarm_count = 0
    for name in [a[0] for a in ACTIVITIES]:
        a = agg.get(name, {"runs": 0, "fires": 0, "event_types": set(), "processes": set(), "would_contain": 0})
        fired_str = f"{a['fires']}/{a['runs']}"
        if a["fires"] > 0 and "CONTROL" not in name:
            fired_str += " ⚠️"
            false_alarm_count += a["fires"]
        elif "CONTROL" in name and a["fires"] > 0:
            fired_str += " ✅"
        event_str = ", ".join(sorted(a["event_types"])) or "—"
        proc_str = ", ".join(sorted(a["processes"])) or "—"
        contain_str = f"{a['would_contain']}/{a['runs']}"
        if a["would_contain"] > 0 and "CONTROL" not in name:
            contain_str += " ⚠️"
        elif "CONTROL" in name and a["would_contain"] > 0:
            contain_str += " ✅"
        lines.append(f"| {name} | {fired_str} | {event_str} | {proc_str} | {contain_str} |")

    lines.append("")
    lines.append("## Summary\n")

    if false_alarm_count == 0:
        lines.append("**No false alarms detected.** All benign activities completed without triggering "
                      "the deception tripwires. The control test (simulate_attack.py) was correctly "
                      "detected every time.\n")
    else:
        lines.append(f"**{false_alarm_count} false alarm(s) detected across benign activities.**\n")
        lines.append("The following benign activities triggered the tripwire:\n")
        for name in [a[0] for a in ACTIVITIES]:
            a = agg.get(name)
            if a and a["fires"] > 0 and "CONTROL" not in name:
                lines.append(f"- **{name}**: fired {a['fires']}/{a['runs']} times "
                             f"(events: {', '.join(sorted(a['event_types']))})")
        lines.append("")

    # Control check
    ctrl = agg.get("h. CONTROL: simulate_attack.py", {"fires": 0, "runs": REPEAT_COUNT})
    if ctrl["fires"] == ctrl["runs"]:
        lines.append(f"**Control test:** simulate_attack.py was detected in {ctrl['fires']}/{ctrl['runs']} runs ✅\n")
    else:
        lines.append(f"**Control test:** simulate_attack.py was detected in {ctrl['fires']}/{ctrl['runs']} runs "
                      f"⚠️ (expected {ctrl['runs']}/{ctrl['runs']})\n")

    lines.append("## Manual Checks (not automated)\n")
    lines.append("The following activities should be tested manually to verify no false alarms:\n")
    lines.append("- [ ] **Windows Search indexing** the test_sandbox folder (wait for indexer to crawl)")
    lines.append("- [ ] **File Explorer preview/thumbnails** — open test_sandbox in Explorer, enable preview pane")
    lines.append("- [ ] **Open a decoy in Notepad** and save without changes")
    lines.append("- [ ] **Open a decoy in Notepad** and save with minor edit (add a space)")
    lines.append("- [ ] **Antivirus quick scan** (full system or targeted at test_sandbox)")
    lines.append("- [ ] **OneDrive/File History** sync if enabled on the machine")
    lines.append("- [ ] **Windows Backup** if configured to include the project folder")
    lines.append("")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[Output] Report: {md_path}")


if __name__ == "__main__":
    run_all_tests()
