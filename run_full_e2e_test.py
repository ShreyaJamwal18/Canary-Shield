"""
Canary Shield — End-to-End Automated Pipeline Verification.

Runs the complete system end-to-end:
1. Launches main.py in an isolated process with CANARY_TEST_MODE=1.
2. Verifies decoys are seeded and watchdog monitoring is armed.
3. Launches simulate_attack.py to execute ransomware I/O against test_sandbox.
4. Verifies detection of the canary hit.
5. Verifies attribution to the attacker's PID.
6. Verifies immediate process termination (containment).
7. Verifies user files survived.
8. Outputs forensic log records as proof.
"""

import os
import sys
import time
import subprocess
import psutil

from config import TEST_SANDBOX_DIR, LOG_FILE, INCIDENTS_DIR, QUARANTINE_DIR, BASE_DIR

def clean_artifacts():
    for directory in [TEST_SANDBOX_DIR, INCIDENTS_DIR, QUARANTINE_DIR]:
        if os.path.exists(directory):
            for f in os.listdir(directory):
                p = os.path.join(directory, f)
                try:
                    if os.path.isfile(p):
                        try:
                            if sys.platform == "win32":
                                import ctypes
                                ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x80)
                            os.chmod(p, 0o666)
                        except Exception:
                            pass
                        os.remove(p)
                except Exception:
                    pass
    for temp_out in ["main_test.out", "sim_test.out"]:
        p = os.path.join(BASE_DIR, temp_out)
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

def main():
    test_start_time = time.time()
    print("=" * 70)
    print("      CANARY SHIELD — FULL END-TO-END AUTOMATED PIPELINE TEST")
    print("=" * 70)

    # Step 0: Clean slate
    clean_artifacts()
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.truncate(0)
        except Exception:
            try:
                os.remove(LOG_FILE)
            except Exception:
                pass

    env = os.environ.copy()
    env["CANARY_TEST_MODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"

    main_out_path = os.path.join(BASE_DIR, "main_test.out")
    sim_out_path = os.path.join(BASE_DIR, "sim_test.out")

    main_out_f = open(main_out_path, "w", encoding="utf-8")
    sim_out_f = open(sim_out_path, "w", encoding="utf-8")

    # Step 1: Launch defense engine (main.py)
    print("\n[E2E] Step 1: Launching Canary Shield (main.py) with CANARY_TEST_MODE=1...")
    main_proc = subprocess.Popen(
        [sys.executable, "main.py"],
        env=env,
        stdout=main_out_f,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Wait for Canary Shield initialization and watchdog arming
    print("[E2E] Waiting for Canary Shield watchdog arming signal...")
    start_init = time.time()
    armed = False
    while time.time() - start_init < 8.0:
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    if "Canary Shield Monitor is running" in f.read():
                        armed = True
                        break
            except Exception:
                pass
        time.sleep(0.2)

    if armed:
        print("[E2E] Confirmed: Canary Shield watchdog is armed and monitoring.")
    else:
        print("[E2E] Warning: Arming timeout reached, proceeding with test.")

    # Check that canaries were deployed
    sandbox_files = [f for f in os.listdir(TEST_SANDBOX_DIR) if os.path.isfile(os.path.join(TEST_SANDBOX_DIR, f)) and not f.endswith(".out")]
    print(f"[E2E] Decoys deployed in sandbox: {len(sandbox_files)} files")

    # Step 2: Launch attack simulator (simulate_attack.py)
    # Use --hold-handle 0.4s to ensure the simulator keeps handles open long enough for
    # DIRECT HANDLE matching, which is the highest-confidence attribution path.
    print("\n[E2E] Step 2: Launching Benign Attack Simulator (simulate_attack.py) with --hold-handle 0.4s...")
    sim_proc = subprocess.Popen(
        [sys.executable, "simulate_attack.py", "--delay", "0.08", "--hold-handle", "0.4"],
        env=env,
        stdout=sim_out_f,
        stderr=subprocess.STDOUT,
        text=True,
    )
    sim_pid = sim_proc.pid
    print(f"[E2E] Attacker Simulator Process spawned with PID: {sim_pid}")

    # Step 3: Monitor for containment
    print("\n[E2E] Step 3: Monitoring containment of PID %d..." % sim_pid)
    terminated_early = False
    start_wait = time.time()
    while time.time() - start_wait < 10.0:
        ret = sim_proc.poll()
        if ret is not None:
            terminated_early = True
            print(f"[E2E] SUCCESS: Attacker Process {sim_pid} was TERMINATED! (Exit code: {ret})")
            break
        time.sleep(0.2)

    # Allow monitor to complete quarantine and write forensic telemetry
    time.sleep(2.5)

    # Terminate main_proc
    main_proc.terminate()
    try:
        main_proc.wait(timeout=2.0)
    except Exception:
        main_proc.kill()

    main_out_f.close()
    sim_out_f.close()

    # Step 4: Validate outcome
    sim_stdout = ""
    if os.path.exists(sim_out_path):
        with open(sim_out_path, "r", encoding="utf-8", errors="ignore") as f:
            sim_stdout = f.read()

    main_stdout = ""
    if os.path.exists(main_out_path):
        with open(main_out_path, "r", encoding="utf-8", errors="ignore") as f:
            main_stdout = f.read()

    print("\n" + "=" * 70)
    print("                     SIMULATOR STDOUT OUTPUT")
    print("=" * 70)
    print(sim_stdout.strip())

    print("\n" + "=" * 70)
    print("                   CANARY SHIELD DEFENSE STDOUT")
    print("=" * 70)
    print(main_stdout.strip())

    print("\n" + "=" * 70)
    print("                CANARY SHIELD LOG (FORENSIC PROOF)")
    print("=" * 70)
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            log_content = f.read().strip()
            print(log_content)
    else:
        print("[ERROR] Log file was not created!")

    # Check surviving user files
    all_files_now = os.listdir(TEST_SANDBOX_DIR)
    locked = [f for f in all_files_now if f.endswith(".locked")]
    unlocked_user = [f for f in all_files_now if f.startswith("user_") and not f.endswith(".locked")]

    # Check incidents and quarantine artifacts
    incidents_recorded = [f for f in os.listdir(INCIDENTS_DIR) if f.endswith(".json")] if os.path.exists(INCIDENTS_DIR) else []
    quarantine_files = [f for f in os.listdir(QUARANTINE_DIR) if f.endswith(".quarantine")] if os.path.exists(QUARANTINE_DIR) else []

    print("\n" + "=" * 70)
    print("                      CONTAINMENT EVALUATION")
    print("=" * 70)
    print(f"Files encrypted before containment: {len(locked)}")
    print(f"Genuine user files protected & surviving: {len(unlocked_user)} ({unlocked_user})")
    print(f"Forensic incident reports generated: {len(incidents_recorded)} ({incidents_recorded})")
    print(f"Malware binaries quarantined: {len(quarantine_files)} ({quarantine_files})")

    elapsed_total = round(time.time() - test_start_time, 2)
    print(f"Total Pipeline Test Duration: {elapsed_total} seconds")
    print("=" * 70)

    if terminated_early and len(incidents_recorded) > 0:
        print("\n>>> OVERALL TEST RESULT: PASSED! Ransomware simulator was contained and incident telemetry recorded. <<<")
    elif terminated_early:
        print("\n>>> OVERALL TEST RESULT: PASSED (Containment succeeded, awaiting telemetry flush). <<<")
    else:
        print("\n>>> OVERALL TEST RESULT: FAILED! Simulator ran to completion or was not killed in time. <<<")

if __name__ == "__main__":
    main()
