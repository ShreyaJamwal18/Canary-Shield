"""
Canary Shield — Enterprise Containment Module.

Safely and aggressively neutralizes identified ransomware processes via psutil.
Equipped with real-world enterprise containment capabilities:
1. Process Suspension (proc.suspend()): Immediately arrests all worker
   threads in the target process before further encryption I/O can be queued.
2. Full Process Tree Neutralization (proc.children(recursive=True)): Terminates all
   helper scripts, worker processes, and child encryptors spawned by the parent.
3. Cryptographic Malware Quarantining: Extracts SHA-256 hash and isolates the binary.
4. Desktop Threat Alerting: Native Windows notifications for operators.
5. Forensic Telemetry Generation: Produces structured JSON and SOC HTML reports.

Enforces Hard Rule 2 (production allowlist enforcement) and Hard Rule 3 (fail-safe error handling):
- Checks allowlist first: refuses to kill any protected process.
- Fails safe on any uncertainty, ambiguity, or exception — never lets an unhandled error reach the kill call.
- Windows-specific note: proc.kill() invokes TerminateProcess on Windows.
  Elevated privileges (Administrator) are required to terminate arbitrary processes.
"""

import os
import time
import logging
import threading
from typing import Optional, List
import psutil

from config import (
    PRODUCTION_PROCESS_ALLOWLIST,
    get_active_allowlist,
    is_test_mode,
    INSTANT_THREAD_FREEZE,
    TERMINATE_PROCESS_TREE,
    QUARANTINE_MALWARE,
)
from incident_manager import record_incident
from notify import send_threat_alert

logger = logging.getLogger("canary_shield.contain")


def get_protected_pids() -> set[int]:
    """Return self PID and all ancestor PIDs to prevent self/parent termination or suspension."""
    protected = {os.getpid()}
    try:
        curr = psutil.Process()
        for parent in curr.parents():
            protected.add(parent.pid)
    except Exception:
        pass
    return protected


def is_safe_to_kill(pid: int, proc_name: str) -> tuple[bool, str]:
    """
    Evaluate if a process is safe to terminate according to safety rules and allowlists.
    Fails closed: returns (False, reason) if there is any doubt.
    """
    clean_name = proc_name.lower().strip()
    active_allowlist = {name.lower().strip() for name in get_active_allowlist()}
    protected_pids = get_protected_pids()

    # Check 1: Prohibit killing self (Canary Shield process) or any of its ancestors
    if pid in protected_pids:
        logger.warning(
            "Protected PID matched for termination/suspension: PID %d (%s) is in self/ancestor chain %s — containment blocked.",
            pid, clean_name, protected_pids
        )
        if pid == os.getpid():
            return False, "Target PID matches Canary Shield process (self)"
        return False, f"Target PID {pid} is an ancestor of Canary Shield process"

    # Check 2: Prohibit killing OS Kernel / System Idle / Core Windows init
    if pid <= 4:
        return False, f"Target PID {pid} is Windows System/Kernel process"

    # Check 3: Active allowlist check
    if clean_name in active_allowlist:
        mode_str = "TEST_MODE" if is_test_mode() else "PRODUCTION"
        return False, f"Process '{clean_name}' (PID {pid}) is protected by {mode_str} allowlist"

    # Check 4: Even in test mode, double-check that critical OS processes are NEVER killed
    # Hard Rule 2 sanity check: explorer.exe, svchost.exe, lsass.exe must NEVER be killed
    critical_core_os = {
        "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
        "services.exe", "dwm.exe", "winlogon.exe", "smss.exe", "wininit.exe"
    }
    if clean_name in critical_core_os:
        return False, f"Critical OS process '{clean_name}' cannot be killed under any mode"

    return True, "Safe to terminate"


def kill_process(
    pid: Optional[int],
    confidence: str = "HIGH",
    method: str = "direct_handle",
    target_path: Optional[str] = None,
    latency_ms: Optional[float] = None,
    t_event_received: Optional[float] = None,
    t_attr_start: Optional[float] = None,
    t_attr_end: Optional[float] = None,
) -> bool:
    """
    Terminate the offending process with the given PID using enterprise containment.
    
    Hard Rule 3 (Fail-Safe):
    On ANY uncertainty, ambiguity, allowlist match, or exception,
    log the event cleanly and do NOT kill.

    Args:
        pid: Process ID to terminate.
        confidence: Attribution confidence ('HIGH', 'MEDIUM', 'LOW', 'NONE').
        method: Attribution method used ('direct_handle', 'directory_heuristic', 'none').
        target_path: Optional canary path that triggered the tripwire.
        latency_ms: Optional latency measured in ms.

    Returns:
        True if the process was confirmed terminated, False otherwise.
    """
    # Fail-safe Check 1: Validate PID presence and type
    if pid is None or not isinstance(pid, int):
        logger.error("Containment aborted: Invalid PID provided (PID=%s)", pid)
        return False

    # Fail-safe Check 2: Reject attribution with zero confidence
    if confidence.upper() == "NONE":
        logger.error("Containment aborted: Attribution confidence is NONE for PID %s", pid)
        return False

    # Fail-safe Check 3: Process inspection wrapped in exception safety
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
    except psutil.NoSuchProcess:
        logger.warning("Containment skipped: PID %d already exited prior to termination.", pid)
        return False
    except (psutil.AccessDenied, psutil.ZombieProcess) as exc:
        logger.error("Containment aborted: Cannot inspect PID %d (%s) — failing safe.", pid, exc)
        return False
    except Exception as exc:
        logger.critical("Unexpected error inspecting PID %d: %s — failing safe.", pid, exc)
        return False

    # Fail-safe Check 4: Strict allowlist and safety rules (HARD RULE 2)
    safe, reason = is_safe_to_kill(pid, proc_name)
    if not safe:
        logger.error("CONTAINMENT REFUSED: %s. Action blocked.", reason)
        return False

    # Step 1: Real-World Process Suspension (Thread Freeze)
    # Freezes all running threads instantly to prevent further file encryption syscalls
    t_freeze_done = None
    if INSTANT_THREAD_FREEZE:
        try:
            proc.suspend()
            t_freeze_done = time.time()
            logger.info("CONTAINMENT FREEZE: Suspended threads of PID %d (%s).", pid, proc_name)
        except Exception as exc:
            logger.debug("Could not suspend PID %d: %s", pid, exc)
    if t_freeze_done is None:
        t_freeze_done = time.time()

    # Step 2: Enumerate Process Tree (Children)
    children: List[psutil.Process] = []
    tree_pids = [pid]
    if TERMINATE_PROCESS_TREE:
        try:
            children = proc.children(recursive=True)
            for ch in children:
                try:
                    if ch.pid in protected_pids:
                        logger.warning(
                            "Protected PID %d matched in child process tree — excluded from containment.",
                            ch.pid
                        )
                        continue
                    tree_pids.append(ch.pid)
                    if INSTANT_THREAD_FREEZE:
                        ch.suspend()
                except Exception:
                    pass
            if children:
                logger.warning(
                    "Identified %d child worker processes for PID %d: PIDs=%s",
                    len(children), pid, [c.pid for c in children]
                )
        except Exception as exc:
            logger.debug("Could not enumerate process tree for PID %d: %s", pid, exc)

    # Step 3: Forensic Metadata Extraction (Before termination cleans up handles)
    proc_exe = None
    proc_cmdline = None
    proc_user = None
    try:
        proc_exe = proc.exe()
    except Exception:
        pass
    try:
        cmd = proc.cmdline()
        proc_cmdline = " ".join(cmd) if cmd else None
    except Exception:
        pass
    try:
        proc_user = proc.username()
    except Exception:
        pass

    # Step 4: Execute Termination Wrapped in Fail-Safe Try-Except (HARD RULE 3)
    try:
        logger.warning(
            "CONTAINMENT ENGAGED: Terminating PID %d (%s) | Method=%s | Confidence=%s",
            pid, proc_name, method, confidence
        )

        # Terminate all child worker processes first
        for ch in children:
            if ch.pid in protected_pids:
                logger.warning("Protected PID %d matched in child termination list — excluded.", ch.pid)
                continue
            try:
                ch.kill()
            except Exception:
                pass

        # Terminate primary offending process (TerminateProcess Win32 API)
        proc.kill()

        # Confirm termination
        terminated = False
        try:
            gone, alive = psutil.wait_procs([proc] + children, timeout=2.0)
            if proc in gone or not proc.is_running():
                terminated = True
        except Exception:
            if not proc.is_running():
                terminated = True

        if terminated:
            t_kill_done = time.time()
            t_evt = t_event_received if t_event_received is not None else (t_attr_start or t_freeze_done)
            t_as = t_attr_start or t_evt
            t_ae = t_attr_end or t_as
            total_contain_ms = (t_kill_done - t_evt) * 1000.0

            logger.info(
                "TIMING_BREAKDOWN: event_received=%.4f | attr_start=%.4f | attr_end=%.4f | freeze_done=%.4f | kill_done=%.4f | total_contain_ms=%.2f",
                t_evt, t_as, t_ae, t_freeze_done, t_kill_done, total_contain_ms
            )
            print(
                f"[TIMING BREAKDOWN] Event: {t_evt:.4f} | Attr Start: {t_as:.4f} | Attr End: {t_ae:.4f} | "
                f"Freeze Done: {t_freeze_done:.4f} | Kill Done: {t_kill_done:.4f} | Total Containment: {total_contain_ms:.2f} ms"
            )
            logger.critical("CONTAINMENT SUCCESS: Successfully terminated PID %d (%s).", pid, proc_name)

            # Step 5 & 6: Async Background Forensics, Quarantine & Alert Dispatch
            # Runs asynchronously after kill confirmation so it does not delay the watchdog thread
            def _async_post_containment():
                try:
                    record_incident(
                        pid=pid,
                        proc_name=proc_name,
                        confidence=confidence,
                        method=method,
                        latency_ms=latency_ms or 0.0,
                        target_path=target_path or "Unknown",
                        proc_exe=proc_exe,
                        cmdline=proc_cmdline,
                        username=proc_user,
                        process_tree_pids=tree_pids,
                    )
                except Exception as exc:
                    logger.error("Could not record incident telemetry: %s", exc)

                try:
                    send_threat_alert(
                        pid=pid,
                        proc_name=proc_name,
                        latency_ms=latency_ms or 0.0,
                        confidence=confidence,
                        method=method,
                    )
                except Exception as exc:
                    logger.debug("Desktop alert dispatch failed: %s", exc)

            threading.Thread(target=_async_post_containment, name="AsyncPostContainment", daemon=True).start()
            return True
        else:
            logger.error("Containment timeout: PID %d (%s) still alive after termination attempt.", pid, proc_name)
            return False

    except psutil.AccessDenied:
        logger.critical(
            "CONTAINMENT FAILED: AccessDenied terminating PID %d (%s). "
            "Canary Shield must be executed with Administrator privileges on Windows.",
            pid, proc_name
        )
        return False
    except psutil.NoSuchProcess:
        logger.info("PID %d (%s) exited during termination.", pid, proc_name)
        return True
    except Exception as exc:
        # HARD RULE 3: Never let an unhandled error reach the kill call or crash the monitor
        logger.critical("Unexpected exception during containment of PID %d (%s): %s", pid, proc_name, exc)
        return False
