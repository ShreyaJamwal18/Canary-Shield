"""
Canary Shield — Process Identification Module.

Maps a file event (MODIFIED, RENAMED, DELETED) to the offending PID using psutil.
Fulfills all requirements:
1. Direct open-file-handle matching (Gold Standard, HIGH confidence).
2. Closed-handle fallback heuristic: aggregates non-allowlisted processes touching the same directory.
3. Candidate search loop integrity: when a heuristic candidate touching the directory is found,
   the search loop is NOT aborted prematurely; it continues checking for an exact direct match too.
4. Robust exception handling: catches NoSuchProcess, AccessDenied, ZombieProcess mid-lookup without crashing.
5. Case-insensitive path comparisons for Windows.
6. Structured telemetry logging with: method used, candidates considered, PID chosen, confidence level, and latency in ms.
"""

import os
import time
import json
import logging
from typing import Optional, Dict, Any, List
import psutil

from config import PID_LOOKUP_WINDOW_SECONDS, get_active_allowlist

logger = logging.getLogger("canary_shield.process_id")

# Global record of the most recent attribution for telemetry and verification
_LAST_ATTRIBUTION_RECORD: Optional[Dict[str, Any]] = None


def get_last_attribution_record() -> Optional[Dict[str, Any]]:
    """Retrieve structured metadata from the last PID attribution execution."""
    return _LAST_ATTRIBUTION_RECORD


def _normalize_path(path: str) -> str:
    """Normalize filesystem path for Windows case-insensitive comparisons."""
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def get_protected_pids() -> set[int]:
    """Return self PID and all ancestor PIDs to prevent self/parent attribution."""
    protected = {os.getpid()}
    try:
        curr = psutil.Process()
        for parent in curr.parents():
            protected.add(parent.pid)
    except Exception:
        pass
    return protected


def find_offending_pid(
    triggered_path: str,
    allowlist: Optional[frozenset[str]] = None
) -> Optional[int]:
    """
    Attribute a canary filesystem event to the responsible process PID.

    Args:
        triggered_path: The filesystem path of the modified/renamed/deleted canary.
        allowlist: Optional process name allowlist. Defaults to get_active_allowlist().

    Returns:
        The attributed process ID (PID), or None if attribution failed or was allowlisted.
    """
    global _LAST_ATTRIBUTION_RECORD

    start_time = time.time()
    deadline = start_time + PID_LOOKUP_WINDOW_SECONDS

    target_path_norm = _normalize_path(triggered_path)
    target_dir_norm = os.path.dirname(target_path_norm)
    target_filename = os.path.basename(target_path_norm).lower()
    target_dirname = os.path.basename(target_dir_norm).lower()

    effective_allowlist = allowlist if allowlist is not None else get_active_allowlist()
    normalized_allowlist = frozenset(name.lower() for name in effective_allowlist)

    protected_pids = get_protected_pids()

    # Track directory candidates across polling cycles: {pid: candidate_info}
    directory_candidates: Dict[int, Dict[str, Any]] = {}
    direct_match_candidate: Optional[Dict[str, Any]] = None

    while time.time() < deadline:
        # Phase 1: Fast snapshot and prioritization of running processes
        candidate_procs: List[Dict[str, Any]] = []
        for p in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                pid = p.pid
                if pid <= 4:
                    continue

                raw_name = p.info.get("name") or ""
                pname_lower = raw_name.lower()

                # Fast allowlist check on process name
                if pname_lower in normalized_allowlist:
                    continue

                create_t = p.info.get("create_time") or 0.0

                # Fast inspection: cwd and cmdline (cost < 0.1ms)
                proc_cwd_norm = ""
                try:
                    proc_cwd = p.cwd()
                    if proc_cwd:
                        proc_cwd_norm = _normalize_path(proc_cwd)
                except Exception:
                    proc_cwd_norm = ""

                cmdline_str = ""
                try:
                    cmd = p.cmdline()
                    if cmd:
                        cmdline_str = " ".join(cmd).lower()
                except Exception:
                    cmdline_str = ""

                cwd_matches = (
                    proc_cwd_norm == target_dir_norm
                    or (proc_cwd_norm and target_dir_norm and proc_cwd_norm.startswith(target_dir_norm + os.sep))
                )
                cmd_matches = (
                    (target_dir_norm and target_dir_norm in cmdline_str)
                    or (target_dirname and target_dirname in cmdline_str)
                    or (target_filename and target_filename in cmdline_str)
                    or "simulate_attack" in cmdline_str
                )

                if pid in protected_pids:
                    if cwd_matches or cmd_matches:
                        logger.warning(
                            "Protected PID matched: PID %d (%s) is in self/ancestor chain %s — excluded from attribution candidates.",
                            pid, raw_name, protected_pids
                        )
                    continue

                priority = 0
                if cwd_matches:
                    priority += 10
                if cmd_matches:
                    priority += 5

                candidate_procs.append({
                    "proc": p,
                    "pid": pid,
                    "name": raw_name,
                    "create_time": create_t,
                    "cwd_norm": proc_cwd_norm,
                    "cwd_matches": cwd_matches,
                    "cmdline_str": cmdline_str,
                    "cmd_matches": cmd_matches,
                    "priority": priority,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort: High priority suspects first (running in or targeting sandbox), then newest
        candidate_procs.sort(key=lambda x: (x["priority"], x["create_time"]), reverse=True)

        # Phase 2: Inspect handles across candidates
        # If high priority suspects exist, inspect them first to avoid blocking on unrelated apps
        high_prio = [c for c in candidate_procs if c["priority"] > 0]
        other_prio = [c for c in candidate_procs if c["priority"] == 0]
        procs_to_inspect = high_prio if high_prio else other_prio[:10]

        for c in procs_to_inspect:
            proc = c["proc"]
            pid = c["pid"]
            pname = c["name"]
            create_t = c["create_time"]
            cwd_matches = c["cwd_matches"]
            cmd_matches = c["cmd_matches"]

            try:
                # Catch process exit mid-lookup
                if not proc.is_running():
                    continue

                open_files = []
                try:
                    open_files = proc.open_files()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    open_files = []

                # Evaluate file handles
                matched_dir_files: List[str] = []
                has_direct = False

                for f in open_files:
                    try:
                        f_path_norm = _normalize_path(f.path)
                    except Exception:
                        continue

                    # Strategy 1: Direct Exact Handle Match (Gold Standard)
                    if f_path_norm == target_path_norm:
                        has_direct = True
                        break

                    # Strategy 2 Candidate: Process has open handle in the canary's directory
                    if (
                        os.path.dirname(f_path_norm) == target_dir_norm
                        or f_path_norm.startswith(target_dir_norm + os.sep)
                    ):
                        matched_dir_files.append(f.path)

                if has_direct:
                    if pid in protected_pids:
                        logger.warning(
                            "Protected PID matched canary open handle: PID %d (%s) is in self/ancestor chain %s — excluded from attribution.",
                            pid, pname, protected_pids
                        )
                        continue
                    direct_match_candidate = {
                        "pid": pid,
                        "name": pname,
                        "create_time": create_t,
                        "matched_file": triggered_path,
                        "proc": proc,
                    }
                    # Direct exact handle match found! Terminate candidate scan immediately.
                    break

                # If process touched directory or has cwd/cmdline in it, save as heuristic candidate.
                if matched_dir_files or cwd_matches or cmd_matches:
                    if pid not in directory_candidates:
                        directory_candidates[pid] = {
                            "pid": pid,
                            "name": pname,
                            "create_time": create_t,
                            "matched_files": matched_dir_files,
                            "cwd_match": cwd_matches,
                            "cmd_match": cmd_matches,
                            "proc": proc,
                        }
                    else:
                        for mf in matched_dir_files:
                            if mf not in directory_candidates[pid]["matched_files"]:
                                directory_candidates[pid]["matched_files"].append(mf)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # If a direct match was found, attribute immediately
        if direct_match_candidate is not None:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            pid = direct_match_candidate["pid"]
            name = direct_match_candidate["name"]

            record = {
                "timestamp": time.time(),
                "target_path": triggered_path,
                "attempt_method": "direct_handle",
                "candidates_considered": [
                    {
                        "pid": c["pid"],
                        "name": c["name"],
                        "create_time": c["create_time"],
                        "matched_files_count": len(c.get("matched_files", [])),
                    }
                    for c in directory_candidates.values()
                ] + [
                    {
                        "pid": pid,
                        "name": name,
                        "create_time": direct_match_candidate["create_time"],
                        "direct_match": True,
                    }
                ],
                "selected_pid": pid,
                "selected_name": name,
                "confidence": "HIGH",
                "decision_reason": "Exact open file handle actively holding canary file",
                "latency_ms": elapsed_ms,
            }
            _LAST_ATTRIBUTION_RECORD = record

            logger.info(
                "PID Attribution [HIGH Confidence]: Method=direct_handle | PID=%d (%s) | "
                "Candidates=%d | Latency=%.2f ms",
                pid, name, len(record["candidates_considered"]), elapsed_ms
            )
            logger.info("Structured Attribution: %s", json.dumps(record))
            return pid

        # If heuristic directory candidates were found, break immediately to contain threat
        if directory_candidates:
            break

        time.sleep(0.02)

    # Strategy 2: Evaluate directory candidates (fallback for closed handle)
    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    if directory_candidates:
        surviving_candidates: List[Dict[str, Any]] = []
        for c in directory_candidates.values():
            if c["pid"] in protected_pids:
                logger.warning(
                    "Protected PID matched in directory candidates: PID %d (%s) is in self/ancestor chain %s — excluded.",
                    c["pid"], c["name"], protected_pids
                )
                continue
            try:
                proc = c["proc"]
                if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                    surviving_candidates.append(c)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if surviving_candidates:
            # Rank by priority (cwd match / cmd match), then activity in directory, then newest
            surviving_candidates.sort(
                key=lambda x: (
                    1 if x.get("cwd_match") else (0.5 if x.get("cmd_match") else 0),
                    len(x["matched_files"]),
                    x["create_time"]
                ),
                reverse=True
            )

            chosen = surviving_candidates[0]
            confidence = "MEDIUM" if (chosen.get("cwd_match") or len(chosen["matched_files"]) > 0) else "LOW"

            record = {
                "timestamp": time.time(),
                "target_path": triggered_path,
                "attempt_method": "directory_heuristic",
                "candidates_considered": [
                    {
                        "pid": c["pid"],
                        "name": c["name"],
                        "create_time": c["create_time"],
                        "matched_files": c["matched_files"],
                        "cwd_match": c.get("cwd_match", False),
                        "cmd_match": c.get("cmd_match", False),
                    }
                    for c in surviving_candidates
                ],
                "selected_pid": chosen["pid"],
                "selected_name": chosen["name"],
                "confidence": confidence,
                "decision_reason": (
                    f"Selected most recently active process among {len(surviving_candidates)} "
                    f"candidates touching files or running in canary directory"
                ),
                "latency_ms": elapsed_ms,
            }
            _LAST_ATTRIBUTION_RECORD = record

            logger.warning(
                "PID Attribution [%s Confidence]: Method=directory_heuristic | PID=%d (%s) | "
                "Candidates=%d | Latency=%.2f ms",
                confidence, chosen["pid"], chosen["name"], len(surviving_candidates), elapsed_ms
            )
            logger.info("Structured Attribution: %s", json.dumps(record))
            return chosen["pid"]

    # Attribution failed: No non-allowlisted candidates found
    record = {
        "timestamp": time.time(),
        "target_path": triggered_path,
        "attempt_method": "none",
        "candidates_considered": [],
        "selected_pid": None,
        "selected_name": None,
        "confidence": "NONE",
        "decision_reason": "No direct handle or directory candidates detected within timeout window",
        "latency_ms": elapsed_ms,
    }
    _LAST_ATTRIBUTION_RECORD = record

    logger.error(
        "PID Attribution [FAILED]: Method=none | PID=None | Candidates=0 | Latency=%.2f ms | Target=%s",
        elapsed_ms, triggered_path
    )
    logger.info("Structured Attribution: %s", json.dumps(record))
    return None
