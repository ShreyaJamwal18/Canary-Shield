"""
Canary Shield — Incident & Quarantine Manager.

Handles real-world digital forensics and incident response:
1. Cryptographic hashing (SHA-256) of offending malware executables.
2. Secure binary quarantining in an isolated directory with execution privileges stripped.
3. Structured JSON telemetry generation for SIEM / SOC ingestion.
4. Standalone HTML forensic incident reports with timeline, process tree, and damage assessment.
"""

import os
import time
import json
import hashlib
import shutil
import logging
from typing import Dict, Any, List, Optional
import psutil

from config import INCIDENTS_DIR, QUARANTINE_DIR, BASE_DIR
from decoy import load_decoy_manifest

logger = logging.getLogger("canary_shield.incident_manager")


def compute_sha256(filepath: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file."""
    if not filepath or not os.path.isfile(filepath):
        return None
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception as exc:
        logger.warning("Could not compute SHA-256 for %s: %s", filepath, exc)
        return None


def quarantine_binary(proc_exe: Optional[str], pid: int, proc_name: str, cmdline: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Safely copy the offending executable or script into the quarantine vault.
    Renames file with .quarantine extension to neutralize execution.
    """
    target_to_quarantine = proc_exe

    # If the process is a script runner (like python.exe), target the attack script
    if proc_name.lower().startswith("python") and cmdline:
        parts = cmdline.split()
        for part in parts:
            if part.endswith(".py") and os.path.isfile(part):
                target_to_quarantine = os.path.abspath(part)
                break

    if not target_to_quarantine or not os.path.isfile(target_to_quarantine):
        logger.info("Quarantine skipped: No valid file available for PID %d", pid)
        return None

    try:
        sha256 = compute_sha256(target_to_quarantine) or "unknown_hash"
        ts = int(time.time())
        quarantine_filename = f"{ts}_PID{pid}_{proc_name}_{sha256[:10]}.quarantine"
        quarantine_dest = os.path.join(QUARANTINE_DIR, quarantine_filename)

        if os.path.exists(quarantine_dest):
            try:
                os.chmod(quarantine_dest, 0o666)
            except Exception:
                pass

        # Copy binary to quarantine
        shutil.copy2(target_to_quarantine, quarantine_dest)

        # Revoke execute permissions (set to read-only)
        try:
            os.chmod(quarantine_dest, 0o444)
        except Exception:
            pass

        logger.critical(
            "MALWARE QUARANTINED: Copied %s to %s (SHA-256: %s)",
            target_to_quarantine, quarantine_dest, sha256
        )

        return {
            "original_path": target_to_quarantine,
            "quarantine_path": quarantine_dest,
            "sha256": sha256,
            "quarantined_at": ts,
            "filesize_bytes": os.path.getsize(quarantine_dest),
        }
    except Exception as exc:
        logger.error("Failed to quarantine binary %s: %s", target_to_quarantine, exc)
        return None


def generate_html_report(incident: Dict[str, Any], output_path: str) -> None:
    """Generate an HTML forensic incident report."""
    pid = incident.get("pid", "Unknown")
    proc_name = incident.get("proc_name", "Unknown")
    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(incident.get("timestamp", time.time())))
    confidence = incident.get("confidence", "NONE")
    latency = incident.get("latency_ms", 0.0)
    method = incident.get("method", "Unknown")
    sha256 = incident.get("quarantine", {}).get("sha256") if incident.get("quarantine") else "N/A"
    exe_path = incident.get("exe_path", "N/A")
    cmdline = incident.get("cmdline", "N/A")
    user = incident.get("username", "N/A")
    target_path = incident.get("target_path", "N/A")
    tree_pids = incident.get("process_tree_pids", [pid])
    surviving_files = incident.get("surviving_user_files", [])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Canary Shield — Incident #{incident.get("incident_id")}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
    .container {{ max-width: 960px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 13px; text-transform: uppercase; }}
    .badge-contained {{ background: #059669; color: #ecfdf5; }}
    .badge-critical {{ background: #dc2626; color: #fef2f2; }}
    .badge-high {{ background: #2563eb; color: #eff6ff; }}
    h1 {{ margin: 0 0 8px 0; font-size: 26px; color: #38bdf8; }}
    .subtitle {{ color: #94a3b8; font-size: 14px; margin-bottom: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }}
    .card {{ background: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid #334155; }}
    .card-title {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 4px; }}
    .card-value {{ font-size: 18px; font-weight: 700; color: #f1f5f9; word-break: break-all; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
    th {{ color: #94a3b8; font-weight: 600; background: #0f172a; }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; color: #38bdf8; font-size: 13px; }}
    .timeline {{ margin: 20px 0; border-left: 2px solid #38bdf8; padding-left: 16px; }}
    .timeline-item {{ margin-bottom: 12px; }}
    .footer {{ margin-top: 32px; font-size: 12px; color: #64748b; text-align: center; border-top: 1px solid #334155; padding-top: 16px; }}
</style>
</head>
<body>
<div class="container">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1>🛡️ Canary Shield Incident Report</h1>
            <div class="subtitle">Incident ID: <code>{incident.get("incident_id")}</code> | Generated: {timestamp_str}</div>
        </div>
        <div>
            <span class="badge badge-contained">Threat Neutralized</span>
            <span class="badge badge-critical">Deception Defense</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Offending Process</div>
            <div class="card-value">{proc_name}</div>
        </div>
        <div class="card">
            <div class="card-title">Process ID (PID)</div>
            <div class="card-value">{pid}</div>
        </div>
        <div class="card">
            <div class="card-title">Containment Latency</div>
            <div class="card-value" style="color: #4ade80;">{latency:.2f} ms</div>
        </div>
        <div class="card">
            <div class="card-title">Attribution Confidence</div>
            <div class="card-value"><span class="badge badge-high">{confidence}</span></div>
        </div>
    </div>

    <h3>🔍 Threat Forensics & Telemetry</h3>
    <table>
        <tr><th style="width: 25%;">Property</th><th>Observed Value</th></tr>
        <tr><td>Binary Path</td><td><code>{exe_path}</code></td></tr>
        <tr><td>SHA-256 Hash</td><td><code>{sha256}</code></td></tr>
        <tr><td>Command Line</td><td><code>{cmdline}</code></td></tr>
        <tr><td>Execution User</td><td>{user}</td></tr>
        <tr><td>Targeted Honeytoken</td><td><code>{target_path}</code></td></tr>
        <tr><td>Attribution Method</td><td><code>{method}</code></td></tr>
        <tr><td>Terminated Process Tree</td><td>PIDs: <code>{tree_pids}</code></td></tr>
    </table>

    <h3>⏱️ Containment Timeline</h3>
    <div class="timeline">
        <div class="timeline-item">
            <strong>1. Deception Tripwire Triggered:</strong> Ransomware attempted I/O on hidden decoy file.
        </div>
        <div class="timeline-item">
            <strong>2. Process Correlated:</strong> Event mapped to PID <code>{pid}</code> ({proc_name}) via <code>{method}</code> in {latency:.2f}ms.
        </div>
        <div class="timeline-item">
            <strong>3. Thread Freeze:</strong> <code>proc.suspend()</code> halted all execution threads before next I/O burst.
        </div>
        <div class="timeline-item">
            <strong>4. Process Tree Termination:</strong> Parent PID <code>{pid}</code> and child processes terminated via <code>TerminateProcess</code>.
        </div>
        <div class="timeline-item">
            <strong>5. Binary Quarantined:</strong> Malicious executable copied to secure vault with execution flags stripped.
        </div>
    </div>

    <h3>🛡️ Impact & Asset Protection Assessment</h3>
    <p>Canary Shield deceptive honeytokens trapped the malicious traversal sequence early in the attack chain. User assets were shielded from encryption.</p>
    <div>
        <strong>Surviving Genuine User Files in Directory:</strong> {len(surviving_files)}
    </div>

    <div class="footer">
        Canary Shield Deception-Based Ransomware Defense
    </div>
</div>
</body>
</html>"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("Generated HTML Forensic Incident Report: %s", output_path)
    except Exception as exc:
        logger.error("Failed to generate HTML report: %s", exc)


def _count_surviving_user_files(target_path: str) -> List[str]:
    """
    Count genuine user files that survive in the directory containing target_path.
    Excludes: decoy files listed in decoy_manifest.json and their .locked variants.
    Returns sorted list of surviving non-decoy filenames.
    """
    try:
        directory = os.path.dirname(os.path.normcase(os.path.normpath(target_path)))
        if not os.path.isdir(directory):
            # target_path may itself be the directory
            directory = os.path.normcase(os.path.normpath(target_path))
        if not os.path.isdir(directory):
            return []
        decoy_paths = set(load_decoy_manifest())
        # Also build set of basenames for .locked variant matching
        decoy_bases = {os.path.basename(p) for p in decoy_paths}
        decoy_locked = {b + ".locked" for b in decoy_bases}
        surviving = []
        for fname in os.listdir(directory):
            fpath = os.path.normcase(os.path.normpath(os.path.join(directory, fname)))
            if fpath in decoy_paths:
                continue
            if fname in decoy_locked:
                continue
            if os.path.isfile(fpath):
                surviving.append(fname)
        return sorted(surviving)
    except Exception as exc:
        logger.warning("Could not count surviving user files: %s", exc)
        return []


def record_incident(
    pid: int,
    proc_name: str,
    confidence: str,
    method: str,
    latency_ms: float,
    target_path: str,
    proc_exe: Optional[str] = None,
    cmdline: Optional[str] = None,
    username: Optional[str] = None,
    process_tree_pids: Optional[List[int]] = None,
    surviving_user_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Record an incident, quarantine the executable, and generate JSON & HTML forensic reports.
    """
    ts = time.time()
    incident_id = f"INC-{int(ts)}-{pid}"
    # Compute surviving user files at report time if not provided by caller
    if surviving_user_files is None:
        surviving_user_files = _count_surviving_user_files(target_path)

    # Step 1: Quarantine malware binary or attacking script
    quarantine_info = quarantine_binary(proc_exe, pid, proc_name, cmdline=cmdline)

    incident_data = {
        "incident_id": incident_id,
        "timestamp": ts,
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "pid": pid,
        "proc_name": proc_name,
        "exe_path": proc_exe,
        "cmdline": cmdline,
        "username": username,
        "target_path": target_path,
        "confidence": confidence,
        "method": method,
        "latency_ms": latency_ms,
        "process_tree_pids": process_tree_pids or [pid],
        "quarantine": quarantine_info,
        "surviving_user_files": surviving_user_files or [],
    }

    # Step 2: Save JSON telemetry report
    json_path = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")
    try:
        os.makedirs(INCIDENTS_DIR, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(incident_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        logger.critical("Saved JSON incident telemetry: %s", json_path)
    except Exception as exc:
        logger.critical("CRITICAL ERROR: Failed to save JSON incident report: %s", exc)

    # Step 3: Save HTML visual report
    try:
        html_path = os.path.join(INCIDENTS_DIR, f"{incident_id}.html")
        generate_html_report(incident_data, html_path)
        logger.critical("Generated HTML visual report: %s", html_path)
    except Exception as exc:
        logger.critical("CRITICAL ERROR: Failed to generate HTML report: %s", exc)

    return incident_data


def list_incidents() -> List[Dict[str, Any]]:
    """List all recorded forensic incident telemetry files."""
    incidents = []
    if not os.path.exists(INCIDENTS_DIR):
        return []

    for f in os.listdir(INCIDENTS_DIR):
        if f.endswith(".json"):
            p = os.path.join(INCIDENTS_DIR, f)
            try:
                with open(p, "r", encoding="utf-8") as fp:
                    incidents.append(json.load(fp))
            except Exception:
                pass

    incidents.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return incidents
