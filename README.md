# Canary Shield — Deception-Based Ransomware Mitigation

**Engineering Capstone Project**  
*An active cyber-defense framework that protects endpoints against novel ransomware using filesystem honeytokens, real-time event telemetry, and rapid process containment.*

---

## Abstract

Traditional endpoint protection platforms (EPP) and antivirus tools rely primarily on signature-based detection and known threat heuristics. Consequently, novel ransomware campaigns (which employ custom packing, polymorphism, or newly weaponized encryption techniques) readily bypass perimeter defenses and begin encrypting user assets unhindered.

**Canary Shield** counters this asymmetry using **active deception**:
1. **Decoy Placement**: It silently plants realistic decoy files ("canaries" or honeytokens) disguised as high-value corporate documents (financial audits, payrolls, password vaults) scattered across monitored storage directories.
2. **Tripwire Monitoring**: Leveraging OS-level filesystem event hooks (`watchdog` / Windows `ReadDirectoryChangesW`), Canary Shield continuously monitors canary tripwires. Any modification, rename, or deletion of a decoy trips the defense.
3. **Real-Time PID Attribution**: When a tripwire fires, Canary Shield inspects running processes via `psutil` using a two-stage attribution engine:
   - **Direct Handle Match (Gold Standard)**: Inspects active OS file handles holding the canary open.
   - **Directory Heuristic Fallback**: If the offending process closed the handle rapidly before inspection, aggregates and scores non-allowlisted processes actively manipulating files or running in the canary's directory.
4. **Rapid Process Containment**: Freezing and terminating the identified process (`TerminateProcess` on Windows) before the ransomware can proceed to encrypt genuine user files.

---

## Architecture Overview

The system is modularized into seven core components:

```
                          ┌────────────────────────┐
                          │       config.py        │
                          │   (Settings & Safety)  │
                          └───────────┬────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
     ┌──────────────────┐                          ┌──────────────────┐
     │     decoy.py     │                          │    contain.py    │
     │ (Seeds Canaries) │                          │(Process Killer)  │
     └─────────┬────────┘                          └─────────▲────────┘
               │                                             │
               ▼                                             │
       [test_sandbox]                                        │
    (Decoys + User Files)                                    │
               │                                             │
               ▼                                             │
     ┌──────────────────┐                          ┌─────────┴────────┐
     │    monitor.py    │ ──[Canary Event Trigger]─►│  process_id.py   │
     │(Watchdog Hooks)  │                          │(PID Attribution) │
     └──────────────────┘                          └──────────────────┘
```

### Module Breakdown

| Module | Purpose |
|---|---|
| [`config.py`](file:///c:/Users/91700/Documents/MDC/config.py) | Central configuration: defines monitored directories (strictly dedicated `test_sandbox`), decoy parameters, and process allowlists (`PRODUCTION_PROCESS_ALLOWLIST` & `TEST_PROCESS_ALLOWLIST`). |
| [`decoy.py`](file:///c:/Users/91700/Documents/MDC/decoy.py) | Generates authentic canary files with valid magic headers (`.pdf`, `.docx`, `.xlsx`, `.jpg`), assigns Windows `FILE_ATTRIBUTE_HIDDEN` attributes, and prioritizes alphabetical prefixes (`!_`, `00_`, `~$`) to trap sequential traversals. |
| [`monitor.py`](file:///c:/Users/91700/Documents/MDC/monitor.py) | Hooks OS-level filesystem events with `watchdog`. Performs case-insensitive path normalization and filters out normal user traffic so only canary access triggers alerts. |
| [`process_id.py`](file:///c:/Users/91700/Documents/MDC/process_id.py) | Correlates filesystem events to offending process PIDs. First checks exact open file handles (High confidence); falls back to directory-activity heuristics if handles closed quickly. Logs telemetry in JSON format. |
| [`contain.py`](file:///c:/Users/91700/Documents/MDC/contain.py) | Terminates verified offender PIDs using `proc.kill()`. Strictly enforces production allowlists and fails safe on any uncertainty, ambiguity, or exception. |
| [`main.py`](file:///c:/Users/91700/Documents/MDC/main.py) | Entry point: initializes decoys in the sandbox and launches real-time monitoring. |
| [`app.py`](file:///c:/Users/91700/Documents/MDC/app.py) | Desktop GUI application built with CustomTkinter: provides real-time telemetry, shield ARM/DISARM controls, attack simulator console, and forensic incident log viewer. |
| [`simulate_attack.py`](file:///c:/Users/91700/Documents/MDC/simulate_attack.py) | Benign test harness: seeds mock user files and simulates ransomware I/O patterns (read -> overwrite -> rename to `.locked`) to validate containment. |

---

## Performance & Containment Timing

Empirical measurements revealed that approximately 95% of the original time-to-contain was consumed by process lookup (`psutil.process_iter` cold iteration plus exhaustive `open_files` inspection), rather than the process freeze and termination mechanisms (which together take about 55 ms).

To eliminate this bottleneck, three optimizations were implemented:
1. **Incremental Process Cache**: A background thread polls `psutil.pids()` about every 100 ms and queries full metadata (`name`, `create_time`, `cwd`, `cmdline`) only for newly spawned PIDs. Entries are keyed by `(pid, create_time)` to prevent PID reuse vulnerabilities. If the cache produces zero candidates, attribution immediately falls back to a fresh scan.
2. **Bounded Parallel Handle Inspection**: Process candidates are queried concurrently using a worker pool with a strict 200 ms timeout per batch, preventing a single slow process handle scan from stalling containment.
3. **Asynchronous Forensics**: Malware quarantine copying, SHA-256 hashing, and JSON/HTML incident report generation are dispatched to a post-containment background thread after the kill is confirmed, keeping the critical containment loop completely unblocked.

### Measured Benchmark Results
Across 5 consecutive runs of `run_full_e2e_test.py` in test mode (`CANARY_TEST_MODE=1`):
- **After optimization**: Median time-to-contain was about **260 ms**, with the worst run at about **950 ms** (typically about a quarter of a second, under a second in the worst test run).
- **Before optimization**: Median time-to-contain was about **930 ms**, with the worst run at about **2450 ms**.
- **Blast radius**: Typically **1 decoy** is touched before containment (before optimization: 1 to 4 decoys). In all 5 runs, 100% (5 of 5) of genuine user files survived intact.

*(Note: These figures were measured against the bundled benign simulator in a sandbox on one Windows machine.)*

---

## Installation & Setup

### Prerequisites
- Windows 10/11 (64-bit)
- Python 3.10+
- Administrative (Elevated) privileges (required for Windows handle querying, thread suspension, and process termination)

### Desktop GUI (Recommended)
Canary Shield provides a modern desktop GUI interface built with CustomTkinter:
- **Launch via Desktop Shortcut**: Double-click the **Canary Shield** shortcut on your Desktop.
- **Launch via Batch Script**: Run `CanaryShield.bat` from the MDC project folder.
- *Administrator Access*: Both launch methods will prompt for Windows Administrator elevation (UAC prompt).

### CLI Quick Start
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run Canary Shield in Test Mode (PowerShell)
$env:CANARY_TEST_MODE = "1"
python main.py
```

In a separate elevated terminal:
```powershell
# 3. Trigger simulated benign attack against sandbox
python simulate_attack.py --delay 0.08
```

---

## Safety & Allowlist Architecture (Hard Rules)

1. **Strict Sandbox Isolation**: All Canary Shield operations and attack simulations are restricted strictly to the dedicated `test_sandbox/` directory inside this project repository. Production user directories (`~/Documents`, `~/Desktop`) are blocked by code assertions.
2. **Frozen Production Allowlist**: The production allowlist protects critical Windows core components (`explorer.exe`, `svchost.exe`, `lsass.exe`, `dwm.exe`, `services.exe`, etc.) and system Python runtimes. Testing Python-based attack harnesses is achieved through an explicit `CANARY_TEST_MODE=1` environment flag that only exempts `python.exe` while preserving all OS protections.
3. **Fail-Safe Containment**: On any permission error, unhandled exception, allowlist match, or attribution ambiguity (`confidence: NONE`), Canary Shield logs the anomaly and refuses to terminate the process.
