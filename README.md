# Canary Shield — Deception-Based Zero-Day Ransomware Mitigation

**Engineering Capstone Project**  
*An active cyber-defense framework that protects endpoints against novel zero-day ransomware using filesystem honeytokens, real-time event telemetry, and immediate process containment.*

---

## Abstract

Traditional endpoint protection platforms (EPP) and antivirus tools rely primarily on signature-based detection and known threat heuristics. Consequently, novel "zero-day" ransomware campaigns (which employ custom packing, polymorphism, or newly weaponized encryption techniques) readily bypass perimeter defenses and begin encrypting user assets unhindered.

**Canary Shield** counters this asymmetry using **active deception**:
1. **Decoy Placement**: It silently plants realistic decoy files ("canaries" or honeytokens) disguised as high-value corporate documents (financial audits, payrolls, password vaults) scattered across monitored storage directories.
2. **Tripwire Monitoring**: Leveraging OS-level filesystem event hooks (`watchdog` / Windows `ReadDirectoryChangesW`), Canary Shield continuously monitors canary tripwires. Any modification, rename, or deletion of a decoy trips the defense.
3. **Real-Time PID Attribution**: When a tripwire fires, Canary Shield inspects running processes via `psutil` using a two-stage attribution engine:
   - **Direct Handle Match (Gold Standard)**: Inspects active OS file handles holding the canary open.
   - **Directory Heuristic Fallback**: If the offending process closed the handle rapidly before inspection, aggregates and scores non-allowlisted processes actively manipulating files in the canary's directory.
4. **Instant Containment**: Terminating the identified process (`TerminateProcess` on Windows) before the ransomware can proceed to encrypt genuine user files.

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
| [`simulate_attack.py`](file:///c:/Users/91700/Documents/MDC/simulate_attack.py) | Benign test harness: seeds mock user files and simulates ransomware I/O patterns (read -> overwrite -> rename to `.locked`) to validate containment. |

---

## Installation & Setup

### Prerequisites
- Windows 10/11 (64-bit)
- Python 3.10+
- Administrative (Elevated) privileges (required for Windows handle querying and process termination)

### Quick Start
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
