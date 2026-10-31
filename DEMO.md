# Canary Shield — Live Presentation Demo Guide

This guide details the **exact step-by-step commands** to run a live demo for your capstone evaluators.

---

## Pre-Demo Checklist

1. Open **two** separate **Administrator (Elevated)** PowerShell terminals.
2. Navigate both to the project root:
   ```powershell
   cd C:\Users\91700\Documents\MDC
   ```
3. Verify Python and dependencies are ready:
   ```powershell
   python --version
   python -c "import watchdog, psutil; print('Dependencies OK!')"
   ```
4. Verify sandbox exists (created automatically):
   ```powershell
   Test-Path test_sandbox
   ```

---

## Step 1: Start Canary Shield — Terminal 1 (Defense)

```powershell
# Enable Test Mode so the Python-based attack simulator can be targeted
$env:CANARY_TEST_MODE = "1"

# Launch the defense engine
python main.py
```

### Expected Output (Terminal 1):
```
======================================================================
           CANARY SHIELD — Deception-Based Ransomware Mitigation
======================================================================
[Initialization] TARGET SANDBOX PATH: C:\Users\91700\Documents\MDC\test_sandbox
[Canary Shield] EXECUTION MODE: TEST MODE (CANARY_TEST_MODE=1)
[Canary Shield] Note: python.exe is permitted for attack simulation.
[Canary Shield] Protected Allowlist Size: 140 processes

[Canary Shield] Step 1: Planting realistic decoy canary files in sandbox...
[Canary Shield] Successfully armed 10 decoy tripwires.

[Canary Shield] Step 2: Activating real-time OS filesystem monitoring...
[Canary Shield] System is armed and guarding the sandbox. Press Ctrl+C to stop.
```

**➡ Leave Terminal 1 running and switch to Terminal 2.**

---

## Step 2: Launch Simulated Attack — Terminal 2 (Attacker)

```powershell
$env:CANARY_TEST_MODE = "1"

# Run the benign attack simulator (holds handles open 0.4s for reliable attribution)
python simulate_attack.py --delay 0.08 --hold-handle 0.4
```

### Expected Output (Terminal 2):
```
[Simulator Target] TARGET SANDBOX PATH: C:\Users\91700\Documents\MDC\test_sandbox
[Simulator] Seeded 5 mock user files into sandbox for realistic testing.
[Simulator] Process ID (PID): 5456
[Simulator] Traversal delay: 0.08s | Handle hold time: 0.4s

[Simulator] Found 15 files to attack in sandbox.
[Simulator] Commencing simulated ransomware traversal...

[Simulator PID 5456] Encrypting: !_confidential_banking_wire_credentials.pdf...
   [Holding open handle for 0.4s to test direct match...]
   -> Successfully locked: !_confidential_banking_wire_credentials.pdf.locked
...
(Process killed mid-traversal by Canary Shield!)
```

**The simulator is killed abruptly mid-traversal — this is containment working!**

---

## Step 3: Observe Detection & Containment — Terminal 1

Look back at **Terminal 1**. You will see the tripwire alert and PID kill (typically about a quarter of a second, under a second in the worst test run):

```
[ALERT] CANARY TRIGGERED: MODIFIED on ...test_sandbox\!_confidential_client_contracts_index.docx

[ATTRIBUTION SUBSTEPS] Enum: 0.10 ms | cwd/cmdline: 0.00 ms | open_files: 107.45 ms | Total Attr: 158.03 ms (Scanned 1 procs, 1 inspected, source=incremental_cache)
[Canary Shield] Attributed PID: 7048 | Method: directory_heuristic | Confidence: MEDIUM | Latency: 158 ms
[Canary Shield] >>> CONTAINMENT ACTIVE: Process 7048 TERMINATED <<<
```

> **Containment Performance Note**: In 5 consecutive runs of `run_full_e2e_test.py` in test mode after the process-cache optimization, the median time-to-contain was about **260 ms**, and the worst run was about **950 ms** (typically about a quarter of a second, under a second in the worst test run). Before optimization, the median was about 930 ms and the worst was about 2450 ms. Typically 1 decoy is touched before containment (before optimization: 1 to 4). Note that these were measured against the bundled benign simulator in a sandbox on one Windows machine.

---

## Step 4: Show Surviving User Files — Terminal 2

```powershell
# Show sandbox files — user_*.docx/xlsx/pdf should survive
Get-ChildItem test_sandbox | Sort-Object Name
```

Point out to evaluators:
- Files with `.locked` extension = encrypted by ransomware **before** canary was tripped
- Files named `user_*.docx/xlsx/txt/pdf` (without `.locked`) = **PROTECTED AND SAVED**

---

## Step 5: Show Forensic Log — Terminal 2

```powershell
# Display the structured forensic log
Get-Content canary_shield.log
```

Highlight to evaluators:
1. **`CANARY TRIPWIRE TRIGGERED`** → exact canary path that was hit
2. **`Method=directory_heuristic`** → attribution strategy used
3. **`PID=5456 (python.exe)`** → offending process correctly identified
4. **`Confidence=MEDIUM`** → honest confidence grading
5. **`CONTAINMENT SUCCESS`** → process terminated

---

## Optional: Interactive Desktop GUI Demo

Alternatively, evaluators can witness the entire defense pipeline through the CustomTkinter desktop interface:
1. Double-click the **Canary Shield** shortcut on the Desktop (or run `CanaryShield.bat` from the MDC folder).
2. Accept the Windows Administrator UAC prompt.
3. In the Dashboard header, click **ARM SHIELD**. The status updates to indicate active tripwires and incremental process cache monitoring.
4. In the Attack Simulator section, click **🚀 Launch Attack Simulation**.
5. Observe the live event feed, prompt threat attribution, process freeze/kill, and forensic report generation logged in real time.

---

## Optional: Run the Automated Full Pipeline Test

```powershell
$env:CANARY_TEST_MODE = "1"
python run_full_e2e_test.py
```

This automatically runs both main.py and simulate_attack.py and verifies the result — great for a clean demo if live terminals feel risky.
