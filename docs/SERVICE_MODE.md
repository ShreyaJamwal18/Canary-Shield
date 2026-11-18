# Canary Shield — Windows Service Mode

## Overview

Canary Shield can run as a **Windows Service** (`CanaryShield`) under LocalSystem,
providing persistence across user logons, automatic restart on failure, and
resistance to casual tampering by standard users.

## Quick Start

### Install (requires Administrator PowerShell)

```powershell
# Test mode (default — monitors test_sandbox only)
.\install_service.ps1

# Production mode (monitors real user directories)
.\install_service.ps1 -IUnderstandProduction
```

### Start / Stop

```powershell
Start-Service CanaryShield          # Start the service
Stop-Service CanaryShield           # Stop (requires Administrator)
Get-Service CanaryShield            # Check status
```

### Uninstall

```powershell
.\uninstall_service.ps1
```

This stops the service, removes it from the SCM, cleans up heartbeat files,
and verifies no orphan processes remain.

## What It Does

| Feature | Detail |
|---------|--------|
| **Runs as LocalSystem** | The service runs under the SYSTEM account, which cannot be stopped by standard users. |
| **Auto-restart on failure** | Windows recovery is configured to restart the service after 5 seconds on the first, second, and third failure. |
| **Restricted DACL** | The service security descriptor is set so that only SYSTEM and Administrators can stop, pause, or delete it. Standard users get read-only access. |
| **Heartbeat file** | The service writes `canary_shield_heartbeat.json` every 2 seconds with the current PID and timestamp. |
| **Tamper / crash detection** | On every start, the service checks for a clean-shutdown marker. If the previous run did *not* end cleanly (e.g., the process was killed), it logs a tamper event with the downtime window and writes a `TAMPER-*.json` incident file. |
| **Console integration** | When the service is running, app.py detects it and disables the ARM button, showing "The CanaryShield service is already protecting this folder." The console switches to read-only incident viewing. |
| **Test mode by default** | The service installs with `CANARY_TEST_MODE=1` unless you explicitly pass `--IUnderstandProduction`. |
| **Manual start** | The service start type is MANUAL, so it never starts automatically at boot unless you change it (`sc config CanaryShield start= auto`). |

## What It Does NOT Protect Against

> **Be honest:** this is a standard Windows service, not a Protected Process Light.

| Threat | Protection? |
|--------|-------------|
| Standard user tries `Stop-Service` | ✅ **Blocked** by DACL — "Access is denied" |
| Standard user tries `taskkill` on the service PID | ✅ **Blocked** — SYSTEM processes cannot be killed by standard users |
| Administrator runs `Stop-Service CanaryShield` | ❌ **Allowed** — Administrators have full control |
| Administrator runs `taskkill /F /PID <pid>` | ⚠️ Service is killed but **restarts in 5 seconds** (recovery) and **logs a tamper event** |
| Administrator runs `sc delete CanaryShield` | ❌ **Allowed** — service is permanently removed |
| Malware running as Administrator | ❌ Can stop and delete the service |
| Kernel-mode rootkit | ❌ No protection (would need a signed driver) |

### Why can't we make it unkillable?

A truly unkillable service on Windows requires:
1. A **kernel-mode driver** signed with an **EV code-signing certificate**.
2. Registration as an **Early Launch Anti-Malware (ELAM)** driver.
3. Running as a **Protected Process Light (PPL)** with `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`.

This is what products like Windows Defender, CrowdStrike, and SentinelOne do.
It requires a Microsoft-approved signing process and is out of scope for this
project.

## Files Created

| File | Purpose |
|------|---------|
| `canary_service.py` | pywin32 `ServiceFramework` implementation |
| `install_service.ps1` | Admin PowerShell installer with safety checks |
| `uninstall_service.ps1` | Admin PowerShell uninstaller with cleanup |
| `canary_shield_heartbeat.json` | Written every 2 s while the service runs |
| `canary_shield_clean_shutdown` | Written on clean stop; absence = crash/tamper |
| `incidents/TAMPER-*.json` | Logged when the service detects an unclean restart |

## Architecture

```
┌───────────────────────────────────────────────────┐
│  Windows Service Control Manager (SCM)            │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │  CanaryShield Service (canary_service.py)   │  │
│  │  ┌───────────┐  ┌──────────────────────┐   │  │
│  │  │ Heartbeat │  │ Detection Engine     │   │  │
│  │  │ Thread    │  │ (deploy_decoys +     │   │  │
│  │  │ (2s tick) │  │  start_monitoring)   │   │  │
│  │  └───────────┘  └──────────────────────┘   │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  Recovery: restart/5000/restart/5000/restart/5000  │
│  DACL: SYSTEM + Administrators only               │
└───────────────────────────────────────────────────┘
```
