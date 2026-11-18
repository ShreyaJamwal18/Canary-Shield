#Requires -RunAsAdministrator
<#
.SYNOPSIS
    End-to-end verification of the CanaryShield Windows service.
.DESCRIPTION
    Run this script in an ELEVATED (Administrator) PowerShell.
    It installs, starts, tests, and uninstalls the service, printing
    results at each step.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe  = (Get-Command python -ErrorAction SilentlyContinue).Source

Write-Host "=" * 70
Write-Host "    CANARY SHIELD - SERVICE VERIFICATION SCRIPT"
Write-Host "=" * 70
Write-Host ""

# -----------------------------------------------------------------------
# STEP 1: Install
# -----------------------------------------------------------------------
Write-Host "=== STEP 1: INSTALL ===" -ForegroundColor Cyan
Set-Location $projectDir
& $pythonExe canary_service.py --startup manual install

# Set test mode environment
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CanaryShield"
if (Test-Path $regPath) {
    New-ItemProperty -Path $regPath -Name 'Environment' -Value @("CANARY_TEST_MODE=1") -PropertyType MultiString -Force | Out-Null
    Write-Host "[OK] CANARY_TEST_MODE=1 set in service registry"
}

# Recovery: restart after 5s
sc.exe failure CanaryShield reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Write-Host "[OK] Recovery options set (restart after 5s x3)"

# DACL
$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
sc.exe sdset CanaryShield $sddl | Out-Null
Write-Host "[OK] DACL restricted (standard users cannot stop/delete)"

Get-Service CanaryShield | Format-List Name,Status,StartType
Write-Host ""

# -----------------------------------------------------------------------
# STEP 2: Start
# -----------------------------------------------------------------------
Write-Host "=== STEP 2: START ===" -ForegroundColor Cyan
Start-Service CanaryShield
Start-Sleep -Seconds 4
$svc = Get-Service CanaryShield
Write-Host "Service status: $($svc.Status)"
if ($svc.Status -eq 'Running') {
    Write-Host "[OK] Service is RUNNING" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Service did not start!" -ForegroundColor Red
}
Write-Host ""

# Check heartbeat
$hbFile = Join-Path $projectDir 'canary_shield_heartbeat.json'
if (Test-Path $hbFile) {
    $hb = Get-Content $hbFile | ConvertFrom-Json
    Write-Host "[OK] Heartbeat file exists (PID=$($hb.pid), time=$($hb.iso))" -ForegroundColor Green
} else {
    Write-Host "[WARN] No heartbeat file yet" -ForegroundColor Yellow
}
Write-Host ""

# -----------------------------------------------------------------------
# STEP 3: Run simulator (should be contained)
# -----------------------------------------------------------------------
Write-Host "=== STEP 3: ATTACK SIMULATION ===" -ForegroundColor Cyan
$env:CANARY_TEST_MODE = "1"
$simProc = Start-Process -FilePath $pythonExe -ArgumentList "simulate_attack.py --delay 0.08 --hold-handle 0.4" -WorkingDirectory $projectDir -PassThru -NoNewWindow -Wait
Write-Host "Simulator exit code: $($simProc.ExitCode)"
if ($simProc.ExitCode -ne 0) {
    Write-Host "[OK] Simulator was KILLED (contained)" -ForegroundColor Green
} else {
    Write-Host "[WARN] Simulator ran to completion (may not have been contained)" -ForegroundColor Yellow
}

# Check for incident
Start-Sleep -Seconds 3
$incidents = Get-ChildItem (Join-Path $projectDir 'incidents') -Filter '*.json' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike 'TAMPER*' }
if ($incidents) {
    Write-Host "[OK] Incident(s) created: $($incidents.Name -join ', ')" -ForegroundColor Green
} else {
    Write-Host "[WARN] No incident JSON found" -ForegroundColor Yellow
}
Write-Host ""

# -----------------------------------------------------------------------
# STEP 4: Standard user Stop-Service (should fail)
# Note: We can only test this if we can create a standard-user context.
# Since this script runs as Admin, we document the expected result.
# -----------------------------------------------------------------------
Write-Host "=== STEP 4: STANDARD USER STOP (documenting expected result) ===" -ForegroundColor Cyan
Write-Host "Cannot test standard-user Stop-Service from an Admin shell."
Write-Host "Expected: 'Stop-Service CanaryShield' from a non-admin PowerShell"
Write-Host "          should return 'Access is denied' (error 5)."
Write-Host "[SKIPPED] No standard-user account context available" -ForegroundColor Yellow
Write-Host ""

# -----------------------------------------------------------------------
# STEP 5: Kill the service process, verify restart + tamper log
# -----------------------------------------------------------------------
Write-Host "=== STEP 5: TAMPER RECOVERY TEST ===" -ForegroundColor Cyan
# Read heartbeat to find PID
if (Test-Path $hbFile) {
    $hb = Get-Content $hbFile | ConvertFrom-Json
    $svcPid = $hb.pid
    Write-Host "Killing service PID $svcPid..."
    try {
        Stop-Process -Id $svcPid -Force -ErrorAction Stop
        Write-Host "[OK] Process killed" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not kill PID $svcPid : $_" -ForegroundColor Yellow
    }

    Write-Host "Waiting 10 seconds for recovery restart..."
    Start-Sleep -Seconds 10

    $svc2 = Get-Service CanaryShield
    Write-Host "Service status after kill: $($svc2.Status)"
    if ($svc2.Status -eq 'Running') {
        Write-Host "[OK] Service RESTARTED automatically!" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Service did not restart (Status: $($svc2.Status))" -ForegroundColor Yellow
    }

    # Check for tamper incident
    Start-Sleep -Seconds 3
    $tampers = Get-ChildItem (Join-Path $projectDir 'incidents') -Filter 'TAMPER-*.json' -ErrorAction SilentlyContinue
    if ($tampers) {
        Write-Host "[OK] Tamper event logged: $($tampers.Name -join ', ')" -ForegroundColor Green
        Get-Content $tampers[0].FullName
    } else {
        Write-Host "[INFO] No TAMPER-*.json found (tamper detection writes on next start)" -ForegroundColor Yellow
    }

    # Read new heartbeat
    if (Test-Path $hbFile) {
        $hb2 = Get-Content $hbFile | ConvertFrom-Json
        Write-Host "[OK] New heartbeat (PID=$($hb2.pid), time=$($hb2.iso))" -ForegroundColor Green
    }
} else {
    Write-Host "[SKIP] No heartbeat file — cannot determine PID" -ForegroundColor Yellow
}
Write-Host ""

# -----------------------------------------------------------------------
# STEP 6: Uninstall
# -----------------------------------------------------------------------
Write-Host "=== STEP 6: UNINSTALL ===" -ForegroundColor Cyan
Stop-Service CanaryShield -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
& $pythonExe canary_service.py remove
Start-Sleep -Seconds 2

$check = Get-Service CanaryShield -ErrorAction SilentlyContinue
if ($check) {
    Write-Host "[WARN] Service still registered (may need reboot)" -ForegroundColor Yellow
} else {
    Write-Host "[OK] Service removed" -ForegroundColor Green
}

# Clean up files
foreach ($f in @($hbFile, "$hbFile.tmp", (Join-Path $projectDir 'canary_shield_clean_shutdown'))) {
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}

# Check for orphans
$orphans = Get-Process python*, pythonw* -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowTitle -eq '' -and $_.StartTime -gt (Get-Date).AddMinutes(-5) }
if ($orphans) {
    Write-Host "[WARN] Possible orphan processes:" -ForegroundColor Yellow
    $orphans | Format-Table Id, ProcessName, StartTime -AutoSize
} else {
    Write-Host "[OK] No orphan processes" -ForegroundColor Green
}
Write-Host ""

# -----------------------------------------------------------------------
# STEP 7: E2E test still passes
# -----------------------------------------------------------------------
Write-Host "=== STEP 7: E2E TEST ===" -ForegroundColor Cyan
$env:CANARY_TEST_MODE = "1"
$e2eResult = & $pythonExe run_full_e2e_test.py 2>&1
$passed = $e2eResult | Select-String "PASSED"
if ($passed) {
    Write-Host "[OK] run_full_e2e_test.py PASSED" -ForegroundColor Green
} else {
    Write-Host "[FAIL] run_full_e2e_test.py did not PASS" -ForegroundColor Red
    $e2eResult | Select-String "PASSED|FAILED"
}
Write-Host ""

Write-Host "=" * 70
Write-Host "    VERIFICATION COMPLETE"
Write-Host "=" * 70
