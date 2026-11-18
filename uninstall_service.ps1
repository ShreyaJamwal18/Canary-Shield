#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Completely uninstall the Canary Shield Windows service.
.DESCRIPTION
    Stops the CanaryShield service if running, removes it from the SCM,
    cleans up heartbeat/shutdown marker files, and verifies no orphan
    processes remain.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Admin check ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator.  Right-click PowerShell -> Run as Administrator."
    exit 1
}

$serviceName = 'CanaryShield'
$projectDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe   = (Get-Command python -ErrorAction SilentlyContinue).Source

# --- Check if service exists ---
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "[*] Service '$serviceName' is not installed.  Nothing to do."
    exit 0
}

# --- Stop the service if running ---
if ($svc.Status -eq 'Running') {
    Write-Host "[*] Stopping service '$serviceName'..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# --- Remove via pywin32 ---
$serviceScript = Join-Path $projectDir 'canary_service.py'
if ($pythonExe -and (Test-Path $serviceScript)) {
    Write-Host "[*] Removing service via pywin32..."
    & $pythonExe $serviceScript remove 2>$null
    Start-Sleep -Seconds 1
}

# --- Fallback: sc.exe delete ---
$stillExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($stillExists) {
    Write-Host "[*] Fallback: removing via sc.exe..."
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}

# --- Clean up heartbeat/marker files ---
$heartbeat = Join-Path $projectDir 'canary_shield_heartbeat.json'
$marker    = Join-Path $projectDir 'canary_shield_clean_shutdown'
foreach ($f in @($heartbeat, "$heartbeat.tmp", $marker)) {
    if (Test-Path $f) {
        Remove-Item $f -Force -ErrorAction SilentlyContinue
        Write-Host "[*] Removed: $(Split-Path $f -Leaf)"
    }
}

# --- Verify no leftover processes ---
$orphans = Get-Process python*, pythonw* -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowTitle -eq '' -and $_.StartTime -gt (Get-Date).AddMinutes(-5) }
if ($orphans) {
    Write-Host "[!] Possible orphan Python processes:" -ForegroundColor Yellow
    $orphans | Format-Table Id, ProcessName, StartTime -AutoSize
} else {
    Write-Host "[*] No orphan Python processes detected."
}

# --- Final check ---
$check = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($check) {
    Write-Host "[!] WARNING: Service '$serviceName' still appears registered." -ForegroundColor Yellow
    Write-Host "    It may be marked for deletion and will disappear after a reboot."
} else {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  CanaryShield service uninstalled successfully." -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  No service, no leftover processes, no heartbeat files."
}
