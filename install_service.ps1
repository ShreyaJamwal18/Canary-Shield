#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install the Canary Shield Windows service (TEST MODE by default).
.DESCRIPTION
    Installs 'CanaryShield' as a MANUAL-start Windows service running as
    LocalSystem.  Sets recovery options (restart on failure) and restricts
    the DACL so only SYSTEM and Administrators can stop / delete it.

    By default the service runs in TEST MODE (CANARY_TEST_MODE=1, monitoring
    test_sandbox only).  To install in production mode, pass
    -IUnderstandProduction.

    This is NOT a Protected Process Light (PPL).  An Administrator can still
    stop or kill the service.  The goal is to resist casual tampering by
    standard users and to restart automatically after crashes.
#>
[CmdletBinding()]
param(
    [switch]$IUnderstandProduction
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Admin check ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator.  Right-click PowerShell -> Run as Administrator."
    exit 1
}

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe  = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    Write-Error "python.exe not found on PATH."
    exit 1
}

$serviceScript = Join-Path $projectDir 'canary_service.py'
if (-not (Test-Path $serviceScript)) {
    Write-Error "canary_service.py not found in $projectDir"
    exit 1
}

$serviceName = 'CanaryShield'

# --- Check if already installed ---
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[!] Service '$serviceName' is already installed (Status: $($existing.Status))."
    Write-Host "    Run uninstall_service.ps1 first if you want to reinstall."
    exit 1
}

# --- Determine mode ---
$mode = 'test'
if ($IUnderstandProduction) {
    Write-Host "[!] PRODUCTION MODE requested.  The service will monitor real user directories." -ForegroundColor Yellow
    $mode = 'production'
} else {
    Write-Host "[*] Installing in TEST MODE (monitors test_sandbox only)."
}

# --- Install the service via pywin32 ---
Write-Host "[*] Installing CanaryShield service..."
& $pythonExe $serviceScript --startup manual install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Service installation failed (exit code $LASTEXITCODE)."
    exit 1
}

# --- Set environment variable for test mode ---
# We inject CANARY_TEST_MODE into the service's Environment registry key.
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
if ($mode -eq 'test') {
    $envBlock = @("CANARY_TEST_MODE=1")
} else {
    $envBlock = @("CANARY_TEST_MODE=0")
}
New-ItemProperty -Path $regPath -Name 'Environment' -Value $envBlock -PropertyType MultiString -Force | Out-Null
Write-Host "[*] Service environment: CANARY_TEST_MODE=$( if ($mode -eq 'test') {'1'} else {'0'} )"

# --- Recovery: restart after 5 s on first, second, third failure ---
Write-Host "[*] Setting recovery options (restart after 5 s on failure)..."
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

# --- Permissions: restrict DACL ---
#   D: = DACL
#   (A;;RPWPCR;;;SY)   = SYSTEM: full control
#   (A;;RPWPCR;;;BA)   = Administrators: full control
#   (A;;0x20014;;;IU)   = Interactive Users: read + enumerate (cannot stop/pause/delete)
#   (A;;0x20014;;;SU)   = Service Logon Users: read
Write-Host "[*] Restricting service DACL (standard users cannot stop/delete)..."
$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
sc.exe sdset $serviceName $sddl | Out-Null

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  CanaryShield service installed successfully." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Service name:   $serviceName"
Write-Host "  Start type:     Manual"
Write-Host "  Mode:           $($mode.ToUpper())"
Write-Host "  Recovery:       Restart after 5 s (3 attempts)"
Write-Host "  Permissions:    SYSTEM + Administrators only"
Write-Host ""
Write-Host "  To start:   Start-Service CanaryShield"
Write-Host "  To stop:    Stop-Service CanaryShield   (requires Admin)"
Write-Host "  To remove:  .\uninstall_service.ps1"
Write-Host ""
Write-Host "  NOTE: This is NOT a Protected Process Light (PPL)."
Write-Host "  An Administrator can still stop or kill the service."
Write-Host "  The goal is to resist standard-user tampering and auto-restart."
