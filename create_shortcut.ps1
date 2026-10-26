# create_shortcut.ps1 — Create Canary Shield Desktop and Project Shortcuts
# Uses pythonw.exe to launch app.py with no black terminal window,
# custom Canary Shield icon, and self-elevating UAC.

$ErrorActionPreference = "Stop"

# Project root directory
$ProjectDir = $PSScriptRoot
if (-not $ProjectDir) {
    $ProjectDir = (Get-Location).Path
}

# Resolve pythonw.exe
$PythonExe = "C:\Users\91700\AppData\Local\Programs\Python\Python311\python.exe"
$PythonwExe = "C:\Users\91700\AppData\Local\Programs\Python\Python311\pythonw.exe"

if (-not (Test-Path $PythonwExe)) {
    # Fallback search in PATH
    $CmdPython = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($CmdPython) {
        $Dir = Split-Path -Parent $CmdPython
        $Candidate = Join-Path $Dir "pythonw.exe"
        if (Test-Path $Candidate) {
            $PythonwExe = $Candidate
        }
    }
}

if (-not (Test-Path $PythonwExe)) {
    Write-Error "Could not locate pythonw.exe at $PythonwExe"
    exit 1
}

$AppPy = Join-Path $ProjectDir "app.py"
$IconPath = Join-Path $ProjectDir "assets\canary_shield.ico"

if (-not (Test-Path $AppPy)) {
    Write-Error "Could not find app.py at $AppPy"
    exit 1
}

if (-not (Test-Path $IconPath)) {
    Write-Error "Could not find icon at $IconPath"
    exit 1
}

$WshShell = New-Object -ComObject WScript.Shell

# 1. Desktop shortcut
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$DesktopShortcutPath = Join-Path $DesktopPath "Canary Shield.lnk"

$Shortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$Shortcut.TargetPath = $PythonwExe
$Shortcut.Arguments = "`"$AppPy`""
$Shortcut.WorkingDirectory = $ProjectDir
$Shortcut.IconLocation = "$IconPath, 0"
$Shortcut.Description = "Canary Shield - Deception-based Ransomware Defense"
$Shortcut.Save()
Write-Host "[OK] Created Desktop shortcut: $DesktopShortcutPath"

# 2. Project directory shortcut copy
$ProjectShortcutPath = Join-Path $ProjectDir "Canary Shield.lnk"
$ShortcutProj = $WshShell.CreateShortcut($ProjectShortcutPath)
$ShortcutProj.TargetPath = $PythonwExe
$ShortcutProj.Arguments = "`"$AppPy`""
$ShortcutProj.WorkingDirectory = $ProjectDir
$ShortcutProj.IconLocation = "$IconPath, 0"
$ShortcutProj.Description = "Canary Shield - Deception-based Ransomware Defense"
$ShortcutProj.Save()
Write-Host "[OK] Created Project folder shortcut: $ProjectShortcutPath"

Write-Host "Shortcut configuration complete. Target: $PythonwExe `"$AppPy`""
