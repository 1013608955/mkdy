# Register an hourly Windows scheduled task that runs the local node verification.
# ASCII-only on purpose: non-ASCII in .ps1/.bat gets mangled by console codepages.
#
# The task runs FULLY HIDDEN (zero black window, no flash) by wrapping
# run_local.bat in run_hidden.vbs (WshShell.Run ..., 0, True).
# VBS vbHide is the only reliable zero-flash method on Windows;
# PowerShell -WindowStyle Hidden still creates a brief window before hiding.
#
# Usage:  powershell -ExecutionPolicy Bypass -File setup_schedule.ps1
# Remove: schtasks /delete /tn mkdy-verify-local /f

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$vbs  = Join-Path $here "run_hidden.vbs"
$bat  = Join-Path $here "run_local.bat"
$name = "mkdy-verify-local"

if (-not (Test-Path $vbs)) { throw "run_hidden.vbs not found: $vbs" }
if (-not (Test-Path $bat)) { throw "run_local.bat not found: $bat" }

# Remove any previous registration so the hidden-window config is always applied.
# The task may not exist on first run -> ignore the error (don't abort the script).
$prev = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
schtasks /delete /tn $name /f 2>$null
$ErrorActionPreference = $prev

# Build the task action: wscript.exe runs VBS wrapper (zero-flash, zero-window)
$vbsQuoted = '"' + $vbs + '"'
$tr = "wscript.exe $vbsQuoted"
schtasks /create /tn $name /tr "$tr" /sc hourly /mo 1 /st 00:05 /f
if ($LASTEXITCODE -ne 0) { throw "schtasks create failed ($LASTEXITCODE)" }

Write-Output ""
Write-Output "Registered (VBS zero-flash hidden). Current state:"
schtasks /query /tn $name /fo list
Write-Output ""
Write-Output "Run once now:  schtasks /run /tn $name"
Write-Output "Log file:      $(Join-Path $here 'logs\run.log')"
