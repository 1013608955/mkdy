# Register an hourly Windows scheduled task that runs the local node verification.
# ASCII-only on purpose: non-ASCII in .ps1/.bat gets mangled by console codepages.
#
# The task runs FULLY HIDDEN (no black cmd window) by wrapping run_local.bat in
# Start-Process -WindowStyle Hidden, launched from a hidden PowerShell host.
#
# Usage:  powershell -ExecutionPolicy Bypass -File setup_schedule.ps1
# Remove: schtasks /delete /tn mkdy-verify-local /f

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$bat  = Join-Path $here "run_local.bat"
$name = "mkdy-verify-local"

if (-not (Test-Path $bat)) { throw "run_local.bat not found: $bat" }

# Remove any previous registration so the hidden-window config is always applied.
schtasks /delete /tn $name /f 2>$null

# /sc hourly /mo 1 /st 00:05  ->  runs at :05 past every hour.
# Rationale: GitHub verify-tag.yml is scheduled at :15, so the local probe
# (~3 min) finishes first; the push also triggers verify-tag immediately.
# The whole thing is launched from a hidden PowerShell so no black cmd window pops up.
$psArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass " + `
          "-Command ""Start-Process -FilePath '$bat' -WindowStyle Hidden -Wait"""
schtasks /create /tn $name /tr "powershell.exe $psArgs" /sc hourly /mo 1 /st 00:05 /f
if ($LASTEXITCODE -ne 0) { throw "schtasks create failed ($LASTEXITCODE)" }

Write-Output ""
Write-Output "Registered (hidden window). Current state:"
schtasks /query /tn $name /fo list
Write-Output ""
Write-Output "Run once now:  schtasks /run /tn $name"
Write-Output "Log file:      $(Join-Path $here 'logs\run.log')"
