# Register an hourly Windows scheduled task that runs the local node verification.
# ASCII-only on purpose: non-ASCII in .ps1/.bat gets mangled by console codepages.
#
# The task runs FULLY HIDDEN (no black cmd window) by wrapping run_local.bat in
# Start-Process -WindowStyle Hidden, launched from a hidden PowerShell host.
#
# Usage:  powershell -ExecutionPolicy Bypass -File setup_schedule.ps1
# Remove: schtasks /delete /tn mkdy-verify-local /f

$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$bat  = Join-Path $here "run_local.bat"
$name = "mkdy-verify-local"

if (-not (Test-Path $bat)) { throw "run_local.bat not found: $bat" }

# Remove any previous registration so the hidden-window config is always applied.
# The task may not exist on first run -> ignore the error (don't abort the script).
$prev = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
schtasks /delete /tn $name /f 2>$null
$ErrorActionPreference = $prev

# Build a single-quoted -Command so there are NO nested double quotes.
# $bat has no spaces, so single quotes around it are safe.
$psCommand = "Start-Process -FilePath '$bat' -WindowStyle Hidden -Wait"
$tr = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command $psCommand"
schtasks /create /tn $name /tr "$tr" /sc hourly /mo 1 /st 00:05 /f
if ($LASTEXITCODE -ne 0) { throw "schtasks create failed ($LASTEXITCODE)" }

Write-Output ""
Write-Output "Registered (hidden window). Current state:"
schtasks /query /tn $name /fo list
Write-Output ""
Write-Output "Run once now:  schtasks /run /tn $name"
Write-Output "Log file:      $(Join-Path $here 'logs\run.log')"
