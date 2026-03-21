#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Discoverykastle agent — Windows uninstaller.

.PARAMETER Purge
    Also removes config, data and log files.
#>

param([switch]$Purge)

$ServiceName = "DiscoverykastleAgent"
$InstallDir  = "C:\Program Files\Discoverykastle\Agent"
$ConfigDir   = "$env:ProgramData\Discoverykastle\Agent"

$ErrorActionPreference = "Stop"

function Write-Step { param($msg) Write-Host "  [ .. ] $msg" -ForegroundColor Cyan  }
function Write-OK   { param($msg) Write-Host "  [ OK ] $msg" -ForegroundColor Green }

Write-Step "Stopping and removing service '$ServiceName'…"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") { Stop-Service -Name $ServiceName -Force }

    $pythonExe = "$InstallDir\venv\Scripts\python.exe"
    $servicePy = "$InstallDir\service.py"
    if (Test-Path $pythonExe) {
        & $pythonExe $servicePy remove
    } else {
        & sc.exe delete $ServiceName | Out-Null
    }
    Write-OK "Service removed"
} else {
    Write-OK "Service not found — skipping"
}

Write-Step "Removing agent files from $InstallDir…"
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
Write-OK "Agent files removed"

if ($Purge) {
    Write-Step "Purging config, data and logs from $ConfigDir…"
    if (Test-Path $ConfigDir) { Remove-Item -Recurse -Force $ConfigDir }
    Write-OK "Config, data and logs purged"
} else {
    Write-Host ""
    Write-Host "  Config and data preserved at: $ConfigDir" -ForegroundColor Yellow
    Write-Host "  Run with -Purge to remove them." -ForegroundColor Yellow
}

Write-OK "Uninstall complete"
