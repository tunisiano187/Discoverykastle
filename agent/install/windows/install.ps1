#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Instoverykastle agent — Windows installer.

.DESCRIPTION
    Installs the Discoverykastle (DK) agent as a Windows Service.
    Supports Windows Server 2019+, Windows 10/11.

    What this script does:
      1. Checks prerequisites (Python 3.10+, pip, git)
      2. Installs the agent to C:\Program Files\Discoverykastle\Agent\
      3. Creates the config file at C:\ProgramData\Discoverykastle\Agent\agent.conf
      4. Registers and starts the Windows Service "DiscoverykastleAgent"

.PARAMETER ServerUrl
    URL of the Discoverykastle server (e.g. https://dkserver.example.com:8443)

.PARAMETER EnrollToken
    Enrollment token generated from the DK dashboard (Agents → New enrollment token)

.PARAMETER InstallDir
    Installation directory. Default: C:\Program Files\Discoverykastle\Agent

.EXAMPLE
    .\install.ps1 -ServerUrl "https://dkserver:8443" -EnrollToken "tok-abc123"

.EXAMPLE
    .\install.ps1   # Installs without token; edit agent.conf manually then start the service
#>

param(
    [string]$ServerUrl   = "",
    [string]$EnrollToken = "",
    [string]$InstallDir  = "C:\Program Files\Discoverykastle\Agent"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName  = "DiscoverykastleAgent"
$ConfigDir    = "$env:ProgramData\Discoverykastle\Agent"
$ConfigFile   = "$ConfigDir\agent.conf"
$DataDir      = "$ConfigDir\data"
$LogDir       = "$ConfigDir\logs"
$PythonExe    = "python"   # must be on PATH

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param($msg) Write-Host "  [ .. ] $msg" -ForegroundColor Cyan  }
function Write-OK    { param($msg) Write-Host "  [ OK ] $msg" -ForegroundColor Green }
function Write-Err   { param($msg) Write-Host "  [ERR] $msg"  -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
Write-Step "Checking prerequisites…"

if (-not (Get-Command $PythonExe -ErrorAction SilentlyContinue)) {
    Write-Err "Python is not found on PATH. Install Python 3.10+ from https://www.python.org/downloads/"
}

$pyVer = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$major, $minor = $pyVer -split "\." | Select-Object -First 2
if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 10)) {
    Write-Err "Python 3.10 or higher is required (found $pyVer)."
}
Write-OK "Python $pyVer found"

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
Write-Step "Creating directories…"
foreach ($dir in @($InstallDir, $ConfigDir, $DataDir, $LogDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
Write-OK "Directories ready"

# ---------------------------------------------------------------------------
# Install agent source
# ---------------------------------------------------------------------------
Write-Step "Installing agent to $InstallDir…"

$repoRoot = Resolve-Path "$PSScriptRoot\..\..\..\"

# Create a virtualenv
& $PythonExe -m venv "$InstallDir\venv"
$pip = "$InstallDir\venv\Scripts\pip.exe"

& $pip install --quiet --upgrade pip

$reqFile = "$repoRoot\agent\requirements.txt"
if (Test-Path $reqFile) {
    & $pip install --quiet -r $reqFile
}

# Copy agent source
$agentSrc = "$InstallDir\src"
if (Test-Path $agentSrc) { Remove-Item -Recurse -Force $agentSrc }
Copy-Item -Recurse "$repoRoot\agent" $agentSrc

# Copy service wrapper
Copy-Item "$PSScriptRoot\service.py" "$InstallDir\service.py" -Force

Write-OK "Agent installed"

# ---------------------------------------------------------------------------
# Config file
# ---------------------------------------------------------------------------
Write-Step "Creating config file…"

if (-not (Test-Path $ConfigFile)) {
    $configContent = @"
# Discoverykastle agent configuration
# Edit this file then restart the service:
#   Restart-Service DiscoverykastleAgent

# ---- DK server connection ----------------------------------------
DKASTLE_SERVER_URL=$ServerUrl
# Enrollment token (remove after first successful enrollment)
DKASTLE_ENROLL_TOKEN=$EnrollToken

# ---- Agent identity (filled in automatically after enrollment) ----
# DKASTLE_AGENT_ID=
# DKASTLE_AGENT_CERT=$DataDir\agent.crt
# DKASTLE_AGENT_KEY=$DataDir\agent.key
# DKASTLE_AGENT_CA=$DataDir\ca.crt
DKASTLE_AGENT_DATA_DIR=$DataDir

# ---- Logging -------------------------------------------------------
DKASTLE_LOG_LEVEL=INFO
DKASTLE_LOG_FILE=$LogDir\agent.log

# ---- Puppet collector (enable if this host IS the Puppet server) --
PUPPET_ENABLED=false
# PUPPET_FACT_CACHE_DIR=C:\ProgramData\PuppetLabs\puppet\cache\yaml\facts
# PUPPET_REPORT_DIR=C:\ProgramData\PuppetLabs\puppet\cache\reports
# PUPPET_SYNC_INTERVAL=3600
"@
    Set-Content -Path $ConfigFile -Value $configContent -Encoding UTF8

    # Restrict access: Administrators + SYSTEM only
    $acl = Get-Acl $ConfigFile
    $acl.SetAccessRuleProtection($true, $false)
    $admins  = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
    $system  = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
    foreach ($account in @($admins, $system)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $account, "FullControl", "Allow"
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $ConfigFile -AclObject $acl
    Write-OK "Config file created at $ConfigFile"
} else {
    Write-OK "Config file already exists — skipping"
}

# ---------------------------------------------------------------------------
# Windows Service
# ---------------------------------------------------------------------------
Write-Step "Registering Windows Service '$ServiceName'…"

$pythonExePath = "$InstallDir\venv\Scripts\python.exe"
$servicePy     = "$InstallDir\service.py"

# If service exists, stop and remove it first
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "Removing existing service…"
    if ($existing.Status -eq "Running") { Stop-Service -Name $ServiceName -Force }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Register using pywin32's service installer
$env:DKASTLE_AGENT_CONFIG = $ConfigFile
$env:PYTHONPATH = "$InstallDir\src"
& $pythonExePath $servicePy install

# Set description and recovery actions
& sc.exe description $ServiceName "Discoverykastle discovery agent"
& sc.exe failure $ServiceName reset= 3600 actions= restart/15000/restart/30000/restart/60000

Write-OK "Service registered"

# ---------------------------------------------------------------------------
# Start or prompt
# ---------------------------------------------------------------------------
if ($ServerUrl -ne "" -and $EnrollToken -ne "") {
    Write-Step "Starting service (will enroll on first run)…"
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 5
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq "Running") {
        Write-OK "Service is running"
    } else {
        Write-Host ""
        Write-Host "  Service failed to start. Check the log:" -ForegroundColor Yellow
        Write-Host "    $LogDir\agent.log"
        Write-Host "  or Windows Event Viewer → Application → DiscoverykastleAgent"
    }
} else {
    Write-Host ""
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  Service installed but NOT started." -ForegroundColor Yellow
    Write-Host "  Edit $ConfigFile and set:" -ForegroundColor Yellow
    Write-Host "    DKASTLE_SERVER_URL=https://your-dkserver:8443" -ForegroundColor Yellow
    Write-Host "    DKASTLE_ENROLL_TOKEN=<token from DK dashboard>" -ForegroundColor Yellow
    Write-Host "  Then run:" -ForegroundColor Yellow
    Write-Host "    Start-Service DiscoverykastleAgent" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor Yellow
}

Write-Host ""
Write-OK "Installation complete"
Write-Host ""
Write-Host "  Useful commands:"
Write-Host "    Get-Service    $ServiceName"
Write-Host "    Start-Service  $ServiceName"
Write-Host "    Stop-Service   $ServiceName"
Write-Host "    Restart-Service $ServiceName"
Write-Host "    Get-Content '$LogDir\agent.log' -Wait -Tail 50"
Write-Host ""
