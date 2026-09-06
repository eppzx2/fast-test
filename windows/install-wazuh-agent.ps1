# F.A.S.T. - Windows Wazuh Agent installation helper
# Run from an elevated PowerShell session.

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ManagerIP,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$WazuhVersion = "4.9.0",

    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}
function Write-Success([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-WarningMessage([string]$Message) { Write-Host "[!]  $Message" -ForegroundColor Yellow }
function Fail([string]$Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { Fail "Administrator privileges are required." }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  F.A.S.T. - Windows Wazuh Agent Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Manager: $ManagerIP"
Write-Host "Agent:   $AgentName"
Write-Host "Version: $WazuhVersion"

Write-Step "Checking Manager reachability"
$portsOk = $true
foreach ($port in 1514, 1515) {
    $test = Test-NetConnection -ComputerName $ManagerIP -Port $port -WarningAction SilentlyContinue
    if ($test.TcpTestSucceeded) {
        Write-Success "TCP $port reachable"
    } else {
        Write-WarningMessage "TCP $port unreachable"
        $portsOk = $false
    }
}
if (-not $portsOk -and -not $Force) {
    $answer = Read-Host "Continue anyway? (y/N)"
    if ($answer -notmatch '^[Yy]$') { exit 1 }
}

$existingService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
$hadExistingService = $null -ne $existingService
if ($hadExistingService -and $existingService.Status -eq 'Running') {
    Write-Step "Stopping existing Wazuh Agent for upgrade/reinstall"
    Stop-Service -Name "WazuhSvc" -Force
}

$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$msiPath = Join-Path $env:TEMP "wazuh-agent-$WazuhVersion.msi"
$installSucceeded = $false
$rebootRequired = $false

try {
    Write-Step "Downloading Wazuh Agent MSI"
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    if (-not (Test-Path $msiPath) -or (Get-Item $msiPath).Length -le 0) {
        throw "Downloaded MSI is missing or empty"
    }
    Write-Success "MSI downloaded"

    Write-Step "Installing Wazuh Agent"
    $installArgs = "/i `"$msiPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_REGISTRATION_SERVER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$AgentName`""
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

    # MSI 3010 = successful install with reboot required.
    if ($process.ExitCode -notin 0, 3010) {
        throw "Installation failed (MSI exit code $($process.ExitCode))"
    }
    $installSucceeded = $true
    $rebootRequired = $process.ExitCode -eq 3010
    Write-Success "Wazuh Agent installed"
} catch {
    if ($hadExistingService) {
        try { Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue } catch { }
    }
    Fail $_.Exception.Message
} finally {
    Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
}

if (-not $installSucceeded) { Fail "Installation did not complete" }

Write-Step "Starting Wazuh Agent service"
$service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $service) { Fail "WazuhSvc was not created by the installer" }
if ($service.Status -eq 'Running') {
    Restart-Service -Name "WazuhSvc" -Force
} else {
    Start-Service -Name "WazuhSvc"
}
Start-Sleep -Seconds 5
$service = Get-Service -Name "WazuhSvc"
if ($service.Status -ne 'Running') { Fail "WazuhSvc did not become Running" }
Write-Success "WazuhSvc is running"

Write-Step "Checking recent agent logs"
Start-Sleep -Seconds 5
$logPath = "C:\Program Files (x86)\ossec-agent\ossec.log"
if (Test-Path $logPath) {
    $recent = Get-Content -Path $logPath -Tail 80
    $recent | Select-String -Pattern 'Connected to the server|Requesting a key|ERROR|WARNING' | Select-Object -Last 12
    if ($recent -match 'Connected to the server') {
        Write-Success "Agent reports a Manager connection"
    } else {
        Write-WarningMessage "Service is running but a confirmed Manager connection was not found in recent logs yet"
    }
} else {
    Write-WarningMessage "Agent log not found yet: $logPath"
}

if ($rebootRequired) {
    Write-WarningMessage "Windows Installer reported success with reboot required (3010). Reboot when practical."
}

Write-Host ""
Write-Host "DONE. Verify on Manager:" -ForegroundColor Cyan
Write-Host "  docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
