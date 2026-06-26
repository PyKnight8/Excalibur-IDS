[CmdletBinding()]
param(
    [string]$AppDir = "$env:ProgramFiles\Excalibur"
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required. Open PowerShell as Administrator and run this script again."
    }
}

function Write-Step([string]$Message) {
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

Assert-Administrator

$SourceDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

Write-Step "Deploying Excalibur..."

Write-Step "Copying application files"

& robocopy.exe `
    $SourceDir `
    $AppDir `
    /E `
    /R:2 `
    /W:1 `
    /XD ".git" ".venv" "__pycache__" `
    /XF "*.sqlite*" "*.pyc"

if ($LASTEXITCODE -gt 7) {
    throw "Deployment failed with robocopy exit code $LASTEXITCODE."
}

$PythonPath = Join-Path $AppDir ".venv\Scripts\python.exe"

if (Test-Path -LiteralPath $PythonPath) {
    Write-Step "Updating Python requirements"

    & $PythonPath -m pip install -r (Join-Path $AppDir "requirements.txt")
}

$HelperService = Get-Service -Name "ExcaliburHelper" -ErrorAction SilentlyContinue

if ($null -ne $HelperService) {
    Write-Step "Restarting ExcaliburHelper"
    Restart-Service -Name "ExcaliburHelper"
}

Write-Step "Restarting Excalibur services"

Restart-Service -Name "ExcaliburSensor"
Restart-Service -Name "ExcaliburDashboard"

Write-Host ""
Write-Host "[+] Deployment complete." -ForegroundColor Green

Get-Service -Name ExcaliburHelper,ExcaliburSensor,ExcaliburDashboard -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize