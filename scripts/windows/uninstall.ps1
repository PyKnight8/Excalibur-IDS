[CmdletBinding()]
param(
    [string]$AppDir = "$env:ProgramFiles\Excalibur",
    [string]$DataDir = "$env:ProgramData\Excalibur"
)

$ErrorActionPreference = "Stop"
$ServiceIds = @("ExcaliburDashboard", "ExcaliburSensor", "ExcaliburHelper")

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required. Open PowerShell as Administrator and run this script again."
    }
}

function Confirm-Choice([string]$Prompt, [bool]$Default = $false) {
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $answer = (Read-Host "$Prompt $suffix").Trim().ToLowerInvariant()
    if (-not $answer) {
        return $Default
    }
    return $answer -in @("y", "yes")
}

Assert-Administrator

if ((Test-Path -LiteralPath $DataDir) -and (Confirm-Choice "Create a backup of ProgramData before uninstalling?" $true)) {
    $BackupRoot = Join-Path $env:ProgramData "Excalibur Backups"
    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $BackupPath = Join-Path $BackupRoot "Excalibur-$Timestamp.zip"
    Write-Host "[*] Creating backup at $BackupPath"
    Compress-Archive -LiteralPath $DataDir -DestinationPath $BackupPath -CompressionLevel Optimal
    Write-Host "[+] Backup created."
}

Write-Host "[*] Stopping and unregistering services"
foreach ($ServiceId in $ServiceIds) {
    $Service = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
    if ($null -eq $Service) {
        Write-Host "[=] Service $ServiceId is not installed."
        continue
    }

    if ($Service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceId -Force -ErrorAction SilentlyContinue
        $Service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }

    $WrapperPath = Join-Path $AppDir "services\$ServiceId.exe"
    if (Test-Path -LiteralPath $WrapperPath) {
        & $WrapperPath uninstall | Out-Host
    }
    else {
        & sc.exe delete $ServiceId | Out-Host
    }
}

if ((Test-Path -LiteralPath $AppDir) -and (Confirm-Choice "Remove application files from $AppDir?")) {
    $ResolvedAppDir = (Resolve-Path -LiteralPath $AppDir).Path
    $ExpectedAppDir = [IO.Path]::GetFullPath("$env:ProgramFiles\Excalibur")
    if ($ResolvedAppDir -ne $ExpectedAppDir) {
        throw "Refusing to remove unexpected application path: $ResolvedAppDir"
    }
    Remove-Item -LiteralPath $ResolvedAppDir -Recurse -Force
    Write-Host "[+] Application files removed."
}

if ((Test-Path -LiteralPath $DataDir) -and (Confirm-Choice "Remove all runtime data, configuration, rules, plugins, and logs from $DataDir?")) {
    $ResolvedDataDir = (Resolve-Path -LiteralPath $DataDir).Path
    $ExpectedDataDir = [IO.Path]::GetFullPath("$env:ProgramData\Excalibur")
    if ($ResolvedDataDir -ne $ExpectedDataDir) {
        throw "Refusing to remove unexpected data path: $ResolvedDataDir"
    }
    Remove-Item -LiteralPath $ResolvedDataDir -Recurse -Force
    Write-Host "[+] ProgramData files removed."
}
else {
    Write-Host "[=] ProgramData was preserved."
}

Write-Host "[+] Excalibur services were uninstalled."
