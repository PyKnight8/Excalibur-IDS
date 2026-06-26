[CmdletBinding()]
param(
    [string]$AppDir = "$env:ProgramFiles\Excalibur",
    [string]$DataDir = "$env:ProgramData\Excalibur"
)

$ErrorActionPreference = "Stop"
$ServiceIds = @("ExcaliburHelper", "ExcaliburSensor", "ExcaliburDashboard")

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

function Copy-IfMissing([string]$Source, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) {
        Write-Host "[=] Preserving existing $Destination"
        return
    }
    $parent = Split-Path -Parent $Destination
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    Write-Host "[+] Created $Destination"
}

function Initialize-DirectoryContents([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($Source.Length).TrimStart("\")
        $target = Join-Path $Destination $relativePath
        Copy-IfMissing $_.FullName $target
    }
}

Assert-Administrator

$SourceDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$BundledWinSW = Join-Path $SourceDir "third_party\winsw\WinSW-x64.exe"
$WinSWHashPath = Join-Path $SourceDir "third_party\winsw\SHA256.txt"

Write-Step "Using bundled WinSW executable"
Write-Host "[*] WinSW source: $BundledWinSW"
if (-not (Test-Path -LiteralPath $BundledWinSW -PathType Leaf)) {
    throw "Bundled WinSW executable not found: $BundledWinSW"
}

if (Test-Path -LiteralPath $WinSWHashPath -PathType Leaf) {
    Write-Step "Verifying bundled WinSW SHA256"
    $HashFileContent = Get-Content -LiteralPath $WinSWHashPath -Raw
    $ExpectedHashMatch = [regex]::Match($HashFileContent, "(?i)\b[0-9a-f]{64}\b")
    if (-not $ExpectedHashMatch.Success) {
        throw "Bundled WinSW SHA256 file does not contain a valid hash: $WinSWHashPath"
    }
    $ExpectedHash = $ExpectedHashMatch.Value.ToUpperInvariant()
    $ActualHash = (Get-FileHash -LiteralPath $BundledWinSW -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "Bundled WinSW hash verification failed."
    }
    Write-Host "[+] Bundled WinSW hash verified."
}

$LogDir = Join-Path $DataDir "logs"
$RulesDir = Join-Path $DataDir "rules"
$PluginsDir = Join-Path $DataDir "plugins"
$ServicesDir = Join-Path $AppDir "services"
$VenvDir = Join-Path $AppDir ".venv"
$PythonPath = Join-Path $VenvDir "Scripts\python.exe"
$ConfigPath = Join-Path $DataDir "config.yaml"
$RulesConfigPath = Join-Path $DataDir "rules.yaml"

Write-Step "Creating application and runtime directories"
@($AppDir, $DataDir, $LogDir, $RulesDir, $PluginsDir, $ServicesDir) | ForEach-Object {
    New-Item -ItemType Directory -Path $_ -Force | Out-Null
}

Write-Step "Copying application files to $AppDir"
& robocopy.exe $SourceDir $AppDir /E /R:2 /W:1 /XD ".git" ".venv" "__pycache__" /XF "*.sqlite" "*.sqlite-shm" "*.sqlite-wal" "*.pyc" "config.yaml" | Out-Host
if ($LASTEXITCODE -gt 7) {
    throw "Application copy failed with robocopy exit code $LASTEXITCODE."
}

Write-Step "Initializing runtime configuration without replacing existing files"
Copy-IfMissing (Join-Path $SourceDir "config.example.yaml") $ConfigPath
Copy-IfMissing (Join-Path $SourceDir "rules.yaml") $RulesConfigPath
Initialize-DirectoryContents (Join-Path $SourceDir "rules") $RulesDir
Initialize-DirectoryContents (Join-Path $SourceDir "plugins") $PluginsDir

if (-not (Test-Path -LiteralPath $PythonPath)) {
    Write-Step "Creating Python virtual environment"
    $PythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -eq $PythonCommand) {
        throw "Python was not found in PATH. Install a supported 64-bit Python release and retry."
    }
    & $PythonCommand.Source -m venv $VenvDir
}

Write-Step "Installing Python requirements"
& $PythonPath -m pip install --upgrade pip
& $PythonPath -m pip install -r (Join-Path $AppDir "requirements.txt")

$TemplateDir = Join-Path $AppDir "scripts\windows\services"
$Replacements = @{
    "__PYTHON__" = $PythonPath
    "__APP_DIR__" = $AppDir
    "__DATA_DIR__" = $DataDir
    "__LOG_DIR__" = $LogDir
    "__CONFIG_PATH__" = $ConfigPath
    "__RULES_CONFIG_PATH__" = $RulesConfigPath
    "__RULES_DIR__" = $RulesDir
    "__PLUGINS_DIR__" = $PluginsDir
}

Write-Step "Registering Windows services"
foreach ($ServiceId in $ServiceIds) {
    $WrapperPath = Join-Path $ServicesDir "$ServiceId.exe"
    $ConfigFile = Join-Path $ServicesDir "$ServiceId.xml"
    Copy-Item -LiteralPath $BundledWinSW -Destination $WrapperPath -Force

    $Xml = Get-Content -LiteralPath (Join-Path $TemplateDir "$ServiceId.xml") -Raw
    foreach ($Replacement in $Replacements.GetEnumerator()) {
        $Xml = $Xml.Replace($Replacement.Key, [Security.SecurityElement]::Escape($Replacement.Value))
    }
    Set-Content -LiteralPath $ConfigFile -Value $Xml -Encoding UTF8

    $ExistingService = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
    if ($null -ne $ExistingService) {
        if ($ExistingService.Status -ne "Stopped") {
            & $WrapperPath stop | Out-Host
        }
        & $WrapperPath uninstall | Out-Host
    }
    & $WrapperPath install | Out-Host
}

Write-Step "Starting Excalibur services"
foreach ($ServiceId in $ServiceIds) {
    Start-Service -Name $ServiceId
}

Write-Host ""
Write-Host "[+] Excalibur installation completed." -ForegroundColor Green
Get-Service -Name $ServiceIds | Format-Table Name, DisplayName, Status -AutoSize
Write-Host "Dashboard: http://127.0.0.1:5000"
Write-Host "Application: $AppDir"
Write-Host "Runtime data: $DataDir"
