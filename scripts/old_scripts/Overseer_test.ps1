# =========================================================
# Overseer_test.ps1
# =========================================================
# TEST version of Overseer Provisioning Script
# - Simulates provisioning commands (no changes applied)
# - Loads constants from .\.env during [1/6] Folder Structure Check
# - Self-elevates to Admin
# - Logging to file controlled by OVERSEER_PRINT_LOGS (console always prints)
#
# Feature toggles (TEST behaviour):
# - If a toggle is FALSE, the script will acknowledge it, but still simulate/check anyway.
# =========================================================

# ===============================
# Self-elevate if not admin
# ===============================
try {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
    Write-Host "[ERR] Could not verify Administrator privileges: $($_.Exception.Message)" -ForegroundColor Red
    $isAdmin = $false
}

if (-not $isAdmin) {
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }

    $escapedArgs = @()
    foreach ($argument in $args) {
        $escapedArgs += ('"{0}"' -f ($argument -replace '"', '`"'))
    }

    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', "`"$scriptPath`""
    ) + $escapedArgs

    try {
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argumentList
        exit
    }
    catch {
        Write-Host "[ERR] Elevation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$ErrorActionPreference = 'Stop'

# -------------------------------
# Root paths (Overseer folder = root)
# -------------------------------
$RootPath = $PSScriptRoot
$EnvFilePath = Join-Path $RootPath '.env'

$InstallersPath = Join-Path $RootPath 'installers'
$MonitoringPath = Join-Path $InstallersPath 'monitoring'
$AppsPath = Join-Path $InstallersPath 'apps'
$DriversPath = Join-Path $InstallersPath 'drivers'
$OfficePath = Join-Path $InstallersPath 'office'
$LogsPath = Join-Path $RootPath 'logs'

# Ensure we operate from Overseer root (helps when launched from shortcuts)
Set-Location $RootPath

# -------------------------------
# Ensure logs folder exists + per-run timestamped log file
# -------------------------------
if (-not (Test-Path $LogsPath)) {
    New-Item -ItemType Directory -Path $LogsPath | Out-Null
}

$RunStamp = Get-Date -Format 'dd-MM-yyyy_HH-mm-ss'
$LogFile = Join-Path $LogsPath ("Overseer_{0}.txt" -f $RunStamp)

# -------------------------------
# File logging toggle (resolved after .env is loaded)
# - Console logs always display.
# - OVERSEER_PRINT_LOGS=true|false controls writing log lines to .\logs\
# -------------------------------
$script:LogToFile = $null
$script:LogFileInitialised = $false
$script:PendingLogLines = New-Object System.Collections.Generic.List[string]

# Tracks any unhandled failures so the script can finish cleanly
$script:HadErrors = $false
$script:UnhandledErrorCount = 0

# -------------------------------
# Console output is intentionally timestamp-free (human readable).
# Log file retains timestamps for auditing.
# -------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')][string]$Level = 'INFO'
    )

    $fileLine = "[$Level] $Message"

    $levelMap = @{
        'SUCCESS' = 'OK'
        'WARNING' = 'WARN'
        'ERROR'   = 'ERR'
        'INFO'    = 'INFO'
    }

    $consoleLevel = if ($levelMap.ContainsKey($Level)) { $levelMap[$Level] } else { $Level }
    $consoleLine = "[{0}] {1}" -f $consoleLevel, $Message

    # Buffer log lines until .env is loaded (so we can honour OVERSEER_PRINT_LOGS)
    if ($null -eq $script:LogToFile) {
        [void]$script:PendingLogLines.Add($fileLine)
    }
    elseif ($script:LogToFile) {
        # If file logging just got enabled, initialise and flush any pending lines first
        if (-not $script:LogFileInitialised) {
            if (-not (Test-Path $LogsPath)) {
                New-Item -ItemType Directory -Path $LogsPath | Out-Null
            }

            if ($script:PendingLogLines.Count -gt 0) {
                Add-Content -Path $LogFile -Value $script:PendingLogLines.ToArray()
                $script:PendingLogLines.Clear()
            }

            $script:LogFileInitialised = $true
        }

        Add-Content -Path $LogFile -Value $fileLine
    }
    # else: file logging disabled => no file writes

    # Console logs should always display (toggle is file-only)
    switch ($Level) {
        'SUCCESS' { Write-Host $consoleLine -ForegroundColor Green }
        'WARNING' { Write-Host $consoleLine -ForegroundColor Yellow }
        'ERROR' { Write-Host $consoleLine -ForegroundColor Red }
        default { Write-Host $consoleLine -ForegroundColor Gray }
    }
}

# -------------------------------
# Global safety net for any unhandled terminating errors
# - Logs the error (console + file if enabled)
# - Marks the run as having errors
# - Continues execution so the completion summary still prints
# -------------------------------
trap {
    $script:HadErrors = $true
    $script:UnhandledErrorCount = $script:UnhandledErrorCount + 1

    $errMessage = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
    $inv = $_.InvocationInfo

    $locationText = $null
    $lineText = $null

    if ($inv) {
        $locationText = "{0}:{1}" -f $inv.ScriptName, $inv.ScriptLineNumber
        if ($inv.Line) { $lineText = $inv.Line.Trim() }
    }

    try {
        if ($locationText) {
            Write-Log ("UNHANDLED ERROR at {0}: {1}" -f $locationText, $errMessage) "ERROR"
            if ($lineText) { Write-Log ("Line: {0}" -f $lineText) "ERROR" }
        }
        else {
            Write-Log ("UNHANDLED ERROR: {0}" -f $errMessage) "ERROR"
        }
    }
    catch {
        Write-Host ("[ERR] UNHANDLED ERROR: {0}" -f $errMessage) -ForegroundColor Red
    }

    continue
}

# -------------------------------
# Helpers
# -------------------------------
function Convert-ToBool {
    param(
        [string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    $normalized = $Value.Trim().ToLowerInvariant()

    if ($normalized -in @('1', 'true', 'yes', 'y', 'on')) { return $true }
    if ($normalized -in @('0', 'false', 'no', 'n', 'off')) { return $false }

    return $Default
}

function Short-Path {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $fullRoot = (Resolve-Path $RootPath).Path.TrimEnd('\')
        $fullPath = (Resolve-Path $Path -ErrorAction SilentlyContinue).Path
        if (-not $fullPath) { $fullPath = $Path }

        if ($fullPath.ToLower().StartsWith($fullRoot.ToLower())) {
            $relative = $fullPath.Substring($fullRoot.Length).TrimStart('\')
            if ([string]::IsNullOrWhiteSpace($relative)) { return ".\" }
            return (".\" + $relative)
        }

        return $Path
    }
    catch {
        return $Path
    }
}

function Mask-ProductKey {
    param([string]$Key)
    if ([string]::IsNullOrWhiteSpace($Key)) { return "<NOT SET>" }

    $trimmedKey = $Key.Trim()
    if ($trimmedKey.Length -le 5) { return "*****" }
    $lastFive = $trimmedKey.Substring($trimmedKey.Length - 5)
    return ("*****-*****-*****-*****-{0}" -f $lastFive)
}

function Mask-PasswordInfo {
    param([string]$Secret)
    if ([string]::IsNullOrWhiteSpace($Secret)) { return "<NOT SET>" }
    return ("<SET> ({0} chars)" -f $Secret.Trim().Length)
}

function Load-DotEnv {
    param([Parameter(Mandatory)][string]$Path)

    $result = @{}

    if (-not (Test-Path $Path)) {
        return $result
    }

    $lines = Get-Content -Path $Path -ErrorAction Stop
    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()

        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith('#')) { continue }

        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { continue }

        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()

        # Strip surrounding quotes if present
        if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
            $val = $val.Substring(1, $val.Length - 2)
        }

        if (-not [string]::IsNullOrWhiteSpace($key)) {
            $result[$key] = $val
        }
    }

    return $result
}

function Test-Folder {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)

    if (Test-Path $Path) {
        Write-Log ("{0}: {1}" -f $Label, (Short-Path $Path)) "SUCCESS"
        return $true
    }
    else {
        Write-Log ("{0}: MISSING ({1})" -f $Label, (Short-Path $Path)) "ERROR"
        return $false
    }
}

function Test-File {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)

    if (Test-Path $Path) {
        Write-Log ("{0}: {1}" -f $Label, (Short-Path $Path)) "SUCCESS"
        return $true
    }
    else {
        Write-Log ("{0}: MISSING ({1})" -f $Label, (Short-Path $Path)) "ERROR"
        return $false
    }
}

function Get-SerialTag {
    param(
        [string]$Serial,
        [string]$FallbackUuid
    )

    $raw = if ($Serial) { $Serial.Trim() } else { "" }

    # Reject common placeholder serials
    $badSerials = @("Default string", "To be filled by O.E.M.", "System Serial Number", "None", "N/A", "Unknown")
    if ([string]::IsNullOrWhiteSpace($raw) -or ($badSerials -contains $raw)) {
        $raw = ""
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        $raw = if ($FallbackUuid) { $FallbackUuid } else { "0000000000000000" }
    }

    # Keep only alnum, uppercase
    $clean = ($raw -replace '[^a-zA-Z0-9]', '').ToUpperInvariant()

    if ([string]::IsNullOrWhiteSpace($clean)) {
        $clean = "000000"
    }

    # Use last 6 chars (fits hostname length)
    if ($clean.Length -gt 6) {
        return $clean.Substring($clean.Length - 6)
    }

    # Pad to 6 if short
    return $clean.PadLeft(6, '0')
}

function Build-ComputerName {
    param([Parameter(Mandatory)][string]$SerialTag)
    return ("BCC-NB{0}" -f $SerialTag)
}

# -------------------------------
# Monitoring installer helpers
# -------------------------------
function Get-MonitoringMsiFiles {
    if (-not (Test-Path $MonitoringPath)) { return @() }
    return Get-ChildItem -Path $MonitoringPath -Filter *.msi -File -ErrorAction SilentlyContinue
}

function Select-MonitoringInstaller {
    param(
        [Parameter(Mandatory)][string]$Model,
        [Parameter(Mandatory)][array]$MsiFiles
    )

    $modelMatch = $MsiFiles | Where-Object { $_.BaseName -match [regex]::Escape($Model) } | Select-Object -First 1
    if ($modelMatch) { return $modelMatch }

    $compactModel = ($Model -replace '\s+', '')
    $compactMatch = $MsiFiles | Where-Object { ($_.BaseName -replace '\s+', '') -match [regex]::Escape($compactModel) } | Select-Object -First 1
    if ($compactMatch) { return $compactMatch }

    return ($MsiFiles | Where-Object { $_.BaseName -match '^default' } | Select-Object -First 1)
}

function Mark-Error { $script:HadErrors = $true }

# -------------------------------
# Preflight checks (TEST-only: no changes applied)
# - Step 1: Check if local user 'Overseer' is an Administrator (case-insensitive)
# - Step 2: Check connectivity + whether a Wi-Fi adapter/driver exists
# -------------------------------

function Test-OverseerAdminMembership {
    param([string]$UserName = 'Overseer')

    try {
        $localUser = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -ieq $UserName } | Select-Object -First 1
        if (-not $localUser) {
            return @{ Found = $false; IsAdmin = $false; Name = $UserName }
        }

        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        foreach ($member in $members) {
            if ($member.SID -and $localUser.SID -and ($member.SID.Value -eq $localUser.SID.Value)) {
                return @{ Found = $true; IsAdmin = $true; Name = $localUser.Name }
            }
            if ($member.Name -and ($member.Name -match "\\$($localUser.Name)$")) {
                return @{ Found = $true; IsAdmin = $true; Name = $localUser.Name }
            }
        }

        return @{ Found = $true; IsAdmin = $false; Name = $localUser.Name }
    }
    catch {
        return @{ Found = $false; IsAdmin = $false; Name = $UserName; Error = $_.Exception.Message }
    }
}

function Get-NetworkState {
    $state = @{
        AnyConnected      = $false
        WifiConnected     = $false
        EthernetConnected = $false
        WifiAdapterFound  = $false
        WifiAdapterName   = ''
    }

    try {
        $adapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue
        if ($adapters) {
            $wifi = $adapters | Where-Object {
                ($_.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11') -or
                ($_.Name -match 'Wi-?Fi|Wireless')
            } | Select-Object -First 1

            if ($wifi) {
                $state.WifiAdapterFound = $true
                $state.WifiAdapterName = $wifi.Name
                if ($wifi.Status -eq 'Up') { $state.WifiConnected = $true }
            }

            $ethUp = $adapters | Where-Object {
                $_.Status -eq 'Up' -and
                ($_.InterfaceDescription -notmatch 'Wi-?Fi|Wireless|802\.11') -and
                ($_.Name -notmatch 'Wi-?Fi|Wireless')
            } | Select-Object -First 1

            if ($ethUp) { $state.EthernetConnected = $true }
        }
    } catch { }

    $state.AnyConnected = ($state.WifiConnected -or $state.EthernetConnected)
    return $state
}

function Find-WifiDriverPackage {
    param([string]$SearchPath)

    if (-not (Test-Path $SearchPath)) { return $null }

    return (Get-ChildItem -Path $SearchPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '\.(exe|msi)$' } |
        Where-Object { $_.Name -match 'wi-?fi|wireless|wlan|802\.11' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1)
}

# -------------------------------
# Header
# -------------------------------
Clear-Host
Write-Host "================================================" -ForegroundColor White
Write-Host " Overseer - Automated Provisioning Script (TEST)" -ForegroundColor White
Write-Host "================================================`n" -ForegroundColor White

Write-Log ("Started (Root: {0})" -f (Short-Path $RootPath)) "INFO"
Write-Log ("Log file: {0}" -f (Short-Path $LogFile)) "INFO"
Write-Log "Administrator privileges: OK" "SUCCESS"

Write-Host ""  # spacing before section 1

# -------------------------------
# [1/6] Folder Structure Check (+ .env detection/loading)
# -------------------------------
Write-Host "[1/6] Folder Structure" -ForegroundColor White
Write-Host "-----------------------------------------------" -ForegroundColor White

$installersExists = Test-Folder $InstallersPath "Installers"
$monitoringExists = Test-Folder $MonitoringPath "Monitoring installers"
$appsExists = Test-Folder $AppsPath "Apps installers"
$driversExists = Test-Folder $DriversPath "Driver installers"
$officeExists = Test-Folder $OfficePath "Office installers"
$logsExists = Test-Folder $LogsPath "Logs"

$envExists = Test-File -Path $EnvFilePath -Label ".env"

# Load .env into Process environment (only if present)
$dotEnv = @{}
if ($envExists) {
    try {
        $dotEnv = Load-DotEnv -Path $EnvFilePath
        if ($dotEnv.Count -eq 0) {
            Write-Log ".env found, but contains no usable KEY=VALUE entries" "ERROR"
            Mark-Error
        }
        else {
            foreach ($key in $dotEnv.Keys) {
                Set-Item -Path ("Env:{0}" -f $key) -Value $dotEnv[$key]
            }
            Write-Log ".env loaded into Process environment" "SUCCESS"
        }
    }
    catch {
        Write-Log ("Failed to read/parse .env: {0}" -f $_.Exception.Message) "ERROR"
        Mark-Error
    }
}
else {
    Write-Log ".env not found - using environment defaults" "WARNING"
}

# Now that .env has been loaded, assign globals (masked for display)
$global:WINDOWS_PRODUCT_KEY = $env:WINDOWS_PRODUCT_KEY
$global:BIOS_PASSWORD = $env:BIOS_PASSWORD
$global:OVERSEER_PASSWORD = $env:OVERSEER_ACCOUNT_PASSWORD
$global:TIMEZONE_ID = if ($env:TIMEZONE_ID) { $env:TIMEZONE_ID } else { 'E. Australia Standard Time' }

# Resolve file logging now that .env/process environment may be loaded.
# - Console logs always display.
# - OVERSEER_PRINT_LOGS only controls writing log lines to .\logs\
$script:LogToFile = Convert-ToBool -Value $env:OVERSEER_PRINT_LOGS -Default $true

# Feature toggles (resolved after .env is loaded)
# NOTE: In the TEST script, these toggles are acknowledged but the section still runs.
$script:ApplyOfficeLicenseEnabled = Convert-ToBool -Value $env:OVERSEER_APPLY_OFFICE_LICENSE        -Default $false
$script:InstallMonitoringAgentEnabled = Convert-ToBool -Value $env:OVERSEER_INSTALL_MONITORING_SOFTWARE   -Default $false
$script:RunDeviceInformationEnabled = Convert-ToBool -Value $env:OVERSEER_RUN_DEVICE_INFORMATION     -Default $true
$script:RunAppsSectionEnabled = Convert-ToBool -Value $env:OVERSEER_RUN_APPS                   -Default $true
$script:ConfigureTaskbarEnabled = Convert-ToBool -Value $env:OVERSEER_CONFIGURE_TASKBAR         -Default $true

if ($script:LogToFile) {
    # Flush any log lines written before .env was loaded
    if (-not (Test-Path $LogsPath)) {
        New-Item -ItemType Directory -Path $LogsPath | Out-Null
    }

    if ($script:PendingLogLines.Count -gt 0) {
        Add-Content -Path $LogFile -Value $script:PendingLogLines.ToArray()
        $script:PendingLogLines.Clear()
    }

    $script:LogFileInitialised = $true
}
else {
    # Discard any pending log lines; file logging disabled
    if ($script:PendingLogLines.Count -gt 0) {
        $script:PendingLogLines.Clear()
    }

    $script:LogFileInitialised = $false
    Write-Log "File logging: OFF (OVERSEER_PRINT_LOGS=false)" "WARNING"
}

Write-Host ""
Write-Host "Constants (loaded from .env / environment):" -ForegroundColor Cyan
Write-Host ("  WINDOWS_PRODUCT_KEY   = {0}" -f (Mask-ProductKey $global:WINDOWS_PRODUCT_KEY)) -ForegroundColor Cyan
Write-Host ("  BIOS_PASSWORD         = {0}" -f (Mask-PasswordInfo $global:BIOS_PASSWORD)) -ForegroundColor Cyan
Write-Host ("  OVERSEER_PASSWORD     = {0}" -f (Mask-PasswordInfo $global:OVERSEER_PASSWORD)) -ForegroundColor Cyan
Write-Host ("  TIMEZONE_ID           = {0}" -f $global:TIMEZONE_ID) -ForegroundColor Cyan
Write-Host ("  OVERSEER_PRINT_LOGS   = {0}" -f $(if ($script:LogToFile) { "true" } else { "false" })) -ForegroundColor Cyan
Write-Host ("  Toggles (TEST)        = OfficeLicense={0}, MonitorAgent={1}, DeviceInfo={2}, Apps={3}, Taskbar={4}" -f `
        $script:ApplyOfficeLicenseEnabled, $script:InstallMonitoringAgentEnabled, $script:RunDeviceInformationEnabled, $script:RunAppsSectionEnabled, $script:ConfigureTaskbarEnabled) -ForegroundColor Cyan
if ((-not $script:ApplyOfficeLicenseEnabled) -or (-not $script:InstallMonitoringAgentEnabled) -or (-not $script:RunDeviceInformationEnabled) -or (-not $script:RunAppsSectionEnabled) -or (-not $script:ConfigureTaskbarEnabled)) {
    Write-Host "  Note                 = Toggle=false still runs in TEST mode" -ForegroundColor Cyan
}

# -------------------------------
# [2/6] Device Information + proposed name
# -------------------------------
Write-Host "`n[2/6] Device Information" -ForegroundColor White
Write-Host "-----------------------------------------------" -ForegroundColor White

if (-not $script:RunDeviceInformationEnabled) {
    Write-Log "Device Information: disabled (toggle false)" "WARNING"
}

$Serial = $null
$Model = $null
$Manufacturer = $null
$SerialTag = $null
$ProposedName = $null

try {
    $bios = Get-CimInstance Win32_BIOS
    $system = Get-CimInstance Win32_ComputerSystem
    $systemProduct = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue

    $Serial = $bios.SerialNumber
    $Model = $system.Model
    $Manufacturer = $system.Manufacturer
    $uuid = if ($systemProduct) { $systemProduct.UUID } else { $null }

    $SerialTag = Get-SerialTag -Serial $Serial -FallbackUuid $uuid
    $ProposedName = Build-ComputerName -SerialTag $SerialTag

    $serialDisplay = if ($Serial) { $Serial } else { "<unknown>" }

    Write-Log ("Device: {0} {1}" -f $Manufacturer, $Model) "INFO"
    Write-Log ("Serial tag: {0} (raw: {1})" -f $SerialTag, $serialDisplay) "INFO"
    Write-Log ("Proposed Name: {0}" -f $ProposedName) "SUCCESS"
}
catch {
    Write-Log ("Device information failed: {0}" -f $_.Exception.Message) "ERROR"
    Mark-Error
}

# -------------------------------
# [3/6] Monitoring Installer Selection + Validation
# -------------------------------
Write-Host "`n[3/6] Monitoring Installer" -ForegroundColor White
Write-Host "-----------------------------------------------" -ForegroundColor White

if (-not $script:InstallMonitoringAgentEnabled) {
    Write-Log "Monitoring: disabled (toggle false)" "WARNING"
}

$script:UsedDefaultMonitoringInstaller = $false
$script:SelectedMonitoringInstaller = $null

try {
    if (-not $monitoringExists) {
        Write-Log ("Monitoring folder missing: {0}" -f (Short-Path $MonitoringPath)) "ERROR"
        Mark-Error
    }
    else {
        $MsiFiles = Get-MonitoringMsiFiles

        if (-not $MsiFiles -or $MsiFiles.Count -eq 0) {
            Write-Log "No monitoring MSI files found" "ERROR"
            Mark-Error
        }
        else {
            $msiNames = ($MsiFiles | Select-Object -ExpandProperty Name)
            $msiList = ($msiNames -join ", ")
            Write-Log ("MSI installers ({0}): {1}" -f $MsiFiles.Count, $msiList) "INFO"

            if ($Model) {
                $selected = Select-MonitoringInstaller -Model $Model -MsiFiles $MsiFiles
                if ($selected) {
                    $script:SelectedMonitoringInstaller = $selected
                    $isDefault = ($selected.BaseName -match '^default')
                    if ($isDefault) {
                        $script:UsedDefaultMonitoringInstaller = $true
                        Write-Log ("Selected MSI: {0} (default fallback; model '{1}' not matched)" -f $selected.Name, $Model) "WARNING"
                    }
                    else {
                        Write-Log ("Selected MSI: {0} (model match)" -f $selected.Name) "SUCCESS"
                    }
                }
                else {
                    Write-Log ("No MSI could be selected for model '{0}' (and no default*.msi present)" -f $Model) "ERROR"
                    Mark-Error
                }
            }
            else {
                Write-Log "Device model not detected - cannot select monitoring installer" "ERROR"
                Mark-Error
            }
        }
    }
}
catch {
    Write-Log ("Monitoring selection/validation failed: {0}" -f $_.Exception.Message) "ERROR"
    Mark-Error
}

# -------------------------------
# [4/6] Apps Installer Check
# -------------------------------
Write-Host "`n[4/6] Apps" -ForegroundColor White
Write-Host "-----------------------------------------------" -ForegroundColor White

if (-not $script:RunAppsSectionEnabled) {
    Write-Log "Apps: disabled (toggle false)" "WARNING"
}

try {
    if (-not $appsExists) {
        Write-Log ("Apps folder missing: {0}" -f (Short-Path $AppsPath)) "ERROR"
        Mark-Error
    }
    else {
        $netExtenderPath = Join-Path $AppsPath 'NetExtender.msi'
        $ninitePath = Join-Path $AppsPath 'Ninite.exe'
        $dellCommandUpdatePath = Join-Path $AppsPath 'Dell-Command-Update.exe'

        if (Test-Path $netExtenderPath) {
            Write-Log ("NetExtender installer: {0}" -f (Short-Path $netExtenderPath)) "SUCCESS"
        }
        else {
            Write-Log ("NetExtender installer missing: {0}" -f (Short-Path $netExtenderPath)) "ERROR"
            Mark-Error
        }

        if (Test-Path $ninitePath) {
            Write-Log ("Ninite installer: {0}" -f (Short-Path $ninitePath)) "SUCCESS"
        }
        else {
            Write-Log ("Ninite installer missing: {0}" -f (Short-Path $ninitePath)) "ERROR"
            Mark-Error
        }

        if (Test-Path $dellCommandUpdatePath) {
            Write-Log ("Dell Command Update installer: {0}" -f (Short-Path $dellCommandUpdatePath)) "SUCCESS"
        }
        else {
            Write-Log ("Dell Command Update installer missing: {0}" -f (Short-Path $dellCommandUpdatePath)) "ERROR"
            Mark-Error
        }
    }
}
catch {
    Write-Log ("Apps check failed: {0}" -f $_.Exception.Message) "ERROR"
    Mark-Error
}

# -------------------------------
# [5/6] Office Installer Check
# -------------------------------
Write-Host "`n[5/6] Office" -ForegroundColor White
Write-Host "-----------------------------------------------" -ForegroundColor White

if (-not $script:ApplyOfficeLicenseEnabled) {
    Write-Log "Office licensing: disabled (toggle false)" "WARNING"
}

try {
    if (-not $officeExists) {
        Write-Log ("Office folder missing: {0}" -f (Short-Path $OfficePath)) "ERROR"
        Mark-Error
    }
    else {
        $officeSetupPath = Join-Path $OfficePath 'setup.exe'
        $officeConfigPath = Join-Path $OfficePath 'configuration-O2019BCC.xml'

        $setupOk = Test-Path $officeSetupPath
        $cfgOk = Test-Path $officeConfigPath

        if ($setupOk) { Write-Log ("Office setup: {0}" -f (Short-Path $officeSetupPath)) "SUCCESS" }
        else { Write-Log ("Office setup missing: {0}" -f (Short-Path $officeSetupPath)) "ERROR"; Mark-Error }

        if ($cfgOk) { Write-Log ("Office config: {0}" -f (Short-Path $officeConfigPath)) "SUCCESS" }
        else { Write-Log ("Office config missing: {0}" -f (Short-Path $officeConfigPath)) "ERROR"; Mark-Error }
    }
}
catch {
    Write-Log ("Office check failed: {0}" -f $_.Exception.Message) "ERROR"
    Mark-Error
}

# -------------------------------
# [6/6] Provisioning Simulation (NO CHANGES APPLIED)
# -------------------------------
Write-Host "`n[6/6] Simulation (no changes applied)" -ForegroundColor White
Write-Host "-----------------------------------------------" -ForegroundColor White

# Step 1: Overseer local user -> Administrators (check only)
$adminCheck = Test-OverseerAdminMembership -UserName 'Overseer'
if (-not $adminCheck.Found) {
    Write-Log "Overseer user: not found" "WARNING"
}
elseif ($adminCheck.IsAdmin) {
    Write-Log ("Overseer user: Administrator ({0})" -f $adminCheck.Name) "SUCCESS"
}
else {
    Write-Log ("Overseer user: NOT Administrator ({0})" -f $adminCheck.Name) "WARNING"
}

# Step 2: Connectivity + Wi-Fi adapter/driver check
$script:WifiDriverActionRequired = $false
$netState = Get-NetworkState
if ($netState.AnyConnected) {
    if ($netState.EthernetConnected) { Write-Log "Network: Connected (Ethernet)" "SUCCESS" }
    elseif ($netState.WifiConnected) { Write-Log "Network: Connected (Wi-Fi)" "SUCCESS" }
    else { Write-Log "Network: Connected" "SUCCESS" }
}
else {
    if ($netState.WifiAdapterFound) {
        Write-Log "Network: Not connected (Wi-Fi adapter detected)" "WARNING"
    }
    else {
        Write-Log "Network: Not connected (no Wi-Fi adapter detected)" "WARNING"
        $script:WifiDriverActionRequired = $true
    }

    # Also check whether a Wi-Fi driver package exists for the technician to install
    $wifiPkg = Find-WifiDriverPackage -SearchPath $DriversPath
    if ($wifiPkg) {
        Write-Log ("Wi-Fi driver package: {0}" -f (Short-Path $wifiPkg.FullName)) "INFO"
    }
    else {
        Write-Log "Wi-Fi driver package: MISSING (installers\\drivers)" "WARNING"
    }
}

Write-Log ("SIM: Set timezone -> tzutil /s `"{0}`"" -f $global:TIMEZONE_ID) "INFO"

if ($ProposedName) {
    Write-Log ("SIM: Rename PC -> {0}" -f $ProposedName) "INFO"
}
else {
    Write-Log "SIM: Rename PC -> <unknown>" "WARNING"
}

# Taskbar (Windows 11) - simulated only
if (-not $script:ConfigureTaskbarEnabled) {
    Write-Log "Taskbar: disabled (toggle false)" "WARNING"
}
Write-Log "SIM: Taskbar -> align left, hide Task View, hide Widgets" "INFO"

if ([string]::IsNullOrWhiteSpace($global:WINDOWS_PRODUCT_KEY)) {
    Write-Log "SIM: Windows key -> MISSING" "WARNING"
    Mark-Error
}
else {
    Write-Log ("SIM: Windows key -> Changepk.exe /ProductKey {0}" -f (Mask-ProductKey $global:WINDOWS_PRODUCT_KEY)) "INFO"
}

if ([string]::IsNullOrWhiteSpace($global:OVERSEER_PASSWORD)) {
    Write-Log "SIM: Local user 'Overseer' -> password MISSING (OVERSEER_ACCOUNT_PASSWORD)" "WARNING"
    Mark-Error
}
else {
    Write-Log ("SIM: Local user 'Overseer' -> enable + set password {0}" -f (Mask-PasswordInfo $global:OVERSEER_PASSWORD)) "INFO"
}

if ([string]::IsNullOrWhiteSpace($global:BIOS_PASSWORD)) {
    Write-Log "SIM: BIOS admin password -> MISSING (BIOS_PASSWORD)" "WARNING"
    Mark-Error
}
else {
    Write-Log ("SIM: BIOS admin password -> DellBIOSProvider {0}" -f (Mask-PasswordInfo $global:BIOS_PASSWORD)) "INFO"
}

# Office install + licensing (simulated regardless of toggle in TEST script)
if ((Test-Path (Join-Path $OfficePath 'setup.exe')) -and (Test-Path (Join-Path $OfficePath 'configuration-O2019BCC.xml'))) {
    $officeSetupSimPath = Join-Path $OfficePath 'setup.exe'
    $officeConfigSimPath = Join-Path $OfficePath 'configuration-O2019BCC.xml'
    Write-Log ("SIM: Office download -> {0} /configure {1}" -f (Short-Path $officeSetupSimPath), (Short-Path $officeConfigSimPath)) "INFO"
}
else {
    Write-Log "SIM: Office download -> SKIPPED (installer/config missing)" "WARNING"
}

if (-not $script:ApplyOfficeLicenseEnabled) {
    Write-Log "SIM: Office licensing -> disabled (toggle false)" "WARNING"
}

if (-not $script:InstallMonitoringAgentEnabled) {
    Write-Log "SIM: Monitoring -> disabled (toggle false)" "WARNING"
}

if ($script:UsedDefaultMonitoringInstaller) {
    Write-Log "SIM: Monitoring installer -> Default" "WARNING"
}

if ($script:SelectedMonitoringInstaller) {
    Write-Log ("SIM: Monitoring download -> msiexec /i {0} /qn" -f (Short-Path $script:SelectedMonitoringInstaller.FullName)) "INFO"
}
else {
    Write-Log "SIM: Monitoring download -> SKIPPED (no MSI selected)" "WARNING"
}

# -------------------------------
# Completion
# -------------------------------
Write-Host "`n================================================" -ForegroundColor White
Write-Host " Overseer Test Complete" -ForegroundColor White
Write-Host "================================================" -ForegroundColor White

Write-Log "Dry run complete (no installers executed, no system changes applied)" "INFO"

if ($script:UnhandledErrorCount -gt 0) {
    Write-Log ("Unhandled errors captured: {0}" -f $script:UnhandledErrorCount) "ERROR"
}

if ($script:HadErrors) {
    Write-Log "Result: COMPLETED WITH ERRORS (see output/log)" "ERROR"
}
else {
    if ($script:UsedDefaultMonitoringInstaller) {
        Write-Log "Result: SUCCESS (used default monitoring MSI)" "WARNING"
    }
    else {
        Write-Log "Result: SUCCESS" "SUCCESS"
    }
}

# -------------------------------
# Ctrl + D exit (ConsoleHost only)
# -------------------------------
Write-Host ""

if ($script:WifiDriverActionRequired) {
    Write-Host ""
    Write-Host "ACTION REQUIRED: Install the Dell Wi-Fi driver from .\\installers\\drivers and connect to Wi-Fi." -ForegroundColor Yellow
}

Write-Host "Press Ctrl + D to exit..." -ForegroundColor White

try {
    if ($Host.Name -ne 'ConsoleHost') {
        exit 0
    }

    while ($true) {
        $keyInfo = [Console]::ReadKey($true)
        $isCtrl = (($keyInfo.Modifiers -band [ConsoleModifiers]::Control) -ne 0)
        if ($isCtrl -and $keyInfo.Key -eq 'D') { break }
    }
}
catch {
    exit 0
}

# -------------------------------
# .env additions (for reference)
# -------------------------------
# OVERSEER_RUN_DEVICE_INFORMATION=true|false
# OVERSEER_RUN_APPS=true|false
# OVERSEER_CONFIGURE_TASKBAR=true|false
