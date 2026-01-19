# Created by Casey Summers (2026) | Used for setting up Dell devices for BCC
# Version 1.5.0

$global:SECTIONS = @(
    "Folder Structure",
    "Load .Env",
    "Pre-script Checks",
    "Dependancies",
    "Device Information",
    "Monitoring Software",
    "Applications",
    "Office Suite",
    "Provisioning",
    "BIOS Configuration"
)

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

$global:OVERSEER_HAD_ERRORS = $false
$global:OVERSEER_ERROR_COUNT = 0

function Main {
    Write-Header "Overseer - Automated Provisioning Script (By Casey & DakTech)"

    Write-Section "Folder Structure"
    Write-Ok "Root: $ROOT"
    $script:logsPath = Assert-Folder "logs"
    $script:scriptsPath = Assert-Folder "scripts"
    $script:installersPath = Assert-Folder "installers"
    $appsPath = Assert-Folder "installers/apps"
    $dependenciesPath = Assert-Folder "installers/dependencies"
    $script:driversPath = Assert-Folder "installers/drivers"
    $monitoringPath = Assert-Folder "installers/monitoring"
    $officePath = Assert-Folder "installers/office"
    $envPath = Assert-Folder ".env"

    Write-Section "Load .Env"
    $envKeys = Import-DotEnv $envPath
    foreach ($name in $envKeys) {
        $raw = [Environment]::GetEnvironmentVariable($name, 'Process')

        # Censors sensitive values
        $value = switch -Regex ($name) {
            'PASSWORD' { Format-SecretValue $raw }
            'KEY' { Format-ProductKey  $raw }
            default { $raw }
        }

        # Displays values set to false clearly
        if ($raw -eq 'false') { Write-Warn "$name = $value" }
        else { Write-Ok "$name = $value" }
    }
    
    Write-Section "Pre-script Checks"
    Test-IsAdmin
    Test-IsOverseer
    Test-HasWiFi
    
    Write-Section "Dependancies"
    if ($env:FETCH_DEPENDENCIES -eq 'true') {

        $niniteExe = Join-Path $dependenciesPath 'Ninite-NET-VC++2015.exe'
        if (-not (Test-Path -LiteralPath $niniteExe)) { throw "Missing dependency bundle: $niniteExe" }

        Invoke-Task `
            -Command {
            Unblock-File -LiteralPath $niniteExe -ErrorAction SilentlyContinue
            Start-Process $niniteExe } `
            -MaxAttempts 3 `
            -RetryDelaySeconds 10 `
            -SkipIf {
            # Visual C++ v14 (x64)
            $vcInstalled =
            (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' `
                -ErrorAction SilentlyContinue).Installed -eq 1

            # .NET Desktop Runtime 8+
            $dotnetInstalled =
            Get-ItemProperty `
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
                -ErrorAction SilentlyContinue |
            Where-Object DisplayName -like '*Windows Desktop Runtime*' |
            Where-Object DisplayName -match '\b(8|9|1\d)\.' |
            Select-Object -First 1

            $vcInstalled -and $dotnetInstalled } `
            -SkipMessage ".NET Desktop 8+ and VC++ v14 already installed. Skipping." `
            -StartMessage "Installing .NET Desktop 8+ and VC++ v14 (Ninite)..." `
            -SuccessMessage ".NET Desktop 8+ and VC++ v14 installed."
    }
    else {
        Write-Warn "Dependencies section disabled in `".env`"."
    }

    Write-Section "Device Information"
    if ($env:GET_DEVICE_INFORMATION -eq 'true') {
        $system = Get-CimInstance Win32_ComputerSystem
        $model = $system.Model
        $serial = (Get-CimInstance Win32_BIOS).SerialNumber
        $prefix = $env:Device_Prefix

        Write-Info "Prefix      : $prefix"
        Write-Info "Manufacturer: $($system.Manufacturer)"
        Write-Info "Model       : $model"
        Write-Info "Serial No.  : $serial"

        $proposedName = "$prefix$serial" -replace '\s+', '' -replace '[^A-Za-z0-9-]', ''
        Write-Ok "Proposed name: $proposedName"

        Invoke-Task `
            -Command {
            try {
                Rename-Computer -NewName $proposedName -Force -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Message -match 'same as the current name') {
                    Write-Warn "Device rename already pending or matches current name. Restart required."
                }
                else { throw }
            }
            Write-Ok "Device renamed to '$proposedName'. Restart required."
            Write-Warn "Provisioning will stop here so the rename applies before installs."
            Write-Info "Press any key to restart this device..."
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            Restart-Computer -Force
            exit 0 } `
            -SkipIf { (hostname) -eq $proposedName } `
            -SkipMessage "New name matches existing name. Skipping." `
            -StartMessage "Renaming device to '$proposedName'..." `
            -SuccessMessage "Rename complete."
    }
    else {
        Write-Warn "Device Information section disabled in `".env`"."
    }

    Write-Section "Monitoring Software"
    if ($env:INSTALL_MONITORING_SOFTWARE -eq 'true') {

        $installers = Get-ChildItem -Path $monitoringPath -File -Filter *.msi
        if ($installers) {
            Write-Info "Ninja installers ($($installers.Count)): $($installers.Name -join ', ')"

            $modelRaw = [string]$model
            $modelKey = ($modelRaw -replace '[^0-9A-Za-z]', '').ToLower()
            $match = $installers | Where-Object { $_.BaseName.ToLower().Contains($modelKey) } | Select-Object -First 1

            if ($match) {
                $ninjaInstaller = $match.Name
                Write-Ok "Matched installer for cleaned key '$modelKey': $ninjaInstaller"
            }
            else {
                $ninjaInstaller = 'Default.msi'
                Write-Warn "No installer found for cleaned key '$modelKey'. Using $ninjaInstaller."
            }
        }
        else {
            Write-Warn "Ninja installers (0): none"
            $ninjaInstaller = 'Default.msi'
        }

        # Runs the Ninja Installer
        Invoke-Task `
            -ExePath (Join-Path $monitoringPath $ninjaInstaller) `
            -SkipIf { Get-Service -Name "NinjaRMMAgent" -ErrorAction SilentlyContinue } `
            -SkipMessage "Ninja Agent $ninjaInstaller is already installed. Skipping." `
            -StartMessage "Installing Ninja using $ninjaInstaller..." `
            -SuccessMessage "Ninja Software successfully installed using $ninjaInstaller."
    }
    else {
        Write-Warn "Monitoring Software section disabled in `".env`"."
    }

    Write-Section "Applications"
    if ($env:INSTALL_APPS -eq 'true') {

        $installers = Get-ChildItem -Path $appsPath -File | Where-Object { $_.Extension -in '.msi', '.exe' }
        if ($installers) {
            Write-Info "Application installers ($($installers.Count)): $($installers.Name -join ', ')"

            # Installs each file within the 'apps' folder
            foreach ($installer in $installers) {
                $appName = [IO.Path]::GetFileNameWithoutExtension($installer.Name)
                $pattern = Get-AppSearchPattern -InstallerBaseName $appName

                Invoke-Task `
                    -ExePath $installer.FullName `
                    -SkipIf { Get-Package -Name $pattern -ErrorAction SilentlyContinue } `
                    -SkipMessage "Application already installed: $appName. Skipping." `
                    -StartMessage "Installing application: $appName..." `
                    -SuccessMessage "'$appName' successfully launched."
            }
        }
        else {
            Write-Warn "Application installers (0): none"
        }
    }
    else {
        Write-Warn "Applications section disabled in `".env`"."
    }

    Write-Section "Office Suite"
    if ($env:INSTALL_OFFICE_SUITE -eq 'true') {

        # Assigns Education license unless already present
        Invoke-Task `
            -ExePath "$env:SystemRoot\System32\changepk.exe" `
            -Arguments "/ProductKey $($env:WINDOWS_PRODUCT_KEY)" `
            -SkipIf {
            if ([string]::IsNullOrWhiteSpace($env:WINDOWS_PRODUCT_KEY)) { return $true }
            $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
            $editionText = @($cv.EditionID, $cv.CompositionEditionID, $cv.ProductName) -join ' '
            $isEdu = ($editionText -match 'Education')
            $lic = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue |
            Select-Object -First 1 LicenseStatus
            $isActivated = ($lic.LicenseStatus -eq 1)
            return ($isEdu -and $isActivated) } `
            -SkipMessage "Windows is already Education and activated. Skipping." `
            -StartMessage "Applying Windows Education product key..." `
            -SuccessMessage "Product key applied successfully."

        # Installs Office 2019 Suite
        Invoke-Task `
            -ExePath "$officePath\setup.exe" `
            -Arguments "/configure `"$officePath\configuration-O2019BCC.xml`"" `
            -WindowStyle Hidden `
            -SkipIf { Get-Package -Name 'Microsoft Office*' -ErrorAction SilentlyContinue } `
            -SkipMessage "Office already installed. Skipping." `
            -StartMessage "Installing Office suite..." `
            -SuccessMessage "Office Suite installer launched."

        # Applies Office 2019 key
        Invoke-Task `
            -Command {
            $osppPath = @(
                Join-Path $env:ProgramFiles 'Microsoft Office\Office16\ospp.vbs'
                Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\Office16\ospp.vbs'
            ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

            if (-not $osppPath) { throw "ospp.vbs not found (Office not installed yet?)." }

            & cscript.exe //nologo $osppPath /inpkey:$env:OFFICE_PRODUCT_KEY | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Failed to apply Office key (exit code $LASTEXITCODE)." }

            & cscript.exe //nologo $osppPath /act | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Failed to activate Office (exit code $LASTEXITCODE)." }

            $verifyText = ((& cscript.exe //nologo $osppPath /dstatus 2>$null) -join "`n")
            if ($verifyText -notmatch 'LICENSE STATUS:\s*---LICENSED---') {
                throw "Office did not report LICENSED after activation."
            } } `
            -SkipIf {
            if ([string]::IsNullOrWhiteSpace($env:OFFICE_PRODUCT_KEY)) { return $true }

            $osppPath = @(
                Join-Path $env:ProgramFiles 'Microsoft Office\Office16\ospp.vbs'
                Join-Path ${env:ProgramFiles(x86)} 'Microsoft Office\Office16\ospp.vbs'
            ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

            if (-not $osppPath) { return $true }

            $desiredLast5 = ($env:OFFICE_PRODUCT_KEY -split '-')[-1]
            $statusText = ((& cscript.exe //nologo $osppPath /dstatus 2>$null) -join "`n")

            if ($statusText -match 'Last 5 characters of installed product key:\s*([A-Z0-9]{5})') {
                return ($Matches[1] -eq $desiredLast5)
            }
            return $false } `
            -SkipMessage "Office already licensed with expected key. Skipping." `
            -StartMessage "Checking/applying Office 2019 license..." `
            -SuccessMessage "Office 2019 license applied and verified."
    }
    else {
        Write-Warn "Office Suite section disabled in `".env`"."
    }

    Write-Section "Provisioning"
    if ($env:PROVISION_CUSTOMISATION -eq 'true') {
        
        # Sets timezone and syncs system time
        Invoke-Task `
            -Command {
            Set-TimeZone -Id $env:TIMEZONE_ID
            Start-Service w32time -ErrorAction SilentlyContinue
            w32tm /resync /force | Out-Null } `
            -SkipIf { (Get-TimeZone).Id -eq $env:TIMEZONE_ID } `
            -SkipMessage "Timezone already set to $env:TIMEZONE_ID. Skipping." `
            -StartMessage "Setting Timezone to $env:TIMEZONE_ID and syncing time..." `
            -SuccessMessage "Timezone set and system time synced."

        # Disables sleeping and screen dimming on AC power
        Invoke-Task `
            -Command {
            # powercfg /change monitor-timeout-ac 0        | Out-Null
            powercfg /change standby-timeout-ac 0        | Out-Null
            powercfg /change hibernate-timeout-ac 0      | Out-Null } `
            -SkipIf {
            $scheme = (powercfg /getactivescheme) -replace '.*:\s*([0-9a-fA-F-]{36}).*', '$1'
            # $screen = powercfg /q $scheme SUB_VIDEO VIDEOIDLE
            $sleep = powercfg /q $scheme SUB_SLEEP STANDBYIDLE
            $hiber = powercfg /q $scheme SUB_SLEEP HIBERNATEIDLE
            # ($screen -match 'Current AC Power Setting Index:\s*0x00000000') -and
            ($sleep -match 'Current AC Power Setting Index:\s*0x00000000') -and
            ($hiber -match 'Current AC Power Setting Index:\s*0x00000000') } `
            -SkipMessage "Power and display already set to never turn off on AC. Skipping." `
            -StartMessage "Disabling sleep, hibernate, and screen timeout when plugged in..." `
            -SuccessMessage "Sleeping and hibernating disabled successfully."

        # Enforces English Australia preference device-wide
        Invoke-Task `
            -Command {
            $langs = Get-WinUserLanguageList
            # Ensure en-AU exists
            if (-not ($langs.LanguageTag -contains 'en-AU')) { $langs.Add((New-WinUserLanguageList 'en-AU')[0]) }
            # Remove en-US
            $langs = $langs | Where-Object LanguageTag -ne 'en-US'
            Set-WinUserLanguageList $langs -Force
            # Set system defaults for all future users
            Set-WinSystemLocale en-AU
            Set-WinDefaultInputMethodOverride -InputTip '0c09:00000409'
            Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true } `
            -SkipIf {
            (Get-WinUserLanguageList).LanguageTag -contains 'en-AU' -and
            -not ((Get-WinUserLanguageList).LanguageTag -contains 'en-US') -and
            (Get-WinSystemLocale).Name -eq 'en-AU' } `
            -SkipMessage "English (Australia) already enforced as preferred language. Skipping." `
            -StartMessage "Enforcing English (Australia) as preferred system language..." `
            -SuccessMessage "English (Australia) set as preferred language for current and future users."

        # Elevates Overseer to Administrator
        Invoke-Task `
            -Command { Add-LocalGroupMember -Group 'Administrators' -Member $env:ADMIN_NAME } `
            -SkipIf { Get-LocalGroupMember -Group 'Administrators' | Where-Object { $_.Name -match "\\$($env:ADMIN_NAME)$" } } `
            -SkipMessage "User '$($env:ADMIN_NAME)' is already a member of the Administrators group. Skipping." `
            -StartMessage "Adding user '$($env:ADMIN_NAME)' to the Administrators group..." `
            -SuccessMessage "User '$($env:ADMIN_NAME)' successfully added to the Administrators group."

        # Sets Overseer profile password
        Invoke-Task `
            -Command { 
            $securePassword = ConvertTo-SecureString -String $env:OVERSEER_ACCOUNT_PASSWORD -AsPlainText -Force
            Set-LocalUser -Name $env:USERNAME -Password $securePassword } `
            -SkipIf { $false } `
            -SkipMessage "Passord cannot be inspected, hence resetting anyway." `
            -StartMessage "Setting password for '$env:USERNAME' profile..." `
            -SuccessMessage "Password successfully set for '$env:USERNAME' profile."

        # Customises Taskbar
        Invoke-Task `
            -Command {
            $advancedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            if (-not (Test-Path $advancedKey)) { New-Item -Path $advancedKey -Force | Out-Null }

            # Left align + hide Task View (HKCU)
            Set-ItemProperty -Path $advancedKey -Name 'TaskbarAl'          -Type DWord -Value 0
            Set-ItemProperty -Path $advancedKey -Name 'ShowTaskViewButton' -Type DWord -Value 0

            # Disables Widgets
            $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Policies\Microsoft\Dsh')
            $k.SetValue('AllowNewsAndInterests', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
            $k.Close()

            # Freshes Taskbar
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Process explorer.exe } `
            -SkipIf {
            $advancedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            $cu = Get-ItemProperty -Path $advancedKey -ErrorAction SilentlyContinue
            $lm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -ErrorAction SilentlyContinue

            ($cu.TaskbarAl -eq 0) -and
            ($cu.ShowTaskViewButton -eq 0) -and
            ($lm.AllowNewsAndInterests -eq 0) } `
            -SkipMessage "Taskbar settings already configured. Skipping." `
            -StartMessage "Customising taskbar settings..." `
            -SuccessMessage "Taskbar settings customised successfully."
    }
    else {
        Write-Warn "Provisioning section disabled in `".env`"."
    }

    Write-Section "BIOS Configuration"
    if ($env:BIOS_CONFIGURATION -eq 'true') {

        # Import DellBIOSProvider
        Invoke-Task `
            -Command {
            if (-not (Get-Module -ListAvailable -Name DellBIOSProvider)) {
                Find-Module DellBIOSProvider | Out-Null
                Install-Module DellBIOSProvider -Force -ErrorAction Stop | Out-Null
            }
            Import-Module DellBIOSProvider -Force -ErrorAction Stop } `
            -StartMessage "Initialising Dell BIOS provider..." `
            -SuccessMessage "Dell BIOS provider initialised."

        # Sets BIOS Admin Password (Dell – physical devices only)
        Invoke-Task `
            -Command {
            if ([string]::IsNullOrWhiteSpace($env:BIOS_PASSWORD)) { throw 'BIOS_PASSWORD not set.' }
            # Write-Info "Would set Dell BIOS Password to `"$env:BIOS_PASSWORD`"."
            Set-Item 'DellSmbios:\Security\AdminPassword' -Value $env:BIOS_PASSWORD } `
            -SkipIf {
            try { return ((Get-Item 'DellSmbios:\Security\IsAdminPasswordSet').CurrentValue -eq $true) }
            catch { return $false } } `
            -SkipMessage "BIOS password already set. Skipping." `
            -StartMessage "Setting BIOS password..." `
            -SuccessMessage "BIOS password set."

        # Enables Secure Boot (Dell – physical devices only)
        Invoke-Task `
            -Command {
            if ([string]::IsNullOrWhiteSpace($env:BIOS_PASSWORD)) { throw 'BIOS_PASSWORD not set.' }
            # Write-Info "Using BIOS: `"$env:BIOS_PASSWORD`"."
            Set-Item `
                -Path 'DellSmbios:\SecureBoot\SecureBoot' `
                -Value 'Enabled' `
                -Password $env:BIOS_PASSWORD
            if ((Get-Item 'DellSmbios:\SecureBoot\SecureBoot').CurrentValue -ne 'Enabled') { throw 'Secure Boot enable command did not take effect.' } } `
            -SkipIf {
            try { (Get-Item 'DellSmbios:\SecureBoot\SecureBoot').CurrentValue -eq 'Enabled' }
            catch { $false } } `
            -SkipMessage "Secure Boot already enabled. Skipping." `
            -StartMessage "Enabling Secure Boot..." `
            -SuccessMessage "Secure Boot enabled."
    }
    else {
        Write-Warn "BIOS Configuration section disabled in `".env`"."
    }

    # Exits Script
    Write-Host ""
    Write-Header "Overseer Script Complete"
    if ($global:OVERSEER_HAD_ERRORS) {
        Write-Err "Result: Completed with $OVERSEER_ERROR_COUNT errors (see output/log)" -ForegroundColor Red
    }
    else { Write-Ok "Result: Completed successfully!" -ForegroundColor Green }
    Read-Host "Press enter to exit"
}

function Write-LogLine {
    param([string]$Text)
    if ($env:PRINT_LOGS_FILE -eq 'false' -or -not $script:logsPath) { return }
    if (-not $script:OverseerLogFile) {
        New-Item -ItemType Directory -Path $script:logsPath -Force | Out-Null
        $script:OverseerLogFile = Join-Path $script:logsPath ("Overseer_{0}.txt" -f (Get-Date -Format 'dd-MM-yyyy_HH-mm-ss'))
    }
    Add-Content -Path $script:OverseerLogFile -Value $Text -Encoding UTF8
}

function Write-Err {
    param([string]$Message)

    $global:OVERSEER_HAD_ERRORS = $true
    $global:OVERSEER_ERROR_COUNT++

    Write-LogLine "[ERR]  $Message"; Write-Host    "[ERR]  $Message" -ForegroundColor Red
}

function Write-Warn {
    param([string]$Message)
    Write-LogLine "[WARN] $Message"; Write-Host    "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Message)
    Write-LogLine "[OK]   $Message"; Write-Host    "[OK]   $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-LogLine "[INFO] $Message"
    if ($env:PRINT_INFO_MESSAGES.Trim().ToLower() -eq 'true') {
        Write-Host "[INFO] $Message" -ForegroundColor White
    }
}

function Write-Header {
    param ([string]$Text, [int]$Padding = 4, [ConsoleColor]$Color = 'Cyan')

    $spaces = ' ' * $Padding
    $linelength = $Text.Length + ($Padding * 2)
    $border = '=' * $linelength

    Write-Host "$border`n$spaces$Text$spaces`n$border" -ForegroundColor $Color
}

function Write-Section {
    param ([string]$Title, [int]$Padding = 4)

    $index = $global:SECTIONS.IndexOf($Title) + 1  # Starts at 1, not 0
    $total = $global:SECTIONS.Count
    if ($index -le 0) { throw "Section '$Title' is not registered" }  # Catches sections without label
    $label = "[$index/$total] $Title"
    $border = '-' * ($label.Length + $Padding)

    Write-Host "`n$Label`n$border"
}

function Test-IsAdmin {
    if (([Security.Principal.WindowsPrincipal] `
                [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Ok "Administrator privileges confirmed."
        return
    }
    Write-Err "This script must be ran as Administrator."
    Read-Host "Press run this script as an admin"
    exit 1
}

function Test-IsOverseer {
    $systemName = $env:USERNAME.ToLower()
    $profileName = $env:ADMIN_NAME.ToLower()

    if ($systemName -ne $profileName) {
        Write-Err "System name '$systemName' does not match expected profile name '$profileName'."
        Read-Host "Please ensure the system name matches `"$profileName`" and press Enter to exit..."
        exit 1
    }
    Write-Ok "Profile name matches $profileName."
}

function Test-HasWiFi {
    Invoke-Task `
        -Command {
        if (-not (Test-InternetOrWiFi -DriverPath $driversPath -ScriptsPath $scriptsPath)) {
            throw "Wi-Fi connection not available. Cannot continue."
            exit 1
        } } `
        -StartMessage "Checking internet connection..." `
        -SuccessMessage "Wi-Fi connected."
}

function Test-InternetOrWiFi {
    param(
        [string]$DriverPath,
        [string]$ScriptsPath
    )

    function Test-Internet {
        $uris = @(
            'http://www.msftconnecttest.com/connecttest.txt',
            'https://www.msftconnecttest.com/connecttest.txt'
        )
        $oldPP = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            foreach ($uri in $uris) {
                try {
                    $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    if ($r.StatusCode -eq 200) { return $true }
                }
                catch {}
            }
            $false
        }
        finally { $ProgressPreference = $oldPP }
    }

    function Get-WiFiAdapter {
        Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -ne 'Disabled' -and (
                $_.InterfaceDescription -match 'Wireless|Wi-?Fi|802\.11' -or $_.Name -match 'Wi-?Fi|Wireless|WLAN'
            )
        } | Select-Object -First 1
    }

    function Get-ModelInfo {
        $m = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model
        $name = if ($m) { $m.ToString().Trim() } else { '' }
        $code = ([regex]::Match($name, '\b(\d{4})\b')).Groups[1].Value
        [pscustomobject]@{ Name = $name; Code = $code }
    }

    function Resolve-WiFiDriver {
        param([string]$DriverPath, [string]$ModelCode)

        $files = Get-ChildItem -Path $DriverPath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.exe', '.msi' }

        if ($ModelCode) {
            $d = $files | Where-Object {
                if (-not $ModelCode) { return $false }
                $models = ($_.BaseName -replace '^Wi-Fi-', '') -split '[_-]'
                $models -contains $ModelCode
            } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($d) { return [pscustomobject]@{ Driver = $d; Rule = "custom:$ModelCode"; Reason = "Found model-specific package for '$ModelCode'" } }
        }

        $d = $files | Where-Object { $_.BaseName -like 'Wi-Fi-default*' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($d) { return [pscustomobject]@{ Driver = $d; Rule = 'default'; Reason = 'Using Wi-Fi-default' } }

        $d = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        [pscustomobject]@{ Driver = $d; Rule = 'fallback-newest'; Reason = 'Default missing; using newest driver (legacy fallback)' }
    }

    function Install-Driver {
        param($Driver)

        Invoke-Task `
            -Command {
            if ($Driver.Extension -ieq '.msi') {
                $p = Start-Process msiexec.exe -ArgumentList "/i `"$($Driver.FullName)`" /qn /norestart" -Wait -PassThru -ErrorAction Stop
            }
            else {
                $p = Start-Process $Driver.FullName -Wait -PassThru -ErrorAction Stop
            }
            if ($p.ExitCode -notin 0, 3010) { throw "Wi-Fi driver install failed (exit $($p.ExitCode))." }
        } `
            -MaxAttempts 2 `
            -RetryDelaySeconds 5 `
            -StartMessage "Installing Wi-Fi driver: $($Driver.Name)..." `
            -SuccessMessage "Wi-Fi driver install complete."
    }

    function ConvertTo-PlainText {
        param([SecureString]$Secure)
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
        try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    function Test-ProfileAndConnect {
        param(
            [string]$Ssid,
            [SecureString]$PasswordSecure,
            [string]$ScriptsPath
        )

        $templatePath = Join-Path $ScriptsPath 'wifi_template.xml'
        if (-not (Test-Path -LiteralPath $templatePath)) { Write-Err "Missing Wi-Fi template: $templatePath"; return $false }

        if ((netsh wlan show profiles) -notmatch [regex]::Escape($Ssid)) {
            $passPlain = ConvertTo-PlainText $PasswordSecure

            $xml = (Get-Content -Path $templatePath -Raw -Encoding UTF8).
            Replace('{{SSID}}', [Security.SecurityElement]::Escape($Ssid)).
            Replace('{{PASSWORD}}', [Security.SecurityElement]::Escape($passPlain))

            $tmp = Join-Path $env:TEMP ("wifi-{0}.xml" -f $Ssid)
            $xml | Set-Content -Path $tmp -Encoding UTF8
            netsh wlan add profile filename="$tmp" user=all | Out-Null
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }

        netsh wlan connect name="$Ssid" ssid="$Ssid" | Out-Null
        $true
    }

    if (Test-Internet) { return $true }

    $ssid = $env:OVERSEER_WIFI_SSID
    $passPlainEnv = $env:OVERSEER_WIFI_PASSWORD
    if (-not $ssid -or -not $passPlainEnv) { Write-Err "No internet and missing OVERSEER_WIFI_SSID / OVERSEER_WIFI_PASSWORD."; return $false }

    $passSecure = ConvertTo-SecureString $passPlainEnv -AsPlainText -Force

    Start-Service WlanSvc -ErrorAction SilentlyContinue | Out-Null
    $model = Get-ModelInfo

    if (-not (Get-WiFiAdapter)) {
        Write-Warn "No Wi-Fi adapter detected."

        $pick = Resolve-WiFiDriver -DriverPath $DriverPath -ModelCode $model.Code
        $driver = $pick.Driver
        if (-not $driver) { Write-Err "No Wi-Fi driver package found in: $DriverPath"; return $false }
        Write-Info "Wi-Fi driver selector: Model='$($model.Name)' Code='$($model.Code)' Rule='$($pick.Rule)' Driver='$($driver.Name)' Reason='$($pick.Reason)'"
        Install-Driver -Driver $driver
        for ($attempt = 0; $attempt -lt 10 -and -not (Get-WiFiAdapter); $attempt++) { Start-Sleep -Seconds 2 }
        if (-not (Get-WiFiAdapter)) { Write-Err "Wi-Fi adapter still not detected after driver install."; return $false }
    }

    if (-not (Test-ProfileAndConnect -Ssid $ssid -PasswordSecure $passSecure -ScriptsPath $ScriptsPath)) { return $false }

    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        if (Test-Internet) { return $true }
        Start-Sleep -Seconds 2
    }

    Write-Err "Wi-Fi connect failed (no internet after connect)."
    return $false
}

function Assert-Folder {
    param([string]$Folder)

    $folderPath = Join-Path $ROOT $Folder
    if (Test-Path $folderPath) {
        Write-Ok "Found: .\$Folder"
    }
    else {
        New-Item -ItemType Directory -Path $folderPath | Out-Null
        Write-Warn "Created: .\$Folder"
    }

    return $folderPath
}

function Import-DotEnv {
    param ([string]$Path)
    $loadedKeys = @()

    Get-Content $Path | ForEach-Object {

        # Skip empty lines and comments
        if ($_ -match '^\s*$' -or $_ -match '^\s*#') { return }

        # Split only on the first =
        $name, $value = $_ -split '=', 2
        $name = $name.Trim()
        $value = $value.Trim()

        # Set into process environment
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        $loadedKeys += $name
    }
    Write-Ok ".env loaded into Process environment"
    return $loadedKeys
}

function Format-SecretValue {
    param ([string]$Value)

    if (-not $Value) { "<NOT SET>"; return }

    "<SET> ($($Value.Length) chars)"
}

function Format-ProductKey {
    param ([string]$Key)

    if ([string]::IsNullOrEmpty($Key)) { return "<NOT SET>" }

    $parts = $Key -split '-'
    if ($parts.Count -lt 5) { return "<INVALID KEY>" }

    return "*****-*****-*****-*****-$($parts[-1])"
}

function Get-AppSearchPattern {
    param([Parameter(Mandatory)][string]$InstallerBaseName)

    $clean = $InstallerBaseName `
        -replace '\bv?\d+(\.\d+){1,4}\b', '' `
        -replace '\b(x64|x86|amd64|arm64)\b', '' `
        -replace '[-_.|]+', ' ' `
        -replace '\s+', ' '
    $clean = $clean.Trim()

    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = $InstallerBaseName }
    return "*$($clean -replace ' ','*')*"
}

function Invoke-Task {
    param(
        [string]$ExePath,
        [scriptblock]$Command,
        [string]$Arguments,
        [scriptblock]$SkipIf,
        [string]$SkipMessage = 'Task already satisfied. Skipping.',
        [string]$StartMessage = 'Running task...',
        [string]$SuccessMessage = 'Task launched.',
        [int]$MaxAttempts = 1,
        [int]$RetryDelaySeconds = 5,
        [ValidateSet('Normal', 'Hidden', 'Minimized', 'Maximized')]
        [string]$WindowStyle = 'Normal',
        [switch]$Wait
    )

    if ($SkipIf -and (& $SkipIf)) { Write-Warn $SkipMessage; return }
    if ($null -eq $Arguments) { $Arguments = '' }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            if ($attempt -eq 1) { Write-Info $StartMessage } else { Write-Warn "Retrying ($attempt/$MaxAttempts)..." }

            if ($Command) {
                $old = $ErrorActionPreference; $ErrorActionPreference = 'Stop'
                try { & $Command; Write-Ok $SuccessMessage; return }
                finally { $ErrorActionPreference = $old }
            }

            if (-not $ExePath) { throw 'No command or executable specified.' }

            $sp = @{ PassThru = $true; ErrorAction = 'Stop' }
            if ($Wait) { $sp.Wait = $true }

            if ($ExePath.EndsWith('.msi', [StringComparison]::OrdinalIgnoreCase)) {
                $sp.FilePath = 'msiexec.exe'
                $sp.ArgumentList = "/i `"$ExePath`" /qn /norestart $Arguments"
            }
            else {
                $sp.FilePath = $ExePath
                $sp.WindowStyle = $WindowStyle
                if (-not [string]::IsNullOrWhiteSpace($Arguments)) { $sp.ArgumentList = $Arguments }
            }

            $proc = Start-Process @sp
            if ($Wait -and $proc.ExitCode -ne 0) { throw "Process failed (exit $($proc.ExitCode))." }

            Write-Ok $SuccessMessage
        }
        catch {
            $msg = $_.Exception.Message
            if ($attempt -ge $MaxAttempts) { Write-Err "Task failed: $msg"; return }
            Write-Warn "Task failed (attempt $attempt/$MaxAttempts): $msg"
            Start-Sleep -Seconds ($RetryDelaySeconds * $attempt)
        }
    }
}


Main 