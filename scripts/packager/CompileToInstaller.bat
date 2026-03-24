<# :
@echo off
setlocal
set "BAT_ROOT=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression $([System.IO.File]::ReadAllText('%~f0'))"
endlocal
goto :eof
#>

# Allow script execution for this process just to be safe
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

try {
    # Get script paths safely depending on whether we ran as .bat or directly
    $Root = if ($PSScriptRoot) { $PSScriptRoot } elseif ($env:BAT_ROOT) { $env:BAT_ROOT.TrimEnd('\') } else { $PWD.Path }
    $InputFile = Join-Path $Root 'Run_Overseer.ps1'
    $IconFile = Join-Path $Root 'DakTech Favicon.ico'
    $OutputFile = Join-Path $Root 'Run_Overseer.exe' # Save within scripts/packager

    # Check if input files exist
    if (-not (Test-Path $InputFile)) {
        throw "Input script not found: $InputFile"
    }

    if (-not (Test-Path $IconFile)) {
        Write-Warning "Icon file not found: $IconFile. Proceeding without custom icon."
        $IconFile = $null
    }

    # Install/Import PS2EXE module if missing
    if (-not (Get-Command Invoke-PS2EXE -ErrorAction SilentlyContinue)) {
        Write-Host "PS2EXE module (Invoke-PS2EXE) not found. Attempting install for current user..." -ForegroundColor Cyan
        try {
            # Ensure NuGet package provider is installed silently
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction SilentlyContinue
            }
            # Set PSGallery as trusted temporarily if it isn't, so it won't prompt
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            Install-Module -Name ps2exe -Scope CurrentUser -Force -SkipPublisherCheck -Confirm:$false -ErrorAction Stop
        } catch {
            throw "Failed to install PS2EXE module automatically. Please install it manually with 'Install-Module ps2exe'."
        }
    }

    Write-Host "Compiling '$($InputFile | Split-Path -Leaf)' into '$($OutputFile | Split-Path -Leaf)'..." -ForegroundColor Green

    # Use splatting for cleaner command call
    $ps2exeParams = @{
        InputFile  = $InputFile
        OutputFile = $OutputFile
        noConsole  = $true
        x64        = $true
        Title      = "Overseer Installer"
        Description= "Automated Device Provisioning System"
        Company    = "DakTech"
        Product    = "Overseer"
        Copyright  = "Casey Summers (2026)"
    }

    if ($IconFile) {
        $ps2exeParams.IconFile = $IconFile
    }

    # Execute compilation
    Invoke-PS2EXE @ps2exeParams

    if (Test-Path $OutputFile) {
        Write-Host "Successfully compiled to: $OutputFile" -ForegroundColor Green
    } else {
        throw "Compilation failed. Output file was not created."
    }
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "$($_.ScriptStackTrace)" -ForegroundColor Gray
}
finally {
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
