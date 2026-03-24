# Allow script execution for this process
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

# Ensure we don't throw if $PSCommandPath is null (happens when compiled with PS2EXE)
if ($PSCommandPath) {
    try { Unblock-File -Path $PSCommandPath -ErrorAction SilentlyContinue } catch {}
}

# Get script or executable path robustly
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $ScriptRoot = [System.IO.Path]::GetDirectoryName([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    }
}

# In dev, Run_Overseer.ps1 is typically in scripts\packager, so Overseer.ps1 relative path is ..\..\
# PS2EXE compiles to Run_Overseer.exe which might sit in root or packager depending on user intent.
# First, try to see if Overseer.ps1 is in the SAME directory.
$Script = Join-Path $ScriptRoot 'Overseer.ps1'

# Fallback: Maybe it's two directories up (in root while script is in scripts\packager).
if (-not (Test-Path $Script)) {
    $TargetScriptPath = Join-Path $ScriptRoot '..\..\Overseer.ps1'
    if (Test-Path $TargetScriptPath) {
        $Script = (Resolve-Path $TargetScriptPath).ProviderPath
    }
}

if (-not (Test-Path $Script)) { 
    Write-Warning "Could not find Overseer.ps1 relative to $ScriptRoot"
    Read-Host "Press Enter to exit..."
    exit 1 
}

Start-Process powershell.exe `
    -Verb RunAs `
    -WindowStyle Maximized `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Script`""