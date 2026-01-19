$RootPath = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

$OverseerScript = Join-Path $RootPath 'Overseer.ps1'
if (-not (Test-Path -LiteralPath $OverseerScript)) { exit 1 }

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

# If not admin, elevate and exit
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        Start-Process powershell.exe `
            -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$OverseerScript`""
    }
    catch { exit 1 }

    exit 0
}

# Already admin → launch a visible PowerShell and exit
Start-Process powershell.exe `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$OverseerScript`""