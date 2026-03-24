@echo off
setlocal

set "ROOT=%~dp0"
set "PS1=%ROOT%Overseer_test.ps1"

start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" ^
  -NoProfile -ExecutionPolicy Bypass ^
  -Command "Set-Location -LiteralPath '%ROOT%'; & '%PS1%'"

endlocal