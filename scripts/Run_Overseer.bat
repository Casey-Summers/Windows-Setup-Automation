@echo off
setlocal

set "ROOT=%~dp0"
set "PS1=%ROOT%Overseer.ps1"

powershell -NoProfile -Command ^
  "Start-Process powershell -Verb RunAs -WindowStyle Maximized -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%PS1%\"'"

endlocal
