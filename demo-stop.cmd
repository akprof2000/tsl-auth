@echo off
rem Остановка демо «Документооборот» (samples\docflow-demo).
set PS=pwsh
where pwsh >nul 2>nul || set PS=powershell
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0samples\docflow-demo\stop.ps1" %*
pause
