@echo off
rem Запуск демо «Документооборот» (samples\docflow-demo).
set PS=pwsh
where pwsh >nul 2>nul || set PS=powershell
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0samples\docflow-demo\start.ps1" %*
pause
