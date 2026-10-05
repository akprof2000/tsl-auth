@echo off
rem Стенд примеров TSL Auth для Windows: запуск scripts\samples.ps1 в PowerShell 7 (pwsh), а если его нет — в Windows PowerShell.
rem   samples.cmd              запустить (образ из реестра GitFlic)
rem   samples.cmd -Build       собрать образ из исходников и запустить
rem   samples.cmd stop         остановить (данные сохраняются)
rem   samples.cmd clean        остановить и удалить данные
chcp 65001 >nul
set "PS=pwsh"
where pwsh >nul 2>nul || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0samples.ps1" %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
