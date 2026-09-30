@echo off
rem Демо-стенд TSL Auth для Windows: запуск scripts\demo.ps1 в PowerShell 7 (pwsh), а если его нет — в Windows PowerShell.
rem   demo.cmd              запустить (образ из реестра GitFlic)
rem   demo.cmd -Build       собрать образ из исходников и запустить
rem   demo.cmd stop         остановить (данные сохраняются)
rem   demo.cmd clean        остановить и удалить данные
chcp 65001 >nul
set "PS=pwsh"
where pwsh >nul 2>nul || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo.ps1" %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
