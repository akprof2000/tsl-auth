@echo off
chcp 65001 >nul
rem Остановка демо "Документооборот".
rem   demo-stop.cmd         остановить, данные сохраняются
rem   demo-stop.cmd clean   остановить и удалить все данные демо
setlocal
cd /d "%~dp0samples\docflow-demo"
if /i "%~1"=="clean" (
  docker compose down -v
  del /q .env 2>nul
  echo Демо остановлено, данные удалены.
) else (
  docker compose down
  echo Демо остановлено. Данные сохранены.
)
pause
