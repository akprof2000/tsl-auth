@echo off
chcp 65001 >nul
rem Остановка примера "Документооборот".
rem   docflow-stop.cmd         остановить, данные сохраняются
rem   docflow-stop.cmd clean   остановить и удалить все данные примера
rem Режим clean: down -v удаляет тома (БД), затем удаляется .env - при следующем запуске секреты создаются заново.
setlocal
cd /d "%~dp0samples\docflow"
if /i "%~1"=="clean" (
  docker compose down -v
  del /q .env 2>nul
  echo Пример остановлен, данные удалены.
) else (
  docker compose down
  echo Пример остановлен. Данные сохранены.
)
pause
