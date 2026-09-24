@echo off
chcp 65001 >nul
rem Запуск демо "Документооборот": TSL Auth, настройка, API + PWA + бот.
rem   demo-start.cmd            обычный запуск
rem   demo-start.cmd rebuild    пересобрать образы API и бота
setlocal
cd /d "%~dp0samples\docflow-demo"

where docker >nul 2>nul || (echo [ОШИБКА] Docker не найден. Установите и запустите Docker Desktop. & goto :fail)
docker info >nul 2>nul || (echo [ОШИБКА] Docker Desktop не запущен. Запустите его и повторите. & goto :fail)

echo [1/4] Запуск TSL Auth...
docker compose up -d tsl-auth || (echo [ОШИБКА] TSL Auth не запустился. Свободен ли порт 8080? & goto :fail)

echo [2/4] Ожидание готовности TSL Auth...
set /a n=0
:wait_auth
curl -fs -o nul http://localhost:8080/health/ready && goto :auth_ok
set /a n+=1
if %n% geq 60 (echo [ОШИБКА] TSL Auth не ответил за 2 минуты. & docker compose logs --tail 30 tsl-auth & goto :fail)
ping -n 3 127.0.0.1 >nul
goto :wait_auth
:auth_ok

echo [3/4] Настройка приложений, ролей и сотрудников...
set PS=pwsh
where pwsh >nul 2>nul || set PS=powershell
%PS% -NoProfile -ExecutionPolicy Bypass -File seed.ps1 || (echo [ОШИБКА] Настройка не удалась. & goto :fail)

echo [4/4] Запуск API, PWA и бота (первый раз — сборка, несколько минут)...
if /i "%~1"=="rebuild" (docker compose up -d --build) else (docker compose up -d)
if errorlevel 1 (echo [ОШИБКА] API или бот не запустились. & goto :fail)

set /a n=0
:wait_api
curl -fs -o nul http://localhost:5200/health && goto :api_ok
set /a n+=1
if %n% geq 60 (echo [ОШИБКА] Приложение не ответило. & docker compose logs --tail 30 docflow-api & goto :fail)
ping -n 3 127.0.0.1 >nul
goto :wait_api
:api_ok

echo.
echo Готово: http://localhost:5200   (TSL Auth: http://localhost:8080)
echo Сотрудники: ivanova, petrov, sidorova, kozlov, admin-doc — пароль Demo-Passw0rd!
start "" http://localhost:5200
pause
exit /b 0

:fail
pause
exit /b 1
