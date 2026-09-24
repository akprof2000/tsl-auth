# Запуск демо одной командой: TSL Auth → ожидание готовности → seed → API, PWA и бот.
#   ./start.ps1            — обычный запуск
#   ./start.ps1 -Rebuild   — пересобрать образы API и бота
param([switch]$Rebuild)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "1/4 Запуск TSL Auth..." -ForegroundColor Cyan
docker compose up -d tsl-auth
if ($LASTEXITCODE) { throw "Не удалось запустить TSL Auth. Запущен ли Docker Desktop? Свободен ли порт 8080?" }

Write-Host "2/4 Ожидание готовности TSL Auth (до 2 минут)..." -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try { if ((Invoke-WebRequest http://localhost:8080/health/ready -TimeoutSec 2 -UseBasicParsing).StatusCode -eq 200) { $ready = $true; break } }
    catch { Start-Sleep 2 }
}
if (-not $ready) { docker compose logs --tail 30 tsl-auth; throw "TSL Auth не ответил на http://localhost:8080/health/ready" }

Write-Host "3/4 Настройка приложений, ролей и сотрудников..." -ForegroundColor Cyan
& "$PSScriptRoot/seed.ps1"

Write-Host "4/4 Запуск API, PWA и бота..." -ForegroundColor Cyan
if ($Rebuild -or -not (docker images -q docflow-demo-api:latest)) { docker compose up -d --build } else { docker compose up -d }
if ($LASTEXITCODE) { throw "Не удалось запустить API или бота" }

for ($i = 0; $i -lt 30; $i++) {
    try { if ((Invoke-WebRequest http://localhost:5200/health -TimeoutSec 2 -UseBasicParsing).StatusCode -eq 200) { break } } catch { Start-Sleep 2 }
}
Write-Host ""
Write-Host "Готово: http://localhost:5200  (TSL Auth: http://localhost:8080)" -ForegroundColor Green
Write-Host "Сотрудники: ivanova, petrov, sidorova, kozlov, admin-doc — пароль Demo-Passw0rd!"
Start-Process "http://localhost:5200"
