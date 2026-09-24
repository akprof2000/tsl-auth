# Остановка демо.
#   ./stop.ps1          — остановить, данные сохраняются (следующий ./start.ps1 продолжит с ними)
#   ./stop.ps1 -Clean   — остановить и удалить все данные демо (TSL Auth, документы, секреты в .env)
param([switch]$Clean)
Set-Location $PSScriptRoot
if ($Clean) {
    docker compose down -v
    Remove-Item .env -ErrorAction SilentlyContinue
    Write-Host "Демо остановлено, данные удалены." -ForegroundColor Yellow
} else {
    docker compose down
    Write-Host "Демо остановлено. Данные сохранены." -ForegroundColor Green
}
