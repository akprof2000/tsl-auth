# Готовит .env примера до первого старта TSL Auth: генерирует секрет клиента Admin API (BOOTSTRAP_API_CLIENT_SECRET),
# если его ещё нет. В репозитории секретов примера нет — у каждого стенда свои случайные значения.
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env"
$lines = @(if (Test-Path $envFile) { Get-Content $envFile })
if ($lines | Where-Object { $_ -match '^BOOTSTRAP_API_CLIENT_SECRET=.+' }) { exit 0 }
# Том TSL Auth уже есть, а секрета в .env нет: клиент admin-cli создан со старым значением по умолчанию,
# новый секрет он не примет. Старое значение было публичным — такой стенд пересоздаётся.
if (& docker volume ls -q --filter "name=^tsl-auth-docflow_auth-data$" 2>$null) {
    Write-Host "[ОШИБКА] Пример создан со старым общим секретом Admin API. Пересоздайте его: docflow-stop.cmd clean, затем docflow-start.cmd."
    exit 1
}
$bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$secret = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
$lines += "BOOTSTRAP_API_CLIENT_SECRET=$secret"
Set-Content -Path $envFile -Value $lines
Write-Host "Секрет клиента Admin API сгенерирован в $envFile"
