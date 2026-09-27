# Локальный запуск API или бота без Docker для отладки: адрес TSL Auth — из .env (его пишет seed.ps1),
# секрет клиента — из OpenBao стенда (docker compose exec openbao ...), в файлы он не сохраняется.
#   ./run-local.ps1 api   → http://localhost:5200 (раздаёт и собранную PWA: cd web; npm run build)
#   ./run-local.ps1 bot   → http://localhost:5201
param([ValidateSet("api", "bot")][string]$Component = "api")
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) { throw "Нет $envFile — сначала запустите seed.ps1" }
$issuer = ((Get-Content $envFile) -match "^DOCFLOW_ISSUER=") -replace "^DOCFLOW_ISSUER=", ""
$compose = Join-Path $PSScriptRoot "docker-compose.yml"
function Get-VaultSecret($path, $field) {
    $out = & docker compose -f $compose exec -T openbao sh /openbao/scripts/bao.sh kv get "-field=$field" "secret/$path"
    if ($LASTEXITCODE -ne 0) { throw "Нет secret/$path $field в OpenBao — запустите seed.ps1" }
    ($out | Out-String).Trim()
}

$env:Auth__Issuer = $issuer
if ($Component -eq "api") {
    $env:Auth__ClientSecret = Get-VaultSecret "docflow-api" "Auth__ClientSecret"
    dotnet run --project (Join-Path $PSScriptRoot "api") --no-launch-profile
} else {
    $env:Auth__BotClientSecret = Get-VaultSecret "docflow-bot" "Auth__BotClientSecret"
    dotnet run --project (Join-Path $PSScriptRoot "bot") --no-launch-profile
}
