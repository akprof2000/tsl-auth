# Локальный запуск API или бота без Docker для отладки. Адрес TSL Auth и секрет клиента — из .env (его пишет seed.ps1);
# если стенд запущен с OpenBao (docker-compose.openbao.yml), секрет берётся из хранилища.
#   ./run-local.ps1 api   → http://localhost:5200 (раздаёт и собранную PWA: cd web; npm run build)
#   ./run-local.ps1 bot   → http://localhost:5201
param([ValidateSet("api", "bot")][string]$Component = "api")
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) { throw "Нет $envFile — сначала запустите seed.ps1" }
$cfg = @{}
Get-Content $envFile | ForEach-Object { $k, $v = $_ -split "=", 2; if ($k) { $cfg[$k] = $v } }
$useVault = [bool](& docker ps -q --filter "name=^docflow-openbao$" 2>$null)
function Get-Secret($path, $field, $envName) {
    if (-not $useVault) {
        if (-not $cfg[$envName]) { throw "Нет $envName в .env — запустите seed.ps1" }
        return $cfg[$envName]
    }
    $out = & docker exec docflow-openbao sh /openbao/scripts/bao.sh kv get "-field=$field" "secret/$path"
    if ($LASTEXITCODE -ne 0) { throw "Нет secret/$path $field в OpenBao — запустите seed.ps1" }
    ($out | Out-String).Trim()
}

$env:Auth__Issuer = $cfg.DOCFLOW_ISSUER
if ($Component -eq "api") {
    $env:Auth__ClientSecret = Get-Secret "docflow-api" "Auth__ClientSecret" "DOCFLOW_API_SECRET"
    dotnet run --project (Join-Path $PSScriptRoot "api") --no-launch-profile
} else {
    $env:Auth__BotClientSecret = Get-Secret "docflow-bot" "Auth__BotClientSecret" "DOCFLOW_BOT_SECRET"
    dotnet run --project (Join-Path $PSScriptRoot "bot") --no-launch-profile
}
