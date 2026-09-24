# Локальный запуск API или бота без Docker: секреты и адрес TSL Auth берутся из .env (его создаёт seed.ps1).
#   ./run-local.ps1 api   → http://localhost:5200 (раздаёт и собранную PWA: cd web; npm run build)
#   ./run-local.ps1 bot   → http://localhost:5201
param([ValidateSet("api", "bot")][string]$Component = "api")
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) { throw "Нет $envFile — сначала запустите seed.ps1" }
$cfg = @{}
Get-Content $envFile | ForEach-Object { $k, $v = $_ -split "=", 2; if ($k) { $cfg[$k] = $v } }

$env:Auth__Issuer = $cfg.DOCFLOW_ISSUER
if ($Component -eq "api") {
    $env:Auth__ClientSecret = $cfg.DOCFLOW_API_SECRET
    dotnet run --project (Join-Path $PSScriptRoot "api") --no-launch-profile
} else {
    $env:Auth__BotClientSecret = $cfg.DOCFLOW_BOT_SECRET
    dotnet run --project (Join-Path $PSScriptRoot "bot") --no-launch-profile
}
