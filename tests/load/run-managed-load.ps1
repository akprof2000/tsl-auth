# Нагрузка подчинённых клиентов: k6 против запущенного стенда (tests/load/managed-clients.js).
# 200 подчинённых с ключами ES256 получают токены по private_key_jwt; постановка «токен каждому раз в 5 минут»
# сжата до CycleSeconds. Результат — tests/artifacts/load/<имя>.json; код выхода — код k6 (пороги).
# Пример: ./tests/load/run-managed-load.ps1 -Name managed -Clients 200 -CycleSeconds 20 -Duration 60s
param(
    [string]$BaseUrl = "http://host.docker.internal:8080",
    [string]$Name = "managed",
    [int]$Clients = 200,
    [int]$CycleSeconds = 20,
    [string]$Duration = "60s",
    [string]$ClientId = "admin-cli",
    [string]$ClientSecret = "demo-admin-cli-secret-2026"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifacts = Join-Path $root "tests/artifacts/load"
New-Item -ItemType Directory -Force $artifacts | Out-Null
$api = $BaseUrl -replace "host.docker.internal", "localhost"

$ready = $false
for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
    try { $ready = (Invoke-WebRequest "$api/health/ready" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { Start-Sleep 2 }
}
if (-not $ready) { throw "Сервис $api не готов за 3 минуты" }

# K6_LOCAL=1 — локальный k6 (CI GitFlic: стенд в docker:dind, bind-mount в контейнер k6 невозможен).
if ($env:K6_LOCAL -and (Get-Command k6 -ErrorAction SilentlyContinue)) {
    $env:BASE_URL = $api; $env:CLIENTS = "$Clients"; $env:CYCLE_SECONDS = "$CycleSeconds"; $env:DURATION = $Duration
    $env:CLIENT_ID = $ClientId; $env:CLIENT_SECRET = $ClientSecret
    k6 run --summary-export (Join-Path $artifacts "$Name.json") (Join-Path $PSScriptRoot "managed-clients.js")
    exit $LASTEXITCODE
}
docker run --rm --user root --add-host=host.docker.internal:host-gateway -v "${PSScriptRoot}:/scripts" -v "${artifacts}:/out" `
    -e BASE_URL=$BaseUrl -e CLIENTS=$Clients -e CYCLE_SECONDS=$CycleSeconds -e DURATION=$Duration `
    -e CLIENT_ID=$ClientId -e CLIENT_SECRET=$ClientSecret `
    grafana/k6:2.3.0@sha256:9c2dee7f8ed74d317e4027c06a10f169b625638189de8d4555d0b3486a5aeb34 run --summary-export "/out/$Name.json" /scripts/managed-clients.js
exit $LASTEXITCODE
