# Нагрузочный тест: k6 в контейнере против запущенного стенда. Результат — tests/artifacts/load/<имя>.json + вывод k6.
param(
    [string]$BaseUrl = "http://host.docker.internal:8080",
    [string]$Name = "single",
    [int]$Vus = 20,
    [string]$Duration = "60s",
    [string]$ClientId = "admin-cli",
    [string]$ClientSecret = "demo-admin-cli-secret-2026",
    [int]$Users = 10,                       # размер пула пользователей load-01..load-NN (создаются при первом запуске)
    [string]$Password = "Demo-Passw0rd!",
    [string]$PublicClient = "load-test-client"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifacts = Join-Path $root "tests/artifacts/load"
New-Item -ItemType Directory -Force $artifacts | Out-Null

# Public-клиент с password/refresh для теста (создаётся один раз через Admin API).
$api = $BaseUrl -replace "host.docker.internal", "localhost"

# Сервис мог только что (пере)создаться — ждём готовности, иначе первые запросы оборвутся.
$ready = $false
for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
    try { $ready = (Invoke-WebRequest "$api/health/ready" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { Start-Sleep 2 }
}
if (-not $ready) { throw "Сервис $api не готов за 3 минуты" }
$t = Invoke-RestMethod "$api/connect/token" -Method Post -Body @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; scope = "tsl-auth-admin" }
$H = @{ Authorization = "Bearer $($t.access_token)" }
try { Invoke-RestMethod "$api/api/admin/applications/$PublicClient" -Headers $H | Out-Null }
catch {
    Invoke-RestMethod "$api/api/admin/applications" -Method Post -Headers $H -ContentType "application/json" -Body (@{
        clientId = $PublicClient; clientType = "public"; grantTypes = @("password", "refresh_token") } | ConvertTo-Json) | Out-Null
}

# Пул пользователей для входов по паролю: у каждого VU своя учётная запись (см. auth-load.js).
$pool = 1..$Users | ForEach-Object { "load-{0:d2}" -f $_ }
foreach ($name in $pool) {
    $found = Invoke-RestMethod "$api/api/admin/users?search=$name" -Headers $H
    if (-not ($found.items | Where-Object userName -eq $name)) {
        Invoke-RestMethod "$api/api/admin/users" -Method Post -Headers $H -ContentType "application/json" -Body (@{
            userName = $name; email = "$name@load.local"; displayName = "Нагрузочный тест"; password = $Password } | ConvertTo-Json) | Out-Null
    }
}

# Образ k6 закреплён по digest: версия инструмента не меняется незаметно между прогонами, результаты сравнимы.
$usersArg = $pool -join ","
docker run --rm --user root --add-host=host.docker.internal:host-gateway -v "${PSScriptRoot}:/scripts" -v "${artifacts}:/out" `
    -e BASE_URL=$BaseUrl -e VUS=$Vus -e DURATION=$Duration -e CLIENT_ID=$ClientId -e CLIENT_SECRET=$ClientSecret `
    -e "USERS=$usersArg" -e PASSWORD=$Password -e PUBLIC_CLIENT=$PublicClient `
    grafana/k6:2.3.0@sha256:9c2dee7f8ed74d317e4027c06a10f169b625638189de8d4555d0b3486a5aeb34 run --summary-export "/out/$Name.json" /scripts/auth-load.js
exit $LASTEXITCODE
