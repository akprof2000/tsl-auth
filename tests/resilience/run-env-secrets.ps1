# MVP: секреты в переменных контейнера и в файле настроек (без OpenBao). E2E и локально:
#   ./tests/resilience/run-env-secrets.ps1 [-Port 8093]
# Сценарии:
#   1. переменные (.env): мастер-ключ, пароль администратора, секрет Admin API, пароль SMTP — сервис стартует,
#      клиент Admin API работает с секретом из переменной, мастер-ключ взят из переменной (master.key в томе нет);
#   2. перезапуск с тем же .env — данные читаются (ключ тот же);
#   3. файл настроек (appsettings.json, APPSETTINGS_PATH) с секретами, в переменных секретов нет — сервис стартует,
#      секрет Admin API из файла принимается.
# После прогона всё удаляется. Отчёт — tests/artifacts/env-secrets/report.md.
param([int]$Port = 8093)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$env:MSYS_NO_PATHCONV = "1"
# docker compose берёт переменные окружения процесса раньше --env-file: убираем унаследованные (в CI они заданы на уровне job).
foreach ($v in "AUTH_PORT", "ENCRYPTION_MASTER_KEY", "BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_API_CLIENT_ID", "BOOTSTRAP_API_CLIENT_SECRET", "SMTP_USER", "SMTP_PASSWORD") {
    Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}
$work = Join-Path ([IO.Path]::GetTempPath()) ("tsl-env-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $work | Out-Null
$report = [System.Collections.Generic.List[string]]::new()
$failed = $false
function Check($name, [scriptblock]$test) {
    try { & $test; $report.Add("| $name | ✅ |"); Write-Host "OK   $name" -ForegroundColor Green }
    catch { $report.Add("| $name | ❌ $($_.Exception.Message) |"); Write-Host "FAIL $name — $($_.Exception.Message)" -ForegroundColor Red; $script:failed = $true }
}
function WaitReady($port) {
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        try { if ((Invoke-WebRequest "http://localhost:$port/health/ready" -TimeoutSec 3 -UseBasicParsing).StatusCode -eq 200) { return } } catch { Start-Sleep 2 }
    }
    throw "сервис на порту $port не ответил за 120 с"
}
function Token($port, $secret) {
    (Invoke-RestMethod "http://localhost:$port/connect/token" -Method Post -Body @{
        grant_type = "client_credentials"; client_id = "admin-cli"; client_secret = $secret; scope = "tsl-auth-admin" }).access_token
}
function Up($compose) {
    $out = & docker compose @compose up -d --build 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker compose up: $($out | Select-Object -Last 5 | Out-String)" }
}
function SaveLogs($compose, $name) {
    $dir = "tests/artifacts/env-secrets/$name"; New-Item -ItemType Directory -Force $dir | Out-Null
    & docker compose @compose logs --no-color > "$dir/logs.txt" 2>&1
}

# ---------- 1–2. Переменные окружения (.env) ----------
$key = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$apiSecret = "env-" + [guid]::NewGuid().ToString("N")
@(
    "AUTH_PORT=$Port", "ENCRYPTION_MASTER_KEY=$key", "BOOTSTRAP_ADMIN_PASSWORD=Env-Adm1n-$([guid]::NewGuid().ToString('N').Substring(0,8))!",
    "BOOTSTRAP_API_CLIENT_ID=admin-cli", "BOOTSTRAP_API_CLIENT_SECRET=$apiSecret", "SMTP_USER=tsl", "SMTP_PASSWORD=$([guid]::NewGuid().ToString("N"))"
) | Set-Content "$work/.env"
$envCompose = @("-p", "tslenv-e2e", "--env-file", "$work/.env", "-f", "docker-compose.yml")
try {
    Up $envCompose
    Check "Переменные: сервис стартует с секретами из .env" { WaitReady $Port }
    Check "Переменные: секрет Admin API из переменной принимается" { if (-not (Token $Port $apiSecret)) { throw "нет токена" } }
    Check "Переменные: секреты дошли до контейнера (мастер-ключ, SMTP)" {
        $vars = docker inspect tsl-auth --format '{{range .Config.Env}}{{println .}}{{end}}'
        foreach ($name in "Encryption__MasterKey", "Smtp__Password", "Bootstrap__AdminApiClientSecret") {
            if (-not ($vars | Where-Object { $_ -match "^$name=.+" })) { throw "$name не задан в контейнере" }
        }
    }
    Check "Переменные: мастер-ключ из переменной, в томе не сгенерирован" {
        $files = docker run --rm -v tslenv-e2e_auth-data:/d alpine:3 ls /d
        if ($files -contains "master.key") { throw "в томе есть master.key" }
    }
    Check "Переменные: перезапуск с тем же ключом — данные читаются" {
        docker restart tsl-auth | Out-Null
        WaitReady $Port
        if (-not (Token $Port $apiSecret)) { throw "нет токена после перезапуска" }
    }
}
finally { SaveLogs $envCompose "env"; docker compose @envCompose down -v | Out-Null }

# ---------- 3. Файл настроек ----------
$fileSecret = "file-" + [guid]::NewGuid().ToString("N")
$settings = @{
    Encryption = @{ MasterKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) }
    Bootstrap  = @{ AdminApiClientId = "admin-cli"; AdminApiClientSecret = $fileSecret; AdminPassword = "Fa1-$([guid]::NewGuid().ToString("N"))!" }
    Smtp       = @{ UserName = "tsl"; Password = [guid]::NewGuid().ToString("N") }
} | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText("$work/appsettings.json", $settings, [Text.UTF8Encoding]::new($false))
@"
services:
  auth:
    environment:
      APPSETTINGS_PATH: /etc/tsl-auth/appsettings.json
      Encryption__MasterKey: ""
      Bootstrap__AdminPassword: ""
      Bootstrap__AdminApiClientSecret: ""
      Bootstrap__AdminApiClientId: ""
    volumes:
      - $($work.Replace('\', '/'))/appsettings.json:/etc/tsl-auth/appsettings.json:ro
"@ | Set-Content "$work/file.yml"
"AUTH_PORT=$($Port + 1)" | Set-Content "$work/file.env"
$fileCompose = @("-p", "tslenv-e2e-file", "--env-file", "$work/file.env", "-f", "docker-compose.yml", "-f", "$work/file.yml")
try {
    Up $fileCompose
    Check "Файл настроек: сервис стартует с секретами из appsettings.json" { WaitReady ($Port + 1) }
    Check "Файл настроек: секрет Admin API из файла принимается" { if (-not (Token ($Port + 1) $fileSecret)) { throw "нет токена" } }
}
finally { SaveLogs $fileCompose "file"; docker compose @fileCompose down -v | Out-Null; Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }

New-Item -ItemType Directory -Force tests/artifacts/env-secrets | Out-Null
@("# Секреты в переменных и файле настроек (MVP)", "", "| Сценарий | Результат |", "|---|---|") + $report |
    Set-Content tests/artifacts/env-secrets/report.md -Encoding utf8
if ($failed) { exit 1 }
Write-Host "Все сценарии MVP-секретов пройдены." -ForegroundColor Green
