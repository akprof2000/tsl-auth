# Сквозная проверка секретов из OpenBao (E2E и локально): одиночный режим и кластер.
#   ./tests/resilience/run-openbao.ps1 [-Port 8095]
# Сценарии:
#   1. одиночный режим: openbao-init генерирует секреты, сервис стартует без секретов в окружении,
#      клиент Admin API работает с секретом из хранилища, файла master.key в томе нет;
#   2. перезапуск OpenBao (хранилище снова запечатано) → openbao-init распечатывает → перезапуск сервиса проходит;
#   3. кластер: пароль PostgreSQL файлом из OpenBao, три узла берут строку подключения и мастер-ключ из хранилища.
# После прогона всё удаляется (docker compose down -v). Отчёт — tests/artifacts/openbao/report.md.
param([int]$Port = 8095)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$env:MSYS_NO_PATHCONV = "1"
$env:AUTH_PORT = "$Port"
$report = [System.Collections.Generic.List[string]]::new()
# Выполнить проверку: ошибка не прерывает прогон, а фиксируется в отчёте и выставляет общий признак провала.
function Check($name, [scriptblock]$test) {
    try { & $test; $report.Add("| $name | ✅ |"); Write-Host "OK   $name" -ForegroundColor Green }
    catch { $report.Add("| $name | ❌ $($_.Exception.Message) |"); Write-Host "FAIL $name — $($_.Exception.Message)" -ForegroundColor Red; $script:failed = $true }
}
function WaitReady($url, $seconds = 120) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { if ((Invoke-WebRequest $url -TimeoutSec 3 -UseBasicParsing).StatusCode -eq 200) { return } } catch { Start-Sleep 2 }
    }
    throw "$url не ответил за $seconds с"
}
# Поднять стенд; при ошибке — понятное сообщение (конфликт имён контейнеров, порт занят).
function Up($compose) {
    $out = & docker compose @compose up -d --build 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker compose up: $($out | Select-Object -Last 5 | Out-String)" }
}
# Журналы всех контейнеров стенда до его удаления — для разбора в артефактах E2E.
function SaveLogs($compose, $name) {
    $dir = "tests/artifacts/openbao/$name"; New-Item -ItemType Directory -Force $dir | Out-Null
    & docker compose @compose ps -a > "$dir/ps.txt" 2>&1
    & docker compose @compose logs --no-color > "$dir/logs.txt" 2>&1
}
# Секрет Admin API читается прямо из OpenBao (в скрипте не хранится), затем по нему запрашивается токен:
# успешная выдача подтверждает, что сервис использует тот же секрет из хранилища.
function AdminToken($compose) {
    $secret = (& docker compose @compose exec -T openbao sh /openbao/scripts/bao.sh kv get -field=Bootstrap__AdminApiClientSecret secret/tsl-auth | Out-String).Trim()
    (Invoke-RestMethod "http://localhost:$Port/connect/token" -Method Post -Body @{
        grant_type = "client_credentials"; client_id = "admin-cli"; client_secret = $secret; scope = "tsl-auth-admin" }).access_token
}
$failed = $false

# ---------- Одиночный режим ----------
$single = @("-p", "tslbao-e2e", "-f", "docker-compose.yml", "-f", "docker-compose.openbao.yml")
try {
    Up $single
    Check "Одиночный режим: сервис готов с секретами из OpenBao" { WaitReady "http://localhost:$Port/health/ready" }
    Check "Секрет Admin API из хранилища принимается" { if (-not (AdminToken $single)) { throw "нет токена" } }
    Check "В окружении контейнера нет значений секретов" {
        $env = docker inspect tsl-auth --format '{{range .Config.Env}}{{println .}}{{end}}'
        $leak = $env | Where-Object { $_ -match '^(Encryption__MasterKey|Bootstrap__AdminPassword|Bootstrap__AdminApiClientSecret)=.+' }
        if ($leak) { throw "секреты в окружении: $leak" }
    }
    Check "Мастер-ключ не сгенерирован в томе (взят из OpenBao)" {
        $files = docker run --rm -v tslbao-e2e_auth-data:/d alpine:3 ls /d
        if ($files -contains "master.key") { throw "в томе есть master.key" }
    }
    Check "Перезапуск OpenBao: хранилище распечатано заново, сервис стартует" {
        docker compose @single restart openbao | Out-Null
        docker compose @single up -d | Out-Null     # openbao-init распечатывает
        docker restart tsl-auth | Out-Null
        WaitReady "http://localhost:$Port/health/ready"
        if (-not (AdminToken $single)) { throw "нет токена после перезапуска" }
    }
}
finally { SaveLogs $single "single"; docker compose @single down -v | Out-Null }

# ---------- Кластер ----------
# Кластер — на соседнем порту: Docker Desktop освобождает порт остановленного стенда не сразу.
$Port = $Port + 1
$env:AUTH_PORT = "$Port"
$ha = @("-p", "tslbao-e2e-ha", "-f", "docker-compose.ha.yml", "-f", "docker-compose.ha-openbao.yml")
try {
    Up $ha
    Check "Кластер: PostgreSQL и три узла с секретами из OpenBao" {
        WaitReady "http://localhost:$Port/health/ready" 180
        # Балансировщик отвечает уже с первым узлом — ждём, пока здоровы все три.
        $deadline = (Get-Date).AddSeconds(180)
        do {
            $unhealthy = docker compose @ha ps --format "{{.Service}} {{.Health}}" | Where-Object { $_ -match '^auth\d' -and $_ -notmatch ' healthy$' }
            if (-not $unhealthy) { break }
            Start-Sleep 3
        } while ((Get-Date) -lt $deadline)
        if ($unhealthy) { throw "узлы не готовы: $unhealthy" }
    }
    Check "Кластер: вход через балансировщик на всех узлах" { 1..6 | ForEach-Object { if (-not (AdminToken $ha)) { throw "нет токена" } } }
}
finally { SaveLogs $ha "cluster"; docker compose @ha down -v | Out-Null }

New-Item -ItemType Directory -Force tests/artifacts/openbao | Out-Null
@("# OpenBao: сквозная проверка", "", "| Сценарий | Результат |", "|---|---|") + $report | Set-Content tests/artifacts/openbao/report.md -Encoding utf8
if ($failed) { exit 1 }
Write-Host "Все сценарии OpenBao пройдены." -ForegroundColor Green
