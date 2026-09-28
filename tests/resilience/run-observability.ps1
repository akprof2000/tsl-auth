# E2E стенда мониторинга на Victoria: TSL Auth (одиночный режим) + docker-compose.observability.yml.
#   ./tests/resilience/run-observability.ps1 [-Port 8096]
# Проверяет, что сервис сам в хранилища не пишет, а данные всё равно доходят:
#   1. метрики — VictoriaMetrics опрашивает /metrics сервиса и компоненты стенда (все цели up, есть tsl_auth_users);
#   2. логи — stdout контейнера сервиса (JSON) Vector через Docker socket доставляет в VictoriaLogs, поля разобраны;
#   3. трассировки — OTLP в коллектор → VictoriaTraces (сервис tsl-auth виден в Jaeger API);
#   4. Grafana (образ с плагином VictoriaLogs) — все три источника данных отвечают OK.
# Порты стенда сдвинуты, секреты генерируются. После прогона стенд, тома и собранный образ Grafana удаляются.
# Отчёт — tests/artifacts/observability/report.md.
param([int]$Port = 8096)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$env:MSYS_NO_PATHCONV = "1"
# docker compose берёт переменные процесса раньше --env-file: убираем унаследованные (в CI заданы на уровне job).
foreach ($v in "AUTH_PORT", "BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_API_CLIENT_ID", "BOOTSTRAP_API_CLIENT_SECRET", "OBS_GRAFANA_PASSWORD") {
    Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}
$report = [System.Collections.Generic.List[string]]::new()
$failed = $false
function Check($name, [scriptblock]$test) {
    try { & $test; $report.Add("| $name | ✅ |"); Write-Host "OK   $name" -ForegroundColor Green }
    catch { $report.Add("| $name | ❌ $($_.Exception.Message) |"); Write-Host "FAIL $name — $($_.Exception.Message)" -ForegroundColor Red; $script:failed = $true }
}
# Повтор проверки до таймаута: данные в хранилища приходят с задержкой (опрос 15 с, батчи Vector и коллектора).
function Eventually([scriptblock]$probe, [int]$seconds = 120) {
    $deadline = (Get-Date).AddSeconds($seconds); $last = $null
    while ((Get-Date) -lt $deadline) {
        try { $r = & $probe; if ($r) { return $r } } catch { $last = $_.Exception.Message }
        Start-Sleep 5
    }
    throw "нет результата за $seconds с $last"
}

$grafanaPassword = [guid]::NewGuid().ToString("N")
$vm = $Port + 10000; $vl = $Port + 11000; $gf = $Port + 12000
$envFile = Join-Path ([IO.Path]::GetTempPath()) ("tsl-obs-" + [guid]::NewGuid().ToString("N") + ".env")
@(
    "AUTH_PORT=$Port", "BOOTSTRAP_ADMIN_PASSWORD=Obs-$([guid]::NewGuid().ToString('N'))!",
    "OBS_PROMETHEUS_ENABLED=true", "OBS_OTLP_ENDPOINT=http://otel-collector:4317",
    "OBS_GRAFANA_PASSWORD=$grafanaPassword", "OBS_GRAFANA_PORT=$gf", "OBS_VM_PORT=$vm", "OBS_VLOGS_PORT=$vl"
) | Set-Content $envFile
$compose = @("-p", "tslobs-e2e", "--env-file", $envFile, "-f", "docker-compose.yml", "-f", "docker-compose.observability.yml")

try {
    $out = & docker compose @compose up -d --build 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker compose up: $($out | Select-Object -Last 5 | Out-String)" }
    Eventually { (Invoke-WebRequest "http://localhost:$Port/health/ready" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } | Out-Null
    # Нагрузка для span'ов и строк лога: discovery и неудачный запрос токена (пишет предупреждение в журнал).
    1..10 | ForEach-Object {
        Invoke-WebRequest "http://localhost:$Port/.well-known/openid-configuration" -UseBasicParsing | Out-Null
        try { Invoke-WebRequest "http://localhost:$Port/connect/token" -Method Post -Body @{ grant_type = "client_credentials"; client_id = "nope"; client_secret = "x" } -UseBasicParsing | Out-Null } catch { }
    }

    Check "Метрики: VictoriaMetrics опрашивает сервис и стенд, все цели up" {
        Eventually {
            $targets = (Invoke-RestMethod "http://localhost:$vm/api/v1/targets").data.activeTargets
            $down = $targets | Where-Object health -ne "up"
            $targets.Count -ge 6 -and -not $down
        } | Out-Null
    }
    Check "Метрики: метрики сервиса в VictoriaMetrics (tsl_auth_users)" {
        Eventually { (Invoke-RestMethod "http://localhost:$vm/api/v1/query?query=tsl_auth_users").data.result.Count -gt 0 } | Out-Null
    }
    Check "Логи: stdout сервиса доставлен Vector'ом в VictoriaLogs, JSON разобран на поля" {
        # Стартовые строки сервис пишет раньше, чем Vector подключается к Docker socket, а при уровнях по умолчанию
        # после старта сервис почти не пишет. Перезапуск даёт свежие строки, которые Vector уже читает.
        docker restart tsl-auth | Out-Null
        Eventually { (Invoke-WebRequest "http://localhost:$Port/health/ready" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } | Out-Null
        $line = Eventually {
            # Ответ — application/stream+json: PowerShell отдаёт такое тело байтами, поэтому декодируем явно.
            $raw = (Invoke-WebRequest "http://localhost:$vl/select/logsql/query" -Method Post -UseBasicParsing `
                -Body @{ query = 'service:"tsl-auth" _time:15m | limit 50' }).Content
            $body = if ($raw -is [byte[]]) { [Text.Encoding]::UTF8.GetString($raw) } else { [string]$raw }
            $body -split "`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.logger } | Select-Object -First 1
        }
        if (-not $line.level -or -not $line.instance) { throw "нет полей level/instance: $($line | ConvertTo-Json -Compress)" }
    }
    Check "Трассировки: сервис tsl-auth в VictoriaTraces (Jaeger API)" {
        Eventually {
            $services = docker exec tsl-auth-grafana wget -qO- http://victoriatraces:10428/select/jaeger/api/services
            ($services | ConvertFrom-Json).data -contains "tsl-auth"
        } | Out-Null
    }
    Check "Grafana: источники VictoriaMetrics, VictoriaLogs, VictoriaTraces отвечают" {
        $auth = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("admin:$grafanaPassword")) }
        foreach ($uid in "victoriametrics", "victorialogs", "victoriatraces") {
            $health = Eventually { Invoke-RestMethod "http://localhost:$gf/api/datasources/uid/$uid/health" -Headers $auth } 60
            if ($health.status -ne "OK") { throw "$uid — $($health.message)" }
        }
    }
}
finally {
    $dir = "tests/artifacts/observability"; New-Item -ItemType Directory -Force $dir | Out-Null
    & docker compose @compose logs --no-color > "$dir/logs.txt" 2>&1
    & docker compose @compose down -v --rmi local 2>&1 | Out-Null
    Remove-Item $envFile -ErrorAction SilentlyContinue
}

@("# Стенд мониторинга на Victoria", "", "| Сценарий | Результат |", "|---|---|") + $report |
    Set-Content tests/artifacts/observability/report.md -Encoding utf8
if ($failed) { exit 1 }
Write-Host "Стенд мониторинга на Victoria: все проверки пройдены." -ForegroundColor Green
