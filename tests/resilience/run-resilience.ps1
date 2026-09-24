# Тесты отказоустойчивости TSL Auth с переподъёмом.
# Для каждого сценария: фоновый непрерывный трафик (client_credentials + refresh) через точку входа,
# действие (остановка/убийство/рестарт), восстановление и проверки:
#   • сессия (refresh-токен), созданная ДО отказа, работает ПОСЛЕ восстановления;
#   • ключи подписи (JWKS) не изменились — ранее выданные JWT остаются валидными;
#   • ошибки во время сценария посчитаны (ожидаемые — только при полном отказе).
# Отчёт: tests/artifacts/resilience/report.md
#
#   pwsh tests/resilience/run-resilience.ps1 -Mode single   # SQLite, docker-compose.yml
#   pwsh tests/resilience/run-resilience.ps1 -Mode ha       # PostgreSQL + 3 узла + nginx, docker-compose.ha.yml
# В кластере сценарии обращаются и к отдельным узлам, поэтому поверх docker-compose.ha.yml накладывается
# docker-compose.ha-nodes.yml (узлы на 127.0.0.1:8081–8083; в штатной конфигурации узлы наружу не публикуются).
param(
    [ValidateSet("single", "ha", "all")] [string]$Mode = "all",
    [string]$ClientId = "admin-cli",
    [string]$ClientSecret = "demo-admin-cli-secret-2026",
    [string]$User = "alice",
    [string]$Password = "Demo-Passw0rd!",
    [string]$PublicClient = "load-test-client"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$artifacts = Join-Path $root "tests/artifacts/resilience"
New-Item -ItemType Directory -Force $artifacts | Out-Null
$results = [System.Collections.Generic.List[object]]::new()
# Точка входа: порт из AUTH_PORT (как в compose), чтобы тест можно было запустить рядом с другим стендом на 8080.
$Lb = "http://localhost:$(if ($env:AUTH_PORT) { $env:AUTH_PORT } else { 8080 })"
# Узлы опубликованы только на 127.0.0.1 (docker-compose.ha-nodes.yml) — обращаемся к ним именно так: localhost
# на Windows сначала пробует ::1, и соединение висит до таймаута вместо быстрого отказа.
$HaCompose = @("-f", "docker-compose.ha.yml", "-f", "docker-compose.ha-nodes.yml")

# ---------------------------------------------------------------- helpers
function Wait-Ready([string]$url, [int]$timeoutSec = 90) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        try { if ((Invoke-WebRequest "$url/health/ready" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { return $sw.Elapsed.TotalSeconds } } catch { }
        Start-Sleep -Milliseconds 500
    }
    # Диагностика в журнал CI: без неё видно только таймаут, а причина (не стартовал узел, nginx, БД) теряется.
    Write-Host "Сервис $url не поднялся за $timeoutSec с. Состояние контейнеров:" -ForegroundColor Red
    docker ps -a --format "table {{.Names}}	{{.Status}}	{{.Ports}}" | Write-Host
    foreach ($name in docker ps -a --format "{{.Names}}" | Where-Object { $_ -like "tsl-auth*" }) {
        Write-Host "--- $name (последние 25 строк)" -ForegroundColor Yellow
        docker logs --tail 25 $name 2>&1 | Write-Host
    }
    throw "Сервис $url не поднялся за $timeoutSec с"
}

function Token([string]$url, [hashtable]$body) {
    Invoke-RestMethod "$url/connect/token" -Method Post -Body $body -TimeoutSec 10
}

function Ensure-PublicClient([string]$url) {
    $t = Token $url @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; scope = "tsl-auth-admin" }
    $h = @{ Authorization = "Bearer $($t.access_token)" }
    try { Invoke-RestMethod "$url/api/admin/applications/$PublicClient" -Headers $h | Out-Null }
    catch {
        Invoke-RestMethod "$url/api/admin/applications" -Method Post -Headers $h -ContentType "application/json" `
            -Body (@{ clientId = $PublicClient; clientType = "public"; grantTypes = @("password", "refresh_token") } | ConvertTo-Json) | Out-Null
    }
}

function New-Session([string]$url) {
    $r = Token $url @{ grant_type = "password"; client_id = $PublicClient; username = $User; password = $Password; scope = "openid offline_access" }
    return $r.refresh_token
}

function Use-Session([string]$url, [string]$refresh) {
    $r = Token $url @{ grant_type = "refresh_token"; client_id = $PublicClient; refresh_token = $refresh }
    return $r.refresh_token
}

# Фоновый трафик: client_credentials в цикле, счётчики ok/ошибок.
function Start-Traffic([string]$url) {
    $state = [hashtable]::Synchronized(@{ ok = 0; fail = 0; stop = $false; firstFail = $null; lastFail = $null })
    $job = Start-ThreadJob -ArgumentList $url, $state, $ClientId, $ClientSecret -ScriptBlock {
        param($url, $state, $id, $secret)
        while (-not $state.stop) {
            try {
                $null = Invoke-RestMethod "$url/connect/token" -Method Post -TimeoutSec 5 -Body @{
                    grant_type = "client_credentials"; client_id = $id; client_secret = $secret; scope = "tsl-auth-admin" }
                $state.ok++
            }
            catch {
                $state.fail++
                $now = Get-Date
                if (-not $state.firstFail) { $state.firstFail = $now }
                $state.lastFail = $now
            }
            Start-Sleep -Milliseconds 50
        }
    }
    return @{ Job = $job; State = $state }
}

function Stop-Traffic($traffic) {
    $traffic.State.stop = $true
    $traffic.Job | Wait-Job -Timeout 15 | Out-Null
    $traffic.Job | Remove-Job -Force
    $s = $traffic.State
    $window = if ($s.firstFail) { [math]::Round(($s.lastFail - $s.firstFail).TotalSeconds, 1) } else { 0 }
    return @{ Ok = $s.ok; Fail = $s.fail; FailWindow = $window }
}

function Scenario([string]$mode, [string]$name, [string]$expectation, [scriptblock]$action, [string]$entry = $Lb, [bool]$expectOutage = $false) {
    Write-Host "`n=== [$mode] $name ===" -ForegroundColor Cyan
    $jwksBefore = (Invoke-WebRequest "$entry/.well-known/jwks" -UseBasicParsing).Content
    $session = New-Session $entry
    $traffic = Start-Traffic $entry
    Start-Sleep -Seconds 2
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $notes = ""
    try { $notes = & $action } catch { $notes = "ОШИБКА ДЕЙСТВИЯ: $($_.Exception.Message)" }
    $recovery = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Start-Sleep -Seconds 3
    $t = Stop-Traffic $traffic

    $sessionOk = $false; $jwksOk = $false
    try { $session = Use-Session $entry $session; $sessionOk = $true } catch { }
    try { $jwksOk = ((Invoke-WebRequest "$entry/.well-known/jwks" -UseBasicParsing).Content -eq $jwksBefore) } catch { }

    $errorsOk = $expectOutage -or $t.Fail -eq 0
    $passed = $sessionOk -and $jwksOk -and $errorsOk -and -not "$notes".StartsWith("ОШИБКА")
    $results.Add([pscustomobject]@{
        Mode = $mode; Scenario = $name; Expectation = $expectation
        Requests = $t.Ok + $t.Fail; Errors = $t.Fail; ErrorWindowSec = $t.FailWindow; ActionSec = $recovery
        SessionSurvived = $sessionOk; KeysSame = $jwksOk; Notes = "$notes"; Passed = $passed
    })
    $color = if ($passed) { "Green" } else { "Red" }
    Write-Host ("  -> {0}: запросов {1}, ошибок {2} (окно {3} c), сессия {4}, ключи {5} {6}" -f `
        ($(if ($passed) { "OK" } else { "FAIL" })), ($t.Ok + $t.Fail), $t.Fail, $t.FailWindow, $sessionOk, $jwksOk, $notes) -ForegroundColor $color
}

# ---------------------------------------------------------------- single (SQLite)
function Run-Single {
    Write-Host "`n##### Одиночный режим (SQLite) #####" -ForegroundColor Yellow
    docker compose @HaCompose down 2>&1 | Out-Null
    docker compose up -d 2>&1 | Out-Null
    Wait-Ready $Lb | Out-Null
    & pwsh -NoProfile -File samples/seed-demo.ps1 -Issuer $Lb | Out-Null
    Ensure-PublicClient $Lb

    Scenario "single" "Штатный перезапуск контейнера" "простой только на время рестарта; сессии и ключи сохраняются" {
        docker restart tsl-auth | Out-Null; $s = Wait-Ready $Lb; "подъём за $([math]::Round($s,1)) c"
    } -expectOutage $true

    Scenario "single" "Аварийное убийство процесса (SIGKILL)" "после kill -9 и старта данные целы (SQLite WAL), сессии работают" {
        docker kill -s KILL tsl-auth | Out-Null; Start-Sleep 2; docker start tsl-auth | Out-Null
        $s = Wait-Ready $Lb; "подъём за $([math]::Round($s,1)) c"
    } -expectOutage $true

    Scenario "single" "Пересоздание контейнера (новая версия образа)" "том с БД и мастер-ключом сохраняется; сессии работают" {
        docker compose up -d --force-recreate 2>&1 | Out-Null; $s = Wait-Ready $Lb; "подъём за $([math]::Round($s,1)) c"
    } -expectOutage $true
}

# ---------------------------------------------------------------- HA (PostgreSQL, 3 узла)
function Run-Ha {
    Write-Host "`n##### Кластер (PostgreSQL + 3 узла + nginx) #####" -ForegroundColor Yellow
    docker compose down 2>&1 | Out-Null
    # Вывод не глушим: ошибка compose (переменные, порты, образы) должна быть видна в журнале.
    docker compose @HaCompose up -d 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "docker compose (кластер) завершился с кодом $LASTEXITCODE" }
    Wait-Ready $Lb | Out-Null; foreach ($p in 8081, 8082, 8083) { Wait-Ready "http://127.0.0.1:$p" | Out-Null }
    & pwsh -NoProfile -File samples/seed-demo.ps1 -Issuer $Lb | Out-Null
    Ensure-PublicClient $Lb

    # Синхронизация состояния между узлами: сессия создана на узле 1, используется на узле 2, отзывается через узел 3.
    Write-Host "`n=== [ha] Синхронизация состояния между узлами ===" -ForegroundColor Cyan
    $r1 = New-Session "http://127.0.0.1:8081"
    $r2 = Use-Session "http://127.0.0.1:8082" $r1
    $t = Token "http://127.0.0.1:8083" @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; scope = "tsl-auth-admin" }
    $h = @{ Authorization = "Bearer $($t.access_token)" }
    $userId = (Invoke-RestMethod "http://127.0.0.1:8083/api/admin/users?search=$User" -Headers $h).items[0].id
    Invoke-RestMethod "http://127.0.0.1:8083/api/admin/users/$userId/sessions" -Method Delete -Headers $h | Out-Null
    $revoked = $false; try { Use-Session "http://127.0.0.1:8081" $r2 | Out-Null } catch { $revoked = $true }
    $results.Add([pscustomobject]@{ Mode = "ha"; Scenario = "Синхронизация: вход на узле 1 → refresh на 2 → отзыв на 3"
        Expectation = "отзыв на любом узле мгновенно действует на всех"; Requests = 3; Errors = 0; ErrorWindowSec = 0; ActionSec = 0
        SessionSurvived = $true; KeysSame = $true; Notes = "отозванная сессия отклонена узлом 1: $revoked"; Passed = $revoked })
    Write-Host "  -> отзыв через узел 3 применился на узле 1: $revoked" -ForegroundColor $(if ($revoked) { "Green" } else { "Red" })

    Scenario "ha" "3 узла: поочерёдный рестарт (rolling)" "без ошибок для клиентов: балансировщик уводит трафик" {
        foreach ($n in 1..3) { docker stop -t 10 "tsl-auth-$n" | Out-Null; Start-Sleep 2; docker start "tsl-auth-$n" | Out-Null; Wait-Ready "http://127.0.0.1:808$n" | Out-Null }
        "узлы перезапущены по одному"
    }

    Scenario "ha" "3 узла: постепенный отказ до 1 узла и возврат" "работает, пока жив хотя бы один узел" {
        docker stop -t 10 tsl-auth-1 | Out-Null; Start-Sleep 3
        docker stop -t 10 tsl-auth-2 | Out-Null; Start-Sleep 3
        docker start tsl-auth-1 tsl-auth-2 | Out-Null
        Wait-Ready "http://127.0.0.1:8081" | Out-Null; Wait-Ready "http://127.0.0.1:8082" | Out-Null
        "оставался только узел 3"
    }

    Scenario "ha" "3 узла: аварийное убийство одного (SIGKILL)" "остальные узлы продолжают без ошибок" {
        docker kill -s KILL tsl-auth-2 | Out-Null; Start-Sleep 5; docker start tsl-auth-2 | Out-Null
        Wait-Ready "http://127.0.0.1:8082" | Out-Null; "узел 2 убит и поднят"
    }

    Scenario "ha" "3 узла: полный отказ всех узлов" "простой на время отказа; после подъёма сессии и ключи целы" {
        docker kill -s KILL tsl-auth-1 tsl-auth-2 tsl-auth-3 | Out-Null; Start-Sleep 5
        docker start tsl-auth-1 tsl-auth-2 tsl-auth-3 | Out-Null
        $s = Wait-Ready $Lb; "подъём кластера за $([math]::Round($s,1)) c"
    } -expectOutage $true

    # Стабильное исходное состояние после полного отказа: все узлы готовы, и nginx вернул их в ротацию
    # (после ошибки узел исключается на fail_timeout=5s, deploy/nginx.conf). Иначе остановка узла 3 сразу
    # после подъёма могла оставить балансировщик без «живых» узлов — ошибка теста, а не отказоустойчивости.
    foreach ($p in 8081, 8082, 8083) { Wait-Ready "http://127.0.0.1:$p" | Out-Null }
    Start-Sleep 6
    Wait-Ready $Lb | Out-Null
    docker stop tsl-auth-3 | Out-Null  # режим «2 узла»
    Scenario "ha" "2 узла: отказ одного и возврат" "второй узел обслуживает без ошибок" {
        docker stop -t 10 tsl-auth-1 | Out-Null; Start-Sleep 5; docker start tsl-auth-1 | Out-Null
        Wait-Ready "http://127.0.0.1:8081" | Out-Null; "узел 1 перезапущен"
    }

    Scenario "ha" "2 узла: полный отказ обоих" "простой; после подъёма сессии и ключи целы" {
        docker kill -s KILL tsl-auth-1 tsl-auth-2 | Out-Null; Start-Sleep 5
        docker start tsl-auth-1 tsl-auth-2 | Out-Null
        $s = Wait-Ready $Lb; "подъём за $([math]::Round($s,1)) c"
    } -expectOutage $true
    docker start tsl-auth-3 | Out-Null; Wait-Ready "http://127.0.0.1:8083" | Out-Null

    Scenario "ha" "Отказ PostgreSQL и возврат" "узлы не падают, /health/ready=503, после возврата БД — самовосстановление без рестарта узлов" {
        docker stop tsl-auth-postgres | Out-Null; Start-Sleep 5
        $code = try { (Invoke-WebRequest "$Lb/health/ready" -UseBasicParsing -TimeoutSec 5).StatusCode } catch { $_.Exception.Response.StatusCode.value__ }
        $alive = (docker ps --filter "name=tsl-auth-" --filter "status=running" --format '{{.Names}}' | Where-Object { $_ -match 'tsl-auth-\d' }).Count
        docker start tsl-auth-postgres | Out-Null
        $s = Wait-Ready $Lb 120
        "при отказе БД: ready=$code, живых узлов $alive/3; восстановление за $([math]::Round($s,1)) c"
    } -expectOutage $true

    Scenario "ha" "Перезапуск балансировщика nginx" "кратковременный простой точки входа; узлы и сессии не затронуты" {
        docker restart tsl-auth-lb | Out-Null; $s = Wait-Ready $Lb; "nginx поднят за $([math]::Round($s,1)) c"
    } -expectOutage $true
}

if ($Mode -in "single", "all") { Run-Single }
if ($Mode -in "ha", "all") { Run-Ha }

# ---------------------------------------------------------------- отчёт
$lines = @("# Отчёт: тесты отказоустойчивости TSL Auth", "", "Дата: $(Get-Date -Format 'yyyy-MM-dd HH:mm')", "",
    "| Режим | Сценарий | Ожидание | Запросов | Ошибок | Окно ошибок, с | Сессия сохранилась | Ключи те же | Итог | Примечание |",
    "|---|---|---|---|---|---|---|---|---|---|")
foreach ($r in $results) {
    $lines += "| $($r.Mode) | $($r.Scenario) | $($r.Expectation) | $($r.Requests) | $($r.Errors) | $($r.ErrorWindowSec) | " +
              "$(if ($r.SessionSurvived) { 'да' } else { 'НЕТ' }) | $(if ($r.KeysSame) { 'да' } else { 'НЕТ' }) | " +
              "$(if ($r.Passed) { '✅' } else { '❌' }) | $($r.Notes) |"
}
$lines | Set-Content (Join-Path $artifacts "report.md")
$results | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $artifacts "report.json")
$failed = @($results | Where-Object { -not $_.Passed }).Count
Write-Host "`nИтог: $($results.Count - $failed)/$($results.Count) сценариев пройдено. Отчёт: $artifacts/report.md" -ForegroundColor $(if ($failed) { "Red" } else { "Green" })
exit $failed
