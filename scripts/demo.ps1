# Демо-стенд TSL Auth для Windows (PowerShell 7): сервис в Docker + четыре демо-приложения
# (.NET MVC :5101, Node SPA :5102, Go API :5103, Python :5104), матрицы доступа и пользователи alice / bob.
#
#   ./scripts/demo.ps1                 — запустить: образ из реестра GitFlic (latest), стенд, демо-данные, приложения
#   ./scripts/demo.ps1 -Build          — то же, но образ собрать из исходников (docker compose build)
#   ./scripts/demo.ps1 -Image <образ>  — запустить с другим образом (например registry.gitflic.ru/...:1.5.1)
#   ./scripts/demo.ps1 stop            — остановить приложения и стенд (данные сохраняются)
#   ./scripts/demo.ps1 clean           — остановить и удалить данные стенда и секреты демо
#
# Нужны Docker Desktop, а для демо-приложений — .NET 10 SDK, Node.js ≥ 20, Go ≥ 1.22, Python ≥ 3.10.
# Секреты стенда (пароль admin, секрет клиента admin-cli) генерируются в .env при первом запуске, секреты
# демо-клиентов — в samples/.env.demo; оба файла вне git. Журналы приложений — tests/artifacts/demo.
param(
    [ValidateSet("start", "stop", "clean")] [string]$Action = "start",
    [switch]$Build,
    [string]$Image = "registry.gitflic.ru/project/uklad/tsl-auth/tsl-auth:latest"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$ports = 5101, 5102, 5103, 5104
$issuer = "http://localhost:8080"

function Stop-Demos {
    foreach ($port in $ports) {
        $owners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($id in $owners) {
            try { Stop-Process -Id $id -Force -ErrorAction Stop; Write-Host "  остановлено приложение на :$port (pid $id)" } catch { }
        }
    }
}

function Get-EnvValue([string]$name) {
    if (-not (Test-Path .env)) { return $null }
    $line = Get-Content .env | Where-Object { $_ -match "^$name=" } | Select-Object -First 1
    if ($line) { return ($line -split "=", 2)[1].Trim() }
    return $null
}

function Initialize-Env {
    # Минимальный .env для демо: без секрета admin-cli сервис не создаст клиента Admin API, и заполнить стенд нечем.
    if (-not (Test-Path .env)) { New-Item .env -ItemType File | Out-Null }
    $add = [ordered]@{}
    if (-not (Get-EnvValue "BOOTSTRAP_API_CLIENT_ID")) { $add["BOOTSTRAP_API_CLIENT_ID"] = "admin-cli" }
    if (-not (Get-EnvValue "BOOTSTRAP_API_CLIENT_SECRET")) { $add["BOOTSTRAP_API_CLIENT_SECRET"] = "demo-" + [guid]::NewGuid().ToString("N") }
    if (-not (Get-EnvValue "BOOTSTRAP_ADMIN_PASSWORD")) { $add["BOOTSTRAP_ADMIN_PASSWORD"] = "Adm-" + [guid]::NewGuid().ToString("N").Substring(0, 16) + "!9" }
    foreach ($k in $add.Keys) { Add-Content .env "$k=$($add[$k])" }
    if ($add.Count -gt 0) { Write-Host "  .env дополнен: $($add.Keys -join ', ')" }
}

switch ($Action) {
    "stop" {
        Write-Host "Остановка демо-стенда"
        Stop-Demos
        docker compose down
        return
    }
    "clean" {
        Write-Host "Остановка демо-стенда и удаление данных"
        Stop-Demos
        docker compose down -v
        Remove-Item samples/.env.demo -ErrorAction SilentlyContinue
        return
    }
}

foreach ($tool in "docker", "dotnet", "node", "go", "python") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Не найден $tool — установите его (см. заголовок скрипта)." }
}

Write-Host "1. Образ TSL Auth"
if ($Build) {
    docker compose build
} else {
    docker pull $Image
    if ($LASTEXITCODE -ne 0) { throw "Не удалось скачать $Image (нужен docker login registry.gitflic.ru или -Build)." }
    docker tag $Image tsl-auth:latest
}
if ($LASTEXITCODE -ne 0) { throw "Образ не подготовлен." }

Write-Host "2. Стенд"
Initialize-Env
docker compose up -d --no-build
$ready = $false
for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
    try { $ready = (Invoke-WebRequest "http://127.0.0.1:8080/health/ready" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { Start-Sleep 2 }
}
if (-not $ready) { throw "TSL Auth не поднялся за 3 минуты: docker logs tsl-auth" }

Write-Host "3. Демо-данные (приложения, матрицы, пользователи)"
& "$root/samples/seed-demo.ps1" -Issuer $issuer -AdminClientId (Get-EnvValue "BOOTSTRAP_API_CLIENT_ID") -AdminClientSecret (Get-EnvValue "BOOTSTRAP_API_CLIENT_SECRET")

Write-Host "4. Демо-приложения"
Stop-Demos
& "$root/tests/e2e/start-demos.ps1" -Issuer "$issuer/"

Write-Host ""
Write-Host "Готово." -ForegroundColor Green
Write-Host "  TSL Auth          $issuer   (admin / пароль BOOTSTRAP_ADMIN_PASSWORD из .env)"
Write-Host "  .NET MVC          http://localhost:5101"
Write-Host "  Node SPA          http://localhost:5102"
Write-Host "  Go API            http://localhost:5103"
Write-Host "  Python            http://localhost:5104"
Write-Host "  Пользователи      alice, bob (пароль Demo-Passw0rd!)"
Write-Host "  Остановить        ./scripts/demo.ps1 stop"
