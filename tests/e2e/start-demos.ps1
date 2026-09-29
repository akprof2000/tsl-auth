# Запуск четырёх демо-приложений для E2E-стенда (UI-автотесты): .NET MVC 5101, Node SPA 5102, Go API 5103, Python 5104.
# Секреты клиентов — из samples/.env.demo (пишет samples/seed-demo.ps1). Вывод каждого приложения — в tests/artifacts/demo:
# при падении UI-тестов причина часто в самом приложении, а без журнала её не увидеть. Процессы остаются работать
# после выхода скрипта (их гасит конец задания CI или tests/e2e/stop-demos.ps1).
param([string]$Issuer = "http://localhost:8080/", [string]$GoApiUrl = "http://localhost:5103")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$logs = Join-Path $root "tests/artifacts/demo"
New-Item -ItemType Directory -Force $logs | Out-Null

function Start-Demo([string]$name, [string]$exe, [string[]]$arguments, [string]$dir) {
    Start-Process $exe -ArgumentList $arguments -WorkingDirectory (Join-Path $root $dir) `
        -RedirectStandardOutput (Join-Path $logs "$name.out.log") -RedirectStandardError (Join-Path $logs "$name.err.log") | Out-Null
}
$s = @{}; Get-Content (Join-Path $root "samples/.env.demo") | ForEach-Object { $k, $v = $_ -split '=', 2; $s[$k] = $v }
$env:AUTH_ISSUER = $Issuer
$env:CLIENT_SECRET = $s.GO_CLIENT_SECRET
Start-Demo go-api go @('run', '.') samples/go-api
Start-Demo node-spa node @('server.mjs') samples/node-spa
$env:CLIENT_SECRET = $s.PYTHON_CLIENT_SECRET
Start-Demo python-app python @('app.py') samples/python-app
$env:Auth__ClientSecret = $s.DOTNET_CLIENT_SECRET; $env:Auth__Issuer = $Issuer; $env:GoApiUrl = $GoApiUrl; $env:ASPNETCORE_URLS = 'http://localhost:5101'
Start-Demo dotnet-mvc dotnet @('run', '-c', 'Release') samples/dotnet-mvc

foreach ($p in 5101, 5102, 5103, 5104) {
    $up = $false
    for ($i = 0; $i -lt 120 -and -not $up; $i++) {
        try { Invoke-WebRequest "http://localhost:$p/health" -UseBasicParsing -TimeoutSec 2 | Out-Null; $up = $true } catch { Start-Sleep 2 }
    }
    if (-not $up) { Write-Host "Демо-приложение на порту $p не поднялось (журналы — tests/artifacts/demo)"; exit 1 }
    Write-Host "demo $p up"
}
