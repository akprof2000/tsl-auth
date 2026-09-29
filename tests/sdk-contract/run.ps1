# Контрактные тесты SDK (docs/client-contract.md, §8): стенд из исходников → vectors.json → тесты пяти SDK.
# -KeepStand: не гасить стенд после тестов (для отладки). -Only dotnet,node,go,python,java — подмножество SDK.
# -NoStand: стенд уже поднят (например, в CI отдельным шагом) — только vectors и тесты.
param(
    [switch]$KeepStand,
    [switch]$NoStand,
    [string[]]$Only = @("dotnet", "node", "go", "python", "java"),
    [string]$Issuer = "http://localhost:8080/"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$env:MSYS_NO_PATHCONV = "1"

if (-not $NoStand) {
    if (-not $env:BOOTSTRAP_API_CLIENT_SECRET) { $env:BOOTSTRAP_API_CLIENT_SECRET = "sdk-" + [guid]::NewGuid().ToString("N") }
    if (-not $env:BOOTSTRAP_ADMIN_PASSWORD) { $env:BOOTSTRAP_ADMIN_PASSWORD = "Sdk-" + [guid]::NewGuid().ToString("N") + "!" }
    $env:BOOTSTRAP_API_CLIENT_ID = "admin-cli"
    # Чистый том: в старом томе прежний секрет admin-cli, и bootstrap его не перезапишет.
    docker compose down -v 2>&1 | Out-Null
    docker compose up -d --build 2>&1 | Select-Object -Last 1
    $up = $false
    for ($i = 0; $i -lt 90 -and -not $up; $i++) {
        try { $up = (Invoke-WebRequest "$($Issuer.TrimEnd('/'))/health/ready" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { Start-Sleep 2 }
    }
    if (-not $up) { throw "стенд не поднялся" }
}

$env:TSL_AUTH_ISSUER = $Issuer
$env:ADMIN_CLIENT_ID = if ($env:BOOTSTRAP_API_CLIENT_ID) { $env:BOOTSTRAP_API_CLIENT_ID } else { "admin-cli" }
$env:ADMIN_CLIENT_SECRET = if ($env:BOOTSTRAP_API_CLIENT_SECRET) { $env:BOOTSTRAP_API_CLIENT_SECRET } else { "demo-admin-cli-secret-2026" }
$vectors = Join-Path $PSScriptRoot "vectors.json"
$env:OUT = $vectors
python (Join-Path $PSScriptRoot "make-vectors.py")
if ($LASTEXITCODE -ne 0) { throw "make-vectors.py завершился с ошибкой" }
$env:SDK_CONTRACT_VECTORS = $vectors

$results = [ordered]@{}
function Run($name, [scriptblock]$body) {
    if ($Only -notcontains $name) { return }
    Write-Host "`n=== SDK: $name ===" -ForegroundColor Cyan
    Push-Location (Join-Path $root "sdk/$name")
    try { & $body; $results[$name] = if ($LASTEXITCODE -eq 0) { "OK" } else { "FAIL" } }
    catch { $results[$name] = "FAIL: $_" }
    finally { Pop-Location }
}
try {
    Run dotnet { dotnet test TslAuth.Client.sln -c Release --logger "trx;LogFileName=sdk-dotnet.trx" --results-directory (Join-Path $root "TestResults") }
    Run node   { npm test }
    Run go     { go test ./... -count=1 }
    Run python { python -m unittest discover -s tests -v }
    Run java   { if (Get-Command mvn -ErrorAction SilentlyContinue) { mvn -q -B test } else { ./mvnw -q -B test } }
}
finally {
    if (-not $NoStand -and -not $KeepStand) { docker compose down -v 2>&1 | Out-Null }
}
Write-Host "`nИтог контрактных тестов SDK:" -ForegroundColor Cyan
$results.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-8} {1}" -f $_.Key, $_.Value) }
if ($results.Values -match "FAIL") { exit 1 }
