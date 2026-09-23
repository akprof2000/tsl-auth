# Упаковка образов для закрытого контура (выполняется на машине с доступом в интернет).
# Результат: dist/tsl-auth-images-<версия>.tar.gz + SHA256 — перенесите на целевой сервер и выполните import-images.
param(
    [string]$Version = "latest",
    [switch]$WithPostgres = $true,
    [switch]$WithNginx = $true
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

docker build -t "tsl-auth:$Version" .
$images = @("tsl-auth:$Version")
if ($WithPostgres) { docker pull postgres:17-alpine; $images += "postgres:17-alpine" }
if ($WithNginx) { docker pull nginx:1.29-alpine; $images += "nginx:1.29-alpine" }

New-Item -ItemType Directory -Force dist | Out-Null
$tar = "dist/tsl-auth-images-$Version.tar"
docker save -o $tar @images
# Сжатие gzip через контейнер (не требует локальных утилит).
docker run --rm -v "${root}/dist:/d" alpine:3 sh -c "gzip -f /d/$(Split-Path -Leaf $tar)"
$gz = "$tar.gz"
(Get-FileHash $gz -Algorithm SHA256).Hash | Set-Content "$gz.sha256"

# Вместе с образами — всё, что нужно для запуска.
Copy-Item docker-compose.yml, docker-compose.ha.yml, docker-compose.https.yml, docker-compose.ha-https.yml, .env.example dist/ -Force
Copy-Item deploy dist/ -Recurse -Force
Copy-Item scripts/import-images.sh, scripts/import-images.ps1 dist/ -Force

Write-Host "Готово: $gz ($([math]::Round((Get-Item $gz).Length / 1MB, 1)) МБ), образы: $($images -join ', ')"
Write-Host "Перенесите каталог dist/ на целевой сервер и выполните import-images.sh (Linux) или import-images.ps1 (Windows)."
