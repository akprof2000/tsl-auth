# Загрузка образов в закрытом контуре (Windows): проверка контрольной суммы и docker load.
param([string]$Archive = (Get-ChildItem tsl-auth-images-*.tar.gz | Select-Object -First 1).FullName)
# По умолчанию берётся первый архив tsl-auth-images-*.tar.gz в текущем каталоге.
$ErrorActionPreference = "Stop"

# Файл .sha256 создаёт export-images.ps1; если его нет, проверка пропускается.
if (Test-Path "$Archive.sha256") {
    $expected = (Get-Content "$Archive.sha256" -Raw).Trim()
    $actual = (Get-FileHash $Archive -Algorithm SHA256).Hash
    if ($expected -ne $actual) { throw "Контрольная сумма не совпадает! Архив повреждён." }
    Write-Host "Контрольная сумма OK"
}

# docker load понимает gzip-архив напрямую.
docker load -i $Archive
Write-Host "Образы загружены. Скопируйте .env.example в .env, заполните и запустите docker compose up -d"
