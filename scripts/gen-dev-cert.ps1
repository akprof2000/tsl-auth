# Самоподписанный сертификат для проверки HTTPS (НЕ для продуктива — используйте сертификат вашего УЦ).
# Результат: certs/tls.crt, certs/tls.key. Openssl берётся из контейнера alpine — локально ставить ничего не нужно.
param([string]$HostName = "localhost")

# Корень репозитория — каталог выше scripts/; туда же смотрят compose-файлы (./certs).
$root = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force "$root/certs" | Out-Null
# SAN обязателен: браузеры не принимают сертификат только с CN. chmod 644 — чтобы файлы
# читал непривилегированный пользователь сервиса (UID 1654).
docker run --rm -v "${root}/certs:/certs" alpine:3 sh -c @"
apk add --no-cache openssl >/dev/null && \
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout /certs/tls.key -out /certs/tls.crt -subj '/CN=$HostName' \
  -addext 'subjectAltName=DNS:$HostName,DNS:localhost,IP:127.0.0.1' && \
chmod 644 /certs/tls.crt /certs/tls.key
"@
Write-Host "Готово: $root/certs/tls.crt, tls.key"
