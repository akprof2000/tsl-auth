#!/bin/sh
# Самоподписанный сертификат для проверки HTTPS (НЕ для продуктива — используйте сертификат вашего УЦ).
#   ./scripts/gen-dev-cert.sh [имя-хоста]
set -eu
HOST="${1:-localhost}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/certs"
docker run --rm -v "$ROOT/certs:/certs" alpine:3 sh -c "
  apk add --no-cache openssl >/dev/null &&
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout /certs/tls.key -out /certs/tls.crt -subj '/CN=$HOST' \
    -addext 'subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1' &&
  chmod 644 /certs/tls.crt /certs/tls.key"
echo "Готово: $ROOT/certs/tls.crt, tls.key"
