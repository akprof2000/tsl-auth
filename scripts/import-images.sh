#!/bin/sh
# Загрузка образов в закрытом контуре: проверка контрольной суммы и docker load.
#   ./import-images.sh tsl-auth-images-latest.tar.gz
set -eu
ARCHIVE="${1:-$(ls tsl-auth-images-*.tar.gz | head -n 1)}"

if [ -f "$ARCHIVE.sha256" ]; then
  expected=$(tr -d '\r\n' < "$ARCHIVE.sha256" | tr 'A-F' 'a-f')
  actual=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
  [ "$expected" = "$actual" ] || { echo "Контрольная сумма не совпадает! Архив повреждён."; exit 1; }
  echo "Контрольная сумма OK"
fi

gunzip -c "$ARCHIVE" | docker load
echo "Образы загружены. Дальше: cp .env.example .env, заполните его и запустите:"
echo "  одиночный режим: docker compose up -d"
echo "  кластер:         docker compose -f docker-compose.ha.yml up -d"
