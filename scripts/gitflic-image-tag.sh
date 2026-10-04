#!/bin/sh
# Дополнительные теги образа в registry.gitflic.ru копированием манифеста через Registry API, без Docker и без
# перекачки слоёв: sh scripts/gitflic-image-tag.sh sha-<коммит> 1.6.0 1.6 1
# Нужен для выпуска (теги X.Y.Z, X.Y, X на образ, который CI уже выгрузил по sha-<коммит>).
# Логин и транспортный токен — из GITFLIC_TOKENS_FILE (значения не выводятся); образ — GITFLIC_IMAGE_REPO. Нужен curl.
set -eu
KEYS="${GITFLIC_TOKENS_FILE:-/c/Projects/TSL/Key/gitflic-tokens.env}"
U="$(grep '^GITFLIC_API_USER=' "$KEYS" | cut -d= -f2- | tr -d '\r"')"
P="$(grep '^GITFLIC_TRANSPORT_TOKEN=' "$KEYS" | cut -d= -f2- | tr -d '\r"')"
REPO="${GITFLIC_IMAGE_REPO:-project/uklad/tsl-auth/tsl-auth}"
BASE=https://registry.gitflic.ru/v2/$REPO
TOK=$(curl -s -u "$U:$P" "https://registry.gitflic.ru/v2/token?service=service&scope=repository:$REPO:pull,push" | sed -E 's/.*"token":"([^"]+)".*/\1/')
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
src="$1"; shift
tmp=$(mktemp -d)
curl -sS -f -D "$tmp/h" -o "$tmp/m" -H "Authorization: Bearer $TOK" -H "Accept: $ACCEPT" "$BASE/manifests/$src"
ctype=$(grep -i '^content-type:' "$tmp/h" | head -1 | cut -d' ' -f2- | tr -d '\r')
digest=$(grep -i '^docker-content-digest:' "$tmp/h" | head -1 | cut -d' ' -f2- | tr -d '\r')
echo "$src: $digest ($ctype)"
for t in "$@"; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" -H "Content-Type: $ctype" \
    --data-binary "@$tmp/m" "$BASE/manifests/$t")
  echo "  -> $t: HTTP $code"
done
rm -rf "$tmp"
