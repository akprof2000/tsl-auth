#!/bin/sh
# Архив образа для релиза и закрытого контура прямо из registry.gitflic.ru, без Docker: формат docker save
# (OCI layout + manifest.json), каждый блоб проверяется по SHA-256; docker load его принимает (проверено 04.10.2026).
# Зачем: Docker Desktop с хранилищем containerd не сохраняет образ, выгруженный crane из CI («does not provide the
# specified platform»), — docker save отдаёт архив в 8 КБ без слоёв.
# Использование (из каталога вывода): sh scripts/gitflic-image-archive.sh 1.6.0 tsl-auth-image-1.6.0-linux-amd64.tar.gz
# Логин GITFLIC_API_USER и транспортный токен GITFLIC_TRANSPORT_TOKEN — из GITFLIC_TOKENS_FILE (значения не выводятся).
# Другой образ — GITFLIC_IMAGE_REPO (по умолчанию project/uklad/tsl-auth/tsl-auth). Нужны curl, jq, sha256sum, tar, gzip.
# jq на Windows пишет CRLF — символы \r убираются.
set -eu
tag="$1"; file="$2"
KEYS="${GITFLIC_TOKENS_FILE:-/c/Projects/TSL/Key/gitflic-tokens.env}"
U="$(grep '^GITFLIC_API_USER=' "$KEYS" | cut -d= -f2- | tr -d '\r"')"
P="$(grep '^GITFLIC_TRANSPORT_TOKEN=' "$KEYS" | cut -d= -f2- | tr -d '\r"')"
REPO="${GITFLIC_IMAGE_REPO:-project/uklad/tsl-auth/tsl-auth}"
NAME="registry.gitflic.ru/$REPO:$tag"
BASE="https://registry.gitflic.ru/v2/$REPO"
MT="application/vnd.docker.distribution.manifest.v2+json"
TOK=$(curl -sS -u "$U:$P" "https://registry.gitflic.ru/v2/token?service=service&scope=repository:$REPO:pull" | jq -r .token | tr -d '\r')
work="oci-$tag"
rm -rf "$work"; mkdir -p "$work/blobs/sha256"
curl -sS -H "Authorization: Bearer $TOK" -H "Accept: $MT" -o "$work/m.json" "$BASE/manifests/$tag"
mdig=$(sha256sum "$work/m.json" | cut -d' ' -f1)
cp "$work/m.json" "$work/blobs/sha256/$mdig"
jq -r '.config.digest, .layers[].digest' "$work/m.json" | tr -d '\r' > "$work/digests"
while read -r d; do
  h=${d#sha256:}
  curl -sSL --retry 5 -H "Authorization: Bearer $TOK" -o "$work/blobs/sha256/$h" "$BASE/blobs/$d"
  [ "$(sha256sum "$work/blobs/sha256/$h" | cut -d' ' -f1)" = "$h" ] || { echo "контрольная сумма не совпала: $d"; exit 1; }
  echo "  $d $(wc -c < "$work/blobs/sha256/$h")"
done < "$work/digests"
size=$(wc -c < "$work/m.json" | tr -d ' ')
printf '{"imageLayoutVersion":"1.0.0"}' > "$work/oci-layout"
jq -n --arg d "sha256:$mdig" --argjson s "$size" --arg n "$NAME" --arg t "$tag" --arg mt "$MT" \
  '{schemaVersion:2, mediaType:"application/vnd.oci.image.index.v1+json", manifests:[{mediaType:$mt, digest:$d, size:$s,
    annotations:{"io.containerd.image.name":$n, "org.opencontainers.image.ref.name":$t}, platform:{architecture:"amd64", os:"linux"}}]}' \
  | tr -d '\r' > "$work/index.json"
jq -c --arg n "$NAME" '[{Config:("blobs/sha256/" + (.config.digest|ltrimstr("sha256:"))), RepoTags:[$n],
    Layers:[.layers[].digest | "blobs/sha256/" + ltrimstr("sha256:")]}]' "$work/m.json" | tr -d '\r' > "$work/manifest.json"
rm "$work/m.json" "$work/digests"
( cd "$work" && tar cf - oci-layout index.json manifest.json blobs | gzip -6 > "../$file" )
rm -rf "$work"
ls -la "$file"
