#!/bin/sh
# Публикация .nupkg в реестр NuGet проекта GitFlic напрямую (протокол NuGet push: PUT multipart/form-data).
# `dotnet nuget push` добавляет к адресу PackagePublish завершающий «/», и GitFlic отвечает 404 — поэтому curl
# по адресу ровно из индекса реестра (…/package/-/nuget).
# Использование: scripts/gitflic-nuget-push.sh <файл.nupkg> [ещё файлы]
# Переменные: PKG_BASE (https://registry.gitflic.ru/project/<владелец>/<проект>/package/-), GITFLIC_PKG_USER, GITFLIC_PKG_TOKEN.
set -eu
: "${PKG_BASE:?}" "${GITFLIC_PKG_USER:?}" "${GITFLIC_PKG_TOKEN:?}"
command -v curl >/dev/null 2>&1 || { (apt-get update -qq && apt-get install -y -qq curl >/dev/null) || apk add --no-cache curl >/dev/null; }
for f in "$@"; do
  code=$(curl -sS -o /tmp/nuget-push.out -w '%{http_code}' -X PUT -u "$GITFLIC_PKG_USER:$GITFLIC_PKG_TOKEN" \
    -H "X-NuGet-ApiKey: $GITFLIC_PKG_TOKEN" -H "X-NuGet-Protocol-Version: 4.1.0" -F "package=@$f" "$PKG_BASE/nuget")
  case "$code" in
    200|201|202) echo "NuGet: $(basename "$f") опубликован (HTTP $code)";;
    409) echo "NuGet: $(basename "$f") уже есть в реестре (HTTP 409)";;
    *) echo "NuGet: $(basename "$f") — HTTP $code"; head -c 600 /tmp/nuget-push.out; echo; exit 1;;
  esac
done
