#!/bin/sh
# Публикация собранных пакетов SDK в реестр пакетов проекта GitFlic (NuGet, npm, PyPI, Maven).
# Использование: scripts/publish-sdk-gitflic.sh <версия> <каталог dist/sdk>
# Переменные: GITFLIC_PKG_USER, GITFLIC_PKG_TOKEN (транспортный токен), PKG_BASE
# (https://registry.gitflic.ru/project/<владелец>/<проект>/package/-). Нужны dotnet, npm, python (twine), mvn.
set -eu
VERSION="${1:?версия}"; DIST="${2:-dist/sdk}"
: "${GITFLIC_PKG_USER:?}" "${GITFLIC_PKG_TOKEN:?}" "${PKG_BASE:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
HOST="${PKG_BASE#https://}"

echo "== NuGet → GitFlic"
dotnet nuget push "$DIST"/nuget/*.nupkg --source "$PKG_BASE/nuget/index.json" --api-key "$GITFLIC_PKG_TOKEN" --skip-duplicate \
  || { dotnet nuget add source "$PKG_BASE/nuget/index.json" -n gitflic -u "$GITFLIC_PKG_USER" -p "$GITFLIC_PKG_TOKEN" --store-password-in-clear-text >/dev/null 2>&1 || true
       dotnet nuget push "$DIST"/nuget/*.nupkg --source gitflic --api-key "$GITFLIC_PKG_TOKEN" --skip-duplicate; }

echo "== npm → GitFlic"
tmp_npmrc="$(mktemp)"; printf '//%s/npm/:_authToken=%s\n' "$HOST" "$GITFLIC_PKG_TOKEN" > "$tmp_npmrc"
npm publish "$DIST"/npm/*.tgz --registry "$PKG_BASE/npm/" --userconfig "$tmp_npmrc" || echo "npm: версия уже есть или реестр отказал (см. выше)"
rm -f "$tmp_npmrc"

echo "== PyPI → GitFlic"
python -m pip install --quiet twine
TWINE_USERNAME="$GITFLIC_PKG_USER" TWINE_PASSWORD="$GITFLIC_PKG_TOKEN" python -m twine upload --repository-url "$PKG_BASE/pypi" --skip-existing "$DIST"/pypi/*

echo "== Maven → GitFlic"
settings="$(mktemp)"
cat > "$settings" <<EOF
<settings><servers><server><id>gitflic</id><username>$GITFLIC_PKG_USER</username><password>$GITFLIC_PKG_TOKEN</password></server></servers></settings>
EOF
( cd sdk/java && mvn -B -q -s "$settings" -Drevision="$VERSION" -DskipTests deploy -DaltDeploymentRepository="gitflic::$PKG_BASE/maven" )
rm -f "$settings"
echo "Пакеты $VERSION опубликованы в реестр GitFlic."
