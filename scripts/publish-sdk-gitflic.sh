#!/bin/sh
# Публикация собранных пакетов SDK в реестр пакетов проекта GitFlic (NuGet, npm, PyPI, Maven).
# Использование: scripts/publish-sdk-gitflic.sh <версия> <каталог dist/sdk>
# С рабочей станции: PKG_BASE=https://registry.gitflic.ru/project/uklad/tsl-auth/package/-  GITFLIC_PKG_USER=<логин>  GITFLIC_PKG_TOKEN=<транспортный токен>
# Переменные: GITFLIC_PKG_USER, GITFLIC_PKG_TOKEN (транспортный токен), PKG_BASE
# (https://registry.gitflic.ru/project/<владелец>/<проект>/package/-). Нужны dotnet, npm, python (twine), mvn.
set -eu
VERSION="${1:?версия}"; DIST="${2:-dist/sdk}"
: "${GITFLIC_PKG_USER:?}" "${GITFLIC_PKG_TOKEN:?}" "${PKG_BASE:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
HOST="${PKG_BASE#https://}"

echo "== NuGet → GitFlic"
# Индекс реестра требует basic-аутентификации: источник с логином и токеном в отдельном nuget.config, push по имени.
NUGET_CFG="$(mktemp -d)/nuget.config"
cat > "$NUGET_CFG" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources><clear /><add key="gitflic" value="$PKG_BASE/nuget/index.json" /></packageSources>
  <packageSourceCredentials><gitflic><add key="Username" value="$GITFLIC_PKG_USER" /><add key="ClearTextPassword" value="$GITFLIC_PKG_TOKEN" /></gitflic></packageSourceCredentials>
</configuration>
EOF
dotnet nuget push "$DIST"/nuget/*.nupkg --source gitflic --api-key "$GITFLIC_PKG_TOKEN" --skip-duplicate --configfile "$NUGET_CFG"
rm -rf "$(dirname "$NUGET_CFG")"

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
MVN=mvn; command -v mvn >/dev/null 2>&1 || MVN=./mvnw
( cd sdk/java && $MVN -B -q -s "$settings" -Drevision="$VERSION" -DskipTests deploy -DaltDeploymentRepository="gitflic::$PKG_BASE/maven" )
rm -f "$settings"
echo "Пакеты $VERSION опубликованы в реестр GitFlic."
