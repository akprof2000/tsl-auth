#!/bin/sh
# Сборка пакетов всех пяти SDK с одной версией: NuGet (.nupkg), npm (.tgz), PyPI (wheel + sdist), Maven (jar + pom),
# Go (архив исходников модуля — для закрытого контура, где go get недоступен).
# Использование: scripts/build-sdk-packages.sh <версия X.Y.Z> [каталог вывода, по умолчанию dist/sdk]
# Нужны: dotnet, node/npm, python (модуль build), mvn или sdk/java/mvnw, git.
set -eu
VERSION="${1:?версия, например 1.4.0}"
OUT="${2:-dist/sdk}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT/nuget" "$OUT/npm" "$OUT/pypi" "$OUT/maven" "$OUT/go"

echo "== NuGet TslAuth.Client $VERSION"
dotnet pack sdk/dotnet/TslAuth.Client/TslAuth.Client.csproj -c Release -p:Version="$VERSION" -o "$OUT/nuget" --nologo -v quiet

echo "== npm @tsl/auth-client $VERSION"
( cd sdk/node && npm version "$VERSION" --no-git-tag-version --allow-same-version >/dev/null && npm pack --pack-destination "$ROOT/$OUT/npm" --silent )
# Версия в package.json возвращается к 0.0.0-dev: в репозитории версия только у тега.
( cd sdk/node && npm version 0.0.0-dev --no-git-tag-version --allow-same-version >/dev/null )

echo "== PyPI tsl-auth-client $VERSION"
( cd sdk/python && sed -i.bak -E "s/^version = \"[^\"]+\"/version = \"$VERSION\"/" pyproject.toml \
  && python -m build --outdir "$ROOT/$OUT/pypi" >/dev/null && mv pyproject.toml.bak pyproject.toml && rm -rf build ./*.egg-info src/*.egg-info )

echo "== Maven ru.tsl.auth:tsl-auth-client $VERSION"
MVN=mvn; command -v mvn >/dev/null 2>&1 || MVN=./mvnw
( cd sdk/java && $MVN -B -q -Drevision="$VERSION" -DskipTests package && cp target/tsl-auth-client-"$VERSION".jar target/tsl-auth-client-"$VERSION"-sources.jar "$ROOT/$OUT/maven/" 2>/dev/null \
  && cp .flattened-pom.xml "$ROOT/$OUT/maven/tsl-auth-client-$VERSION.pom" 2>/dev/null || cp pom.xml "$ROOT/$OUT/maven/tsl-auth-client-$VERSION.pom" )

echo "== Go github.com/akprof2000/tsl-auth/sdk/go v$VERSION (архив исходников)"
git archive --format=zip --prefix="tsl-auth-sdk-go-$VERSION/" -o "$OUT/go/tsl-auth-sdk-go-$VERSION.zip" HEAD:sdk/go

( cd "$OUT" && find . -type f | sort | xargs sha256sum > SHA256SUMS )
echo "Пакеты собраны в $OUT:"; ( cd "$OUT" && find . -type f | sort )
