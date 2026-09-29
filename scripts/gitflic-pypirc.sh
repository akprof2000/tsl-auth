#!/bin/sh
# Пишет ~/.pypirc для публикации в реестр PyPI проекта GitFlic (как в документации GitFlic): twine с --repository-url
# в этот реестр отказывает (UnsupportedConfiguration), а через именованный репозиторий работает.
# Переменные: PKG_BASE (https://registry.gitflic.ru/project/<владелец>/<проект>/package/-), GITFLIC_PKG_USER, GITFLIC_PKG_TOKEN.
set -eu
: "${PKG_BASE:?}" "${GITFLIC_PKG_USER:?}" "${GITFLIC_PKG_TOKEN:?}"
cat > "$HOME/.pypirc" <<PYPIRC
[distutils]
index-servers =
    gitflic

[gitflic]
repository = $PKG_BASE/pypi
username = $GITFLIC_PKG_USER
password = $GITFLIC_PKG_TOKEN
PYPIRC
chmod 600 "$HOME/.pypirc"
echo "~/.pypirc: репозиторий gitflic → $PKG_BASE/pypi"
