#!/bin/sh
# Зеркало GitFlic → GitHub (задание mirror-github конвейера GitFlic): основной репозиторий — GitFlic, GitHub получает
# копию ветки main и тегов. Нужна переменная проекта GITHUB_MIRROR_TOKEN — токен GitHub с правом записи в репозиторий
# (fine-grained: Contents read/write). Клон задания неглубокий, поэтому история сначала дотягивается целиком;
# объекты Git LFS текущего коммита переносятся отдельно (git lfs push).
set -eu
: "${GITHUB_MIRROR_TOKEN:?}"
REPO="${GITHUB_MIRROR_REPO:-akprof2000/tsl-auth}"
command -v git >/dev/null 2>&1 || apk add --no-cache git >/dev/null
command -v git-lfs >/dev/null 2>&1 || apk add --no-cache git-lfs >/dev/null
git fetch --quiet --unshallow origin 2>/dev/null || git fetch --quiet origin
git fetch --quiet --tags origin
sha="$(git rev-parse HEAD)"
url="https://x-access-token:${GITHUB_MIRROR_TOKEN}@github.com/${REPO}.git"
# Файлы Git LFS (*.docx, см. .gitattributes): объекты с GitFlic — на GitHub до push веток, иначе там останутся
# указатели без содержимого.
git lfs install --local >/dev/null
git lfs fetch origin "$sha" >/dev/null
git lfs push "$url" "$sha" 2>&1 | sed "s/${GITHUB_MIRROR_TOKEN}/***/g" || { echo "push LFS на GitHub не удался"; exit 1; }
# Ветка — только main (и только вперёд или с той же историей); теги — все v* и sdk/go/*.
if [ "${CI_COMMIT_REF_NAME:-main}" = "main" ] || [ -n "${CI_COMMIT_TAG:-}" ]; then
  git push --quiet "$url" "$sha:refs/heads/main" 2>&1 | sed "s/${GITHUB_MIRROR_TOKEN}/***/g" || { echo "push main не удался (GitHub ушёл вперёд?)"; exit 1; }
fi
git push --quiet "$url" --tags 2>&1 | sed "s/${GITHUB_MIRROR_TOKEN}/***/g" || true
echo "GitHub ${REPO}: main = $(echo "$sha" | cut -c1-7), теги отправлены"
