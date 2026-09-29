#!/bin/sh
# Очистка проекта GitFlic после сборки: в реестре пакетов (образ, NuGet, npm, PyPI, Maven) и в релизах остаётся
# не больше KEEP новейших версий — место на GitFlic ограничено. Работает через REST API (api.gitflic.ru).
# Переменные: GITFLIC_API_TOKEN (API-токен профиля: Настройки → «API токены»), CI_PROJECT_PATH (uklad/tsl-auth),
# KEEP (по умолчанию 3), DRY_RUN=1 — только показать, что было бы удалено. Нужны curl и jq.
set -eu
API="${GITFLIC_API:-https://api.gitflic.ru}"
# GitFlic не даёт CI_PROJECT_PATH — владелец/проект берутся из CI_REGISTRY_IMAGE (registry.gitflic.ru/project/<владелец>/<проект>).
PROJECT="${CI_PROJECT_PATH:-${CI_REGISTRY_IMAGE#*/project/}}"
[ -n "$PROJECT" ] && [ "$PROJECT" != "$CI_REGISTRY_IMAGE" ] || { echo "не удалось определить владельца/проект (CI_PROJECT_PATH или CI_REGISTRY_IMAGE)"; exit 1; }
echo "проект: $PROJECT"
KEEP="${KEEP:-3}"
DRY="${DRY_RUN:-0}"
AUTH="Authorization: token ${GITFLIC_API_TOKEN:?нужен GITFLIC_API_TOKEN}"

get() { curl -sS -f -H "$AUTH" "$API$1"; }
del() {
  if [ "$DRY" = "1" ]; then echo "    [dry-run] $1 $2"; else curl -sS -f -X "$1" -H "$AUTH" "$API$2" >/dev/null && echo "    удалено: $2"; fi
}
# Списки приходят страницами Spring (поле _embedded или content) либо массивом — берём массив, где бы он ни лежал.
items() { jq -c 'if type=="array" then .[] elif ._embedded then (._embedded|to_entries[0].value[]) elif .content then .content[] else empty end'; }
# Идентификатор и дата у объектов GitFlic называются по-разному; берём первое подходящее поле.
uuid()  { jq -r '.uuid // .id // .packageUuid // .releaseUuid // empty'; }
stamp() { jq -r '(.createdAt // .created // .creationDate // .publishedAt // .updatedAt // "") | tostring'; }

echo "== Реестр пакетов $PROJECT: оставляем $KEEP версий у каждого пакета"
get "/registry/project/$PROJECT/package?size=100" | items | while read -r pkg; do
  id=$(printf '%s' "$pkg" | uuid); name=$(printf '%s' "$pkg" | jq -r '.name // .packageName // .alias // "?"'); type=$(printf '%s' "$pkg" | jq -r '.type // .packageType // "?"')
  [ -n "$id" ] || { echo "  пакет без идентификатора: $pkg"; continue; }
  echo "  пакет $name ($type, $id)"
  get "/registry/project/$PROJECT/package/$id/version-list?size=200" | items | while read -r v; do
    ver=$(printf '%s' "$v" | jq -r '.version // .name // .packageVersion // empty'); st=$(printf '%s' "$v" | stamp)
    [ -n "$ver" ] && printf '%s\t%s\n' "$st" "$ver"
  done | sort -r > "/tmp/versions.$id"
  total=$(wc -l < "/tmp/versions.$id"); echo "    версий: $total"
  # latest — плавающий тег образа, его не трогаем; остальные — по дате, новейшие KEEP остаются.
  grep -v "	latest$" "/tmp/versions.$id" | tail -n +$((KEEP + 1)) | while IFS="$(printf '\t')" read -r st ver; do
    del POST "/registry/project/$PROJECT/package/$id/$ver/delete"
  done
done

echo "== Релизы $PROJECT: оставляем $KEEP"
get "/project/$PROJECT/release?size=100" | items | while read -r r; do
  id=$(printf '%s' "$r" | uuid); st=$(printf '%s' "$r" | stamp); tag=$(printf '%s' "$r" | jq -r '.tagName // .tag // .name // "?"')
  [ -n "$id" ] && printf '%s\t%s\t%s\n' "$st" "$id" "$tag"
done | sort -r > /tmp/releases
echo "  релизов: $(wc -l < /tmp/releases)"
tail -n +$((KEEP + 1)) /tmp/releases | while IFS="$(printf '\t')" read -r st id tag; do
  echo "  релиз $tag"; del DELETE "/project/$PROJECT/release/$id"
done
echo "Готово."
