#!/bin/sh
# Очистка проекта GitFlic после сборки (место на GitFlic ограничено). Работает через REST API (api.gitflic.ru).
# Версии в реестре пакетов (образ, NuGet, npm, PyPI, Maven) делятся на три вида:
#   - плавающие теги образа latest, X, X.Y — не удаляются никогда;
#   - выпуски X.Y.Z (PATCH короче 9 цифр) — остаются KEEP_RELEASES новейших (по умолчанию 1: только текущий выпуск);
#   - временные версии сборок main — X.Y.<unix-время коммита> и теги sha-<коммит> — остаются KEEP новейших.
# Удаление версии образа снимает только этот тег: манифест и другие теги на него остаются (проверено 04.10.2026).
# Раньше выпуски и временные версии считались вместе, и прогоны main вытесняли теги выпуска (так пропали 1.5.1 и 1.5).
# Переменные: GITFLIC_API_TOKEN (API-токен профиля: Настройки → «API токены»), CI_PROJECT_PATH (uklad/tsl-auth),
# KEEP (по умолчанию 3), KEEP_RELEASES (по умолчанию 1), DRY_RUN=1 — только показать, что было бы удалено.
# Нужны curl и jq.
set -eu
API="${GITFLIC_API:-https://api.gitflic.ru}"
# GitFlic не даёт CI_PROJECT_PATH — владелец/проект берутся из CI_REGISTRY_IMAGE (registry.gitflic.ru/project/<владелец>/<проект>).
PROJECT="${CI_PROJECT_PATH:-${CI_REGISTRY_IMAGE#*/project/}}"
[ -n "$PROJECT" ] && [ "$PROJECT" != "$CI_REGISTRY_IMAGE" ] || { echo "не удалось определить владельца/проект (CI_PROJECT_PATH или CI_REGISTRY_IMAGE)"; exit 1; }
echo "проект: $PROJECT"
KEEP="${KEEP:-3}"
KEEP_RELEASES="${KEEP_RELEASES:-1}"
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
# У версии пакета GitFlic даты нет — берём дату первого файла версии (packageFiles[0].createdAt); у релиза — createdAt.
stamp() { jq -r '(.createdAt // .created // .publishedAt // (.packageFiles[0].createdAt // "")) | tostring'; }

echo "== Реестр пакетов $PROJECT: выпусков $KEEP_RELEASES, временных версий $KEEP, плавающие теги не трогаем"
get "/registry/project/$PROJECT/package?size=100" | items | while read -r pkg; do
  id=$(printf '%s' "$pkg" | uuid); name=$(printf '%s' "$pkg" | jq -r '.name // .packageName // .alias // "?"'); type=$(printf '%s' "$pkg" | jq -r '.type // .packageType // "?"')
  [ -n "$id" ] || { echo "  пакет без идентификатора: $pkg"; continue; }
  echo "  пакет $name ($type, $id)"
  get "/registry/project/$PROJECT/package/$id/version-list?size=200" | items > "/tmp/raw.$id"
  # В сухом прогоне показываем первый объект версии: имена полей GitFlic в документации не приведены.
  if [ "$DRY" = "1" ]; then
    echo "    поля версии: $(head -1 "/tmp/raw.$id" | jq -c 'keys')"
    echo "    поля файла версии: $(head -1 "/tmp/raw.$id" | jq -c '.packageFiles[0] | del(.name) | keys')"
    echo "    версии: $(jq -r '.version + " (" + (.packageFiles[0].createdAt // "?") + ")"' "/tmp/raw.$id" | tr '
' ';')"
  fi
  while read -r v; do
    ver=$(printf '%s' "$v" | jq -r '.version // .name // .packageVersion // empty'); st=$(printf '%s' "$v" | stamp)
    [ -n "$ver" ] && printf '%s|%s\n' "$st" "$ver"
  done < "/tmp/raw.$id" | sort -r > "/tmp/versions.$id"
  total=$(wc -l < "/tmp/versions.$id"); echo "    версий: $total"
  # Вид версии: float — latest, X, X.Y; release — X.Y.Z; temp — X.Y.<unix-время> и sha-<коммит>; иное не трогаем.
  # Внутри вида — по дате, новейшие остаются. «|| true» — иначе ложный код возврата цикла останавливает скрипт (set -e).
  grep -E '\|[0-9]+\.[0-9]+\.[0-9]{1,8}$' "/tmp/versions.$id" | tail -n +$((KEEP_RELEASES + 1)) > "/tmp/drop.$id" || true
  grep -E '\|([0-9]+\.[0-9]+\.[0-9]{9,}|sha-[0-9a-f]+)$' "/tmp/versions.$id" | tail -n +$((KEEP + 1)) >> "/tmp/drop.$id" || true
  echo "    удаляем: $(wc -l < "/tmp/drop.$id")"
  while IFS='|' read -r st ver; do
    if [ -n "$ver" ]; then del POST "/registry/project/$PROJECT/package/$id/$ver/delete"; fi
  done < "/tmp/drop.$id" || true
done

echo "== Релизы $PROJECT: оставляем $KEEP"
get "/project/$PROJECT/release?size=100" | items | while read -r r; do
  id=$(printf '%s' "$r" | uuid); st=$(printf '%s' "$r" | stamp); tag=$(printf '%s' "$r" | jq -r '.tagName // .tag // .name // "?"')
  [ -n "$id" ] && printf '%s|%s|%s\n' "$st" "$id" "$tag"
done | sort -r > /tmp/releases
echo "  релизов: $(wc -l < /tmp/releases)"
tail -n +$((KEEP + 1)) /tmp/releases | while IFS='|' read -r st id tag; do
  echo "  релиз $tag"; del DELETE "/project/$PROJECT/release/$id"
done || true
# Конвейеры: остаются KEEP_PIPELINES новейших (по умолчанию 3), старые удаляются вместе с артефактами — именно артефакты
# (image.tar, отчёты, журналы стенда) занимают основное место проекта. Выполняющиеся конвейеры не трогаем.
KEEP_PIPELINES="${KEEP_PIPELINES:-3}"
echo "== Конвейеры $PROJECT: оставляем $KEEP_PIPELINES новейших"
get "/project/$PROJECT/cicd/pipeline?size=200" | items | while read -r p; do
  n=$(printf '%s' "$p" | jq -r '.localId // .id // empty'); st=$(printf '%s' "$p" | jq -r '.status // "?"')
  [ -n "$n" ] && printf '%s|%s\n' "$n" "$st"
done | sort -t'|' -k1,1nr > /tmp/pipelines
echo "  конвейеров: $(wc -l < /tmp/pipelines)"
tail -n +$((KEEP_PIPELINES + 1)) /tmp/pipelines | while IFS='|' read -r n st; do
  case "$st" in *RUN*|*PEND*|*CREATED*|*WAIT*) echo "  #$n $st — пропущен"; continue;; esac
  del DELETE "/project/$PROJECT/cicd/pipeline/$n/delete" || echo "  #$n: удалить не удалось"
done || true
echo "Готово."
