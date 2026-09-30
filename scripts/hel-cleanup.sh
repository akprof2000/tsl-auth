#!/bin/sh
# Очистка места на сервере агентов CI (Хельсинки, 77.42.83.24) после заданий GitFlic.
# Задания с docker:dind оставляют анонимные тома с данными демона (до 100 ГБ в сутки) — диск кончается, и задания
# падают с «No space left on device». Скрипт удаляет ТОЛЬКО то, что оставили задания:
#   - висячие анонимные тома (имя — 64 шестнадцатеричных знака), пустые или с данными dind (overlay2/containers/image);
#     именованные тома (в том числе остановленных чужих сервисов: uklad-gitflic-runner, plaudio, youtrack, platform_dev)
#     не трогаются;
#   - образы без тега (dangling), не используемые ни одним контейнером, старше суток.
# Установка на сервере (cron пользователя, каждые 3 часа; журнал — ~/gitflic-runner/hel-cleanup.log):
#   scp -P 443 scripts/hel-cleanup.sh alexey_kozlov@77.42.83.24:~/gitflic-runner/
#   ssh -p 443 alexey_kozlov@77.42.83.24 '(crontab -l 2>/dev/null | grep -v hel-cleanup; echo "17 */3 * * * sh $HOME/gitflic-runner/hel-cleanup.sh >> $HOME/gitflic-runner/hel-cleanup.log 2>&1") | crontab -'
# Разовый запуск: ssh -p 443 alexey_kozlov@77.42.83.24 'sh ~/gitflic-runner/hel-cleanup.sh'
set -eu
echo "== $(date -u '+%Y-%m-%dT%H:%M:%SZ') до: $(df -h / | awk 'NR==2 {print $3 " занято, " $4 " свободно"}')"
removed=0
for v in $(docker volume ls -qf dangling=true); do
  case "$v" in
    *[!0-9a-f]*) continue ;;  # не анонимный — чей-то именованный том
  esac
  [ "${#v}" -eq 64 ] || continue
  # Содержимое смотрим одноразовым контейнером (без sudo): пустой том или данные dind — остаток задания CI.
  kind=$(docker run --rm -v "$v":/v:ro alpine:3.22 sh -c \
    'if [ -d /v/overlay2 ] || [ -d /v/containers ] || [ -d /v/image ]; then echo dind; elif [ -z "$(ls -A /v)" ]; then echo empty; else echo other; fi' \
    2>/dev/null || echo error)
  case "$kind" in
    dind|empty) docker volume rm "$v" >/dev/null 2>&1 && removed=$((removed + 1)) ;;
  esac
done
echo "   удалено томов: $removed"
docker image prune -f --filter "until=24h" 2>/dev/null | tail -1
echo "   после: $(df -h / | awk 'NR==2 {print $3 " занято, " $4 " свободно"}')"
