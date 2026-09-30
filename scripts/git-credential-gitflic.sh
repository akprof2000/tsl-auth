#!/bin/sh
# Помощник учётных данных git для gitflic.ru: отдаёт логин и API-токен из локального файла вне репозитория,
# чтобы push/fetch в основной репозиторий (GitFlic) работали без ввода пароля и без токена в .git/config.
# Подключение (один раз в рабочей копии):
#   git config credential.https://gitflic.ru.helper '!sh scripts/git-credential-gitflic.sh'
# Токен: строка GITFLIC_API_TOKEN=… в файле GITFLIC_TOKENS_FILE (по умолчанию C:/Projects/TSL/Key/gitflic-tokens.env),
# логин — GITFLIC_GIT_USER там же или akprof2000. Отвечает только на запрос «get».
[ "${1:-}" = "get" ] || exit 0
FILE="${GITFLIC_TOKENS_FILE:-C:/Projects/TSL/Key/gitflic-tokens.env}"
[ -f "$FILE" ] || exit 0
val() { grep -E "^[[:space:]]*$1[[:space:]]*=" "$FILE" | head -1 | cut -d= -f2- | tr -d '\r" '; }
token="$(val GITFLIC_API_TOKEN)"; user="$(val GITFLIC_GIT_USER)"
[ -n "$token" ] || exit 0
printf 'username=%s\npassword=%s\n' "${user:-akprof2000}" "$token"
