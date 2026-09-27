#!/bin/sh
# Команда bao от имени администратора стенда (root-токен из тома openbao-init). Пример:
#   docker compose exec openbao sh /openbao/scripts/bao.sh kv get secret/tsl-auth
# В продуктиве вместо root-токена используйте персональные учётные записи операторов.
set -eu
export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
BAO_TOKEN=$(sed -n 's/^Initial Root Token: //p' /openbao/init/init.txt)
export BAO_TOKEN
exec bao "$@"
