#!/bin/sh
# Подготовка OpenBao для стенда ТСЛ (одноразовый контейнер openbao-init, запускается при каждом `docker compose up`,
# повторный запуск безопасен):
#   1. инициализация хранилища (один раз) и распечатывание;
#   2. KV v2 на secret/, вход по AppRole;
#   3. для каждого сервиса из OPENBAO_APPS — политика «только чтение своего пути», роль AppRole,
#      файлы role_id и свежий secret_id в /openbao/approle/<сервис>/ (том монтируется в сервис только на чтение);
#   4. генерация недостающих секретов TSL Auth (мастер-ключ, пароль администратора, секрет клиента Admin API,
#      при TSL_AUTH_POSTGRES=1 — пароль PostgreSQL и строка подключения).
#
# ВНИМАНИЕ: ключ распечатывания и root-токен сохраняются в томе openbao-init (/openbao/init) — это режим стенда.
# В продуктиве ключи раздаются держателям (key-shares/threshold), а распечатывание выполняется вручную или auto-unseal.
set -eu

export BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
INIT_DIR=/openbao/init
APPROLE_DIR=/openbao/approle
APPS="${OPENBAO_APPS:-tsl-auth}"
umask 077

# ---------- 1. Ожидание, инициализация, распечатывание ----------
i=0
until bao status >/dev/null 2>&1 || [ $? -eq 2 ]; do   # код 2 — запечатано, но отвечает
  i=$((i + 1)); [ $i -gt 60 ] && { echo "OpenBao не отвечает" >&2; exit 1; }
  sleep 1
done

if [ ! -s "$INIT_DIR/init.txt" ]; then
  if bao status 2>/dev/null | grep -q 'Initialized *true'; then
    echo "OpenBao уже инициализирован, но $INIT_DIR/init.txt нет — распечатайте хранилище вручную" >&2; exit 1
  fi
  echo "Инициализация OpenBao..."
  bao operator init -key-shares=1 -key-threshold=1 > "$INIT_DIR/init.txt"
fi
UNSEAL_KEY=$(sed -n 's/^Unseal Key 1: //p' "$INIT_DIR/init.txt")
ROOT_TOKEN=$(sed -n 's/^Initial Root Token: //p' "$INIT_DIR/init.txt")
if bao status 2>/dev/null | grep -q 'Sealed *true'; then
  bao operator unseal "$UNSEAL_KEY" >/dev/null
  echo "OpenBao распечатан."
fi
export BAO_TOKEN="$ROOT_TOKEN"

# ---------- 2. KV v2 и AppRole ----------
bao secrets list | grep -q '^secret/' || bao secrets enable -path=secret -version=2 kv
bao auth list | grep -q '^approle/' || bao auth enable approle

# ---------- 3. Политика, роль и учётные данные для каждого сервиса ----------
for app in $APPS; do
  bao policy write "$app" - >/dev/null <<EOF
path "secret/data/$app" { capabilities = ["read"] }
path "secret/data/shared" { capabilities = ["read"] }
EOF
  # Токен сервиса короткоживущий: нужен только чтобы прочитать секреты при старте.
  bao write "auth/approle/role/$app" token_policies="$app" token_ttl=10m token_max_ttl=30m secret_id_ttl=0 >/dev/null
  mkdir -p "$APPROLE_DIR/$app"
  # Файлы только для чтения, а у root здесь нет CAP_DAC_OVERRIDE: удаляем и создаём заново.
  rm -f "$APPROLE_DIR/$app/role_id" "$APPROLE_DIR/$app/secret_id"
  bao read -field=role_id "auth/approle/role/$app/role-id" > "$APPROLE_DIR/$app/role_id"
  bao write -f -field=secret_id "auth/approle/role/$app/secret-id" > "$APPROLE_DIR/$app/secret_id"
  # Сервисы работают под непривилегированными UID (tsl-auth — 1654): файлы только для чтения всем внутри тома,
  # сам том монтируется лишь в контейнер своего сервиса.
  chmod 0755 "$APPROLE_DIR" "$APPROLE_DIR/$app"
  chmod 0444 "$APPROLE_DIR/$app/role_id" "$APPROLE_DIR/$app/secret_id"
done
echo "AppRole выданы: $APPS"

# ---------- 4. Секреты TSL Auth (создаются только если их ещё нет) ----------
rand() { head -c "$1" /dev/urandom | base64 | tr -d '\n=+/' | head -c "$2"; }
put_if_missing() {  # путь ключ значение
  if ! bao kv get -field="$2" "secret/$1" >/dev/null 2>&1; then
    if bao kv get "secret/$1" >/dev/null 2>&1; then bao kv patch "secret/$1" "$2=$3" >/dev/null
    else bao kv put "secret/$1" "$2=$3" >/dev/null; fi
    echo "secret/$1: создан $2"
  fi
}

if echo " $APPS " | grep -q ' tsl-auth '; then
  put_if_missing tsl-auth Encryption__MasterKey "$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
  put_if_missing tsl-auth Bootstrap__AdminPassword "Adm-$(rand 32 20)-9x"
  put_if_missing tsl-auth Bootstrap__AdminApiClientSecret "$(rand 48 40)"
  if [ "${TSL_AUTH_POSTGRES:-0}" = "1" ]; then
    put_if_missing tsl-auth Postgres__Password "$(rand 48 32)"
    PGPASS=$(bao kv get -field=Postgres__Password secret/tsl-auth)
    put_if_missing tsl-auth Database__ConnectionString \
      "Host=${POSTGRES_HOST:-postgres};Database=${POSTGRES_DB:-tsl_auth};Username=${POSTGRES_USER:-tsl_auth};Password=$PGPASS"
    # PostgreSQL не умеет ходить в OpenBao — пароль ему отдаётся файлом в отдельном томе.
    mkdir -p /openbao/postgres && rm -f /openbao/postgres/password && printf '%s' "$PGPASS" > /openbao/postgres/password && chmod 0444 /openbao/postgres/password
  fi
fi
echo "OpenBao готов."
