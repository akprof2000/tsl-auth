#!/usr/bin/env bash
# Демо-стенд TSL Auth для Linux: сервис в Docker + четыре демо-приложения
# (.NET MVC :5101, Node SPA :5102, Go API :5103, Python :5104), матрицы доступа и пользователи alice / bob.
#
#   scripts/demo.sh                    — запустить: образ из реестра GitFlic (latest), стенд, демо-данные, приложения
#   scripts/demo.sh --build            — то же, но образ собрать из исходников (docker compose build)
#   scripts/demo.sh --image <образ>    — запустить с другим образом (например registry.gitflic.ru/...:1.5.1)
#   scripts/demo.sh stop               — остановить приложения и стенд (данные сохраняются)
#   scripts/demo.sh clean              — остановить и удалить данные стенда и секреты демо
#
# Нужны Docker (с compose), PowerShell 7 (pwsh — им заполняются демо-данные, samples/seed-demo.ps1),
# а для демо-приложений — .NET 10 SDK, Node.js ≥ 20, Go ≥ 1.22, Python ≥ 3.10.
# Секреты стенда генерируются в .env при первом запуске, секреты демо-клиентов — в samples/.env.demo (оба вне git).
# Журналы и pid приложений — tests/artifacts/demo.
set -euo pipefail

ACTION=start
BUILD=0
IMAGE="registry.gitflic.ru/project/uklad/tsl-auth/tsl-auth:latest"
while [ $# -gt 0 ]; do
  case "$1" in
    start|stop|clean) ACTION="$1" ;;
    --build) BUILD=1 ;;
    --image) IMAGE="$2"; shift ;;
    *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ISSUER="http://localhost:8080"
LOGS="$ROOT/tests/artifacts/demo"
mkdir -p "$LOGS"

env_value() { [ -f .env ] && grep -E "^$1=" .env | head -n1 | cut -d= -f2- | tr -d '\r' || true; }

stop_demos() {
  for pidfile in "$LOGS"/*.pid; do
    [ -f "$pidfile" ] || continue
    pid="$(cat "$pidfile")"
    # go run / dotnet run запускают дочерний процесс — гасим всю группу.
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    rm -f "$pidfile"
  done
  for port in 5101 5102 5103 5104; do
    if command -v fuser >/dev/null 2>&1; then fuser -k "$port/tcp" >/dev/null 2>&1 || true; fi
  done
}

init_env() {
  # Минимальный .env для демо: без секрета admin-cli сервис не создаст клиента Admin API, и заполнить стенд нечем.
  touch .env
  [ -n "$(env_value BOOTSTRAP_API_CLIENT_ID)" ] || echo "BOOTSTRAP_API_CLIENT_ID=admin-cli" >> .env
  [ -n "$(env_value BOOTSTRAP_API_CLIENT_SECRET)" ] || echo "BOOTSTRAP_API_CLIENT_SECRET=demo-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" >> .env
  [ -n "$(env_value BOOTSTRAP_ADMIN_PASSWORD)" ] || echo "BOOTSTRAP_ADMIN_PASSWORD=Adm-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')!9" >> .env
  chmod 600 .env
}

start_app() { # имя каталог команда...
  local name="$1" dir="$2"; shift 2
  ( cd "$ROOT/$dir" && setsid "$@" >"$LOGS/$name.out.log" 2>"$LOGS/$name.err.log" & echo $! >"$LOGS/$name.pid" )
}

case "$ACTION" in
  stop)  echo "Остановка демо-стенда"; stop_demos; docker compose down; exit 0 ;;
  clean) echo "Остановка демо-стенда и удаление данных"; stop_demos; docker compose down -v; rm -f samples/.env.demo; exit 0 ;;
esac

for tool in docker pwsh dotnet node go python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Не найден $tool — установите его (см. заголовок скрипта)." >&2; exit 1; }
done

echo "1. Образ TSL Auth"
if [ "$BUILD" = 1 ]; then
  docker compose build
else
  docker pull "$IMAGE" || { echo "Не удалось скачать $IMAGE (нужен docker login registry.gitflic.ru или --build)." >&2; exit 1; }
  docker tag "$IMAGE" tsl-auth:latest
fi

echo "2. Стенд"
init_env
docker compose up -d --no-build
for _ in $(seq 1 90); do
  curl -fs -o /dev/null http://127.0.0.1:8080/health/ready && break
  sleep 2
done
curl -fs -o /dev/null http://127.0.0.1:8080/health/ready || { echo "TSL Auth не поднялся за 3 минуты: docker logs tsl-auth" >&2; exit 1; }

echo "3. Демо-данные (приложения, матрицы, пользователи)"
pwsh -NoProfile -File samples/seed-demo.ps1 -Issuer "$ISSUER" \
  -AdminClientId "$(env_value BOOTSTRAP_API_CLIENT_ID)" -AdminClientSecret "$(env_value BOOTSTRAP_API_CLIENT_SECRET)"

echo "4. Демо-приложения"
stop_demos
demo_secret() { grep -E "^$1=" samples/.env.demo | cut -d= -f2- | tr -d '\r'; }
AUTH_ISSUER="$ISSUER/" CLIENT_SECRET="$(demo_secret GO_CLIENT_SECRET)" start_app go-api samples/go-api go run .
AUTH_ISSUER="$ISSUER/" start_app node-spa samples/node-spa node server.mjs
AUTH_ISSUER="$ISSUER/" CLIENT_SECRET="$(demo_secret PYTHON_CLIENT_SECRET)" start_app python-app samples/python-app python3 app.py
Auth__Issuer="$ISSUER/" Auth__ClientSecret="$(demo_secret DOTNET_CLIENT_SECRET)" GoApiUrl="http://localhost:5103" \
  ASPNETCORE_URLS="http://localhost:5101" start_app dotnet-mvc samples/dotnet-mvc dotnet run -c Release

for port in 5101 5102 5103 5104; do
  ok=0
  for _ in $(seq 1 120); do
    if curl -fs -o /dev/null "http://127.0.0.1:$port/health"; then ok=1; break; fi
    sleep 2
  done
  if [ "$ok" = 0 ]; then
    echo "Демо-приложение на порту $port не поднялось, журналы — $LOGS:" >&2
    tail -n 20 "$LOGS"/*.log >&2
    exit 1
  fi
  echo "  demo $port up"
done

cat <<EOF

Готово.
  TSL Auth          $ISSUER   (admin / пароль BOOTSTRAP_ADMIN_PASSWORD из .env)
  .NET MVC          http://localhost:5101
  Node SPA          http://localhost:5102
  Go API            http://localhost:5103
  Python            http://localhost:5104
  Пользователи      alice, bob (пароль Demo-Passw0rd!)
  Остановить        scripts/demo.sh stop
EOF
