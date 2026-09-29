#!/bin/sh
# Проверка сети агента до реестра GitFlic: скачивает слой публичного образа (~85 МБ) и сравнивает объём.
# С сервера Hetzner TCP-сессии к registry.gitflic.ru обрываются после ~19 КБ — задание net-check-hel показывает,
# починилась ли сеть (тогда серверным агентам можно вернуть тег tsl-auth). Нужен curl.
set -u
BLOB="https://registry.gitflic.ru/v2/company/gitflic/gitflic-runner-helper/blobs/sha256:3b84935925832868d61044cb4ad9a00cc716d83a1461bdde439da834485caf46"
tok=$(curl -s "https://registry.gitflic.ru/v2/token?service=service&scope=repository:company/gitflic/gitflic-runner-helper:pull" | sed -E 's/.*"token":"([^"]+)".*/\1/')
size=$(curl -sSL -o /dev/null -w '%{size_download}' --max-time 90 -H "Authorization: Bearer $tok" "$BLOB" 2>/dev/null || echo 0)
echo "скачано байт: ${size:-0} (слой ~85 МБ)"
if [ "${size:-0}" -ge 50000000 ]; then
  echo "СЕТЬ ДО РЕЕСТРА GITFLIC РАБОТАЕТ — можно вернуть сборку на сервер (docs/gitflic-ci.md)"
else
  echo "сеть до registry.gitflic.ru по-прежнему обрывается"; exit 1
fi
