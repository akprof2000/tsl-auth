# TSL Auth

Сервис аутентификации и авторизации (аналог Keycloak) на .NET 10: OAuth 2.0 / OpenID Connect, JWT,
ролевая модель с матрицей доступа для каждого приложения, кластер без потери сессий, веб-админка и REST API.
Работает полностью в закрытом контуре (без интернета).

**Исходный код, документация и схемы:** https://github.com/akprof2000/tsl-auth

## Возможности

- **Протоколы:** authorization code + PKCE, client credentials, refresh с ротацией, token exchange (RFC 8693), introspection, revocation, discovery, JWKS.
- **Токены:** JWT RS256, права из матрицы в claims `role`, `permissions`, `resource_access` (совместимо с Keycloak); сроки жизни настраиваются.
- **RBAC:** у каждого приложения свои разрешения, роли и матрица «роль × разрешение».
- **Пользователи:** приглашения, временные пароли, сброс по email и через бота, самостоятельная регистрация с одобрением, персональные токены (PAT).
- **Безопасность:** пароли PBKDF2-SHA512, персональные данные в БД — AES-256-GCM, политика паролей, журнал безопасности, строгий CSP, rate limiting.
- **БД:** встроенная SQLite (один узел) или PostgreSQL (кластер); схема создаётся и обновляется автоматически.
- **Интеграция:** Admin API, App API, Bot API, события (long-polling, SSE, вебхуки), интерактивный справочник API `/docs/api`.

## Быстрый старт (один узел, SQLite)

```bash
docker run -d --name tsl-auth -p 8080:8080 \
  -v tsl-auth-data:/app/data \
  -e Auth__Issuer=http://localhost:8080/ \
  -e Auth__RequireHttps=false \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  akprof2000/tsl-auth:latest

docker logs tsl-auth | grep "временным паролем"
```

Откройте http://localhost:8080 и войдите как `admin` с паролем из лога. Руководство по интеграции — `/docs`,
справочник API — `/docs/api`.

Мастер-ключ шифрования генерируется в томе (`/app/data/master.key`) — **сохраните его резервную копию**.

## Секреты в OpenBao — зависимый контейнер (рекомендуется)

В проектах ТСЛ секреты хранятся в **OpenBao** (`openbao/openbao:2.4.1`, открытый форк HashiCorp Vault).
TSL Auth при старте входит в OpenBao по AppRole и читает секреты из KV v2 (`secret/tsl-auth`).
Хранилище содержит мастер-ключ, пароль первого администратора, секрет клиента Admin API и строку подключения к БД.
В переменных окружения и `.env` значений секретов нет.

| Контейнер | Образ | Роль |
|---|---|---|
| `openbao` | `openbao/openbao:2.4.1` | хранилище секретов (зависимый сервис, запускается первым) |
| `openbao-init` | `openbao/openbao:2.4.1` | одноразовый: инициализирует и распечатывает хранилище, выдаёт AppRole, генерирует секреты |
| `tsl-auth` | `akprof2000/tsl-auth` | стартует после `openbao-init` и читает секреты |

Скрипты `openbao-init` и конфигурация лежат в репозитории в каталоге
[`deploy/openbao`](https://github.com/akprof2000/tsl-auth/tree/main/deploy/openbao).
Готовые оверлеи: `docker-compose.openbao.yml` для одного узла и `docker-compose.ha-openbao.yml` для кластера.

```bash
git clone https://github.com/akprof2000/tsl-auth && cd tsl-auth
docker compose -f docker-compose.yml -f docker-compose.openbao.yml up -d
# пароль администратора
docker compose -f docker-compose.yml -f docker-compose.openbao.yml exec openbao   sh /openbao/scripts/bao.sh kv get -field=Bootstrap__AdminPassword secret/tsl-auth
```

Подключение TSL Auth к уже работающему OpenBao контура:

```bash
-e OpenBao__Address=https://openbao.corp:8200
-e OpenBao__Path=tsl-auth                          # secret/data/tsl-auth, ключи = имена настроек
-e OpenBao__RoleIdFile=/run/secrets/role_id        # AppRole: role_id и secret_id файлами
-e OpenBao__SecretIdFile=/run/secrets/secret_id
-e OpenBao__CaFile=/run/secrets/openbao-ca.pem     # если OpenBao по HTTPS с корпоративным CA
```

Ключ секрета совпадает с именем настройки: `Encryption__MasterKey`, `Database__ConnectionString`,
`Bootstrap__AdminApiClientSecret`, `Smtp__Password` и так далее. Если OpenBao недоступен или запечатан, сервис ждёт его
до 30 попыток по 2 с. Неверный `secret_id` останавливает запуск сразу.

**Без OpenBao сервис тоже работает.** Хранилище подключается, только если задан `OpenBao__Address`. Иначе секреты
берутся из переменных окружения или файлов (`*File`, docker secrets), а в одиночном режиме мастер-ключ генерируется в томе.
При переходе на OpenBao перенесите в него прежний мастер-ключ (`/app/data/master.key`). Если ключи не совпадут,
сервис не стартует, и данные не пострадают.

## Кластер (PostgreSQL + несколько узлов)

Готовые `docker-compose.ha.yml` и конфигурация nginx — в репозитории:
[развёртывание](https://github.com/akprof2000/tsl-auth/blob/main/docs/deployment.md).

```bash
-e Database__Provider=Postgres
-e Database__ConnectionString="Host=db;Database=tsl_auth;Username=tsl_auth;Password=..."
-e Encryption__MasterKey=<base64, 32 байта, одинаковый на всех узлах>
-e Auth__Issuer=https://auth.corp/          # внешний адрес балансировщика, одинаковый на всех узлах
-e AllowedHosts=auth.corp
-e Auth__RequireHttps=true                  # TLS завершается на балансировщике
-e Auth__TrustForwardedHeaders=true         # IP клиента и схема — из X-Forwarded-For/Proto
-e Auth__KnownNetworks=10.20.0.0/24         # подсеть балансировщика (по умолчанию — частные сети)
```

Узлы с `Auth__TrustForwardedHeaders=true` не должны быть доступны напрямую, в обход балансировщика: иначе клиент
подделает `X-Forwarded-For` (обход лимитов по IP) и `X-Forwarded-Proto`. Секреты — в OpenBao (см. выше) или файлами
(docker secrets): `Encryption__MasterKeyFile`, `Database__ConnectionStringFile`, `Bootstrap__AdminPasswordFile`.

## Основные параметры

| Переменная | Назначение |
|---|---|
| `Auth__Issuer` | **Обязателен.** Публичный адрес сервиса (`iss` в токенах, ссылки в письмах), одинаковый на всех узлах |
| `AllowedHosts` | Допустимые значения заголовка `Host`, например `auth.corp` (по умолчанию `*`) |
| `Auth__RequireHttps` | Требовать HTTPS (по умолчанию `true`; `false` — только для стенда без TLS) |
| `Database__Provider` | `Sqlite` (по умолчанию) или `Postgres` |
| `Database__ConnectionString` | Строка подключения к БД |
| `Encryption__MasterKey` / `Encryption__MasterKeyFile` | Мастер-ключ шифрования данных (обязателен для PostgreSQL) |
| `Bootstrap__AdminUserName` / `Bootstrap__AdminPassword` (`...File`) | Первый администратор (пароль пуст — будет сгенерирован) |
| `Auth__TrustForwardedHeaders` | Принимать `X-Forwarded-For/Proto` за обратным прокси (узлы не должны быть доступны напрямую) |
| `Auth__KnownNetworks` | Подсети прокси (CIDR через запятую); по умолчанию loopback и частные сети |

Полный список — в [документации по конфигурации](https://github.com/akprof2000/tsl-auth/blob/main/docs/configuration.md).

## Обслуживание

```bash
# восстановить доступ администратора
docker exec -it tsl-auth dotnet /app/TslAuth.dll admin reset-password admin

# перенести данные одиночного режима (SQLite) в PostgreSQL со сверкой
docker run --rm -v tsl-auth-data:/app/data -e TARGET_DB_CONNECTION_STRING="Host=...;Database=tsl_auth;..." \
  akprof2000/tsl-auth:latest admin migrate-to-postgres
```

## Образ

- База: `mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0-distroless` — без shell и пакетного менеджера, закреплена по digest.
- Запуск под непривилегированным пользователем `1654`, совместим с `--read-only` и `--cap-drop ALL`; встроенный `HEALTHCHECK`.
- Каждая сборка проходит тесты, полный E2E-стенд, сканирование Trivy (0 уязвимостей) и Dockle; подписан cosign именно проверенный digest, приложены SBOM и SLSA provenance.

Проверка подписи:

```bash
cosign verify akprof2000/tsl-auth:latest \
  --certificate-identity-regexp 'https://github.com/akprof2000/tsl-auth/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Теги

| Тег | Что это |
|---|---|
| `latest` | последняя сборка ветки `main` |
| `X.Y.Z`, `X.Y` | релизы |
| `sha-<коммит>` | конкретный коммит |

Также доступен в GHCR: `ghcr.io/akprof2000/tsl-auth`.

Лицензия: [MIT](https://github.com/akprof2000/tsl-auth/blob/main/LICENSE).
