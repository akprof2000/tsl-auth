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
подделает `X-Forwarded-For` (обход лимитов по IP) и `X-Forwarded-Proto`. Секреты можно передавать файлами (docker secrets):
`Encryption__MasterKeyFile`, `Database__ConnectionStringFile`, `Bootstrap__AdminPasswordFile`.

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
