# TSL Auth

Сервис аутентификации и авторизации (аналог Keycloak) на .NET 10 в Docker-контейнере.
OAuth 2.0 / OpenID Connect, JWT, ролевая модель с матрицей доступа для каждого приложения,
кластерный режим без потери сессий, веб-админка и REST API. Работает полностью в закрытом контуре (без интернета).

[![CI](https://github.com/akprof2000/tsl-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/akprof2000/tsl-auth/actions/workflows/ci.yml)

```mermaid
flowchart LR
    subgraph Клиенты
        WEB[Серверные веб-приложения<br/>.NET / Java / Python]
        SPA[SPA и мобильные<br/>PKCE]
        SVC[Сервисы и боты<br/>client_credentials / PAT]
    end
    LB[nginx<br/>TLS, балансировка]
    subgraph TSL Auth кластер
        A1[Узел 1]
        A2[Узел 2]
        A3[Узел 3]
    end
    PG[(PostgreSQL<br/>шифрование полей)]
    API[Ваши API<br/>проверка JWT по JWKS]

    WEB & SPA & SVC --> LB --> A1 & A2 & A3 --> PG
    WEB & SPA & SVC -- JWT --> API
    API -. JWKS .-> LB
```

## Возможности

| Область | Что есть |
|---|---|
| **Протоколы** | OAuth 2.0 / OIDC: authorization code + PKCE, client credentials, refresh (ротация), password (legacy), **token exchange (RFC 8693)**, introspection, revocation, userinfo, logout, discovery, JWKS |
| **Токены** | JWT RS256; права из матрицы в claims `role`, `permissions`, `resource_access` (совместимо с Keycloak); сроки жизни настраиваются глобально, для приложения и уменьшаются клиентом |
| **RBAC** | У каждого приложения — разрешения, роли и матрица «роль × разрешение»; роли пользователям и сервисным клиентам; изменения прав применяются при следующем refresh |
| **Пользователи** | Приглашения, одноразовые (временные) пароли, сброс по email и **через бота мессенджера**, самостоятельная регистрация с заявкой на роли и одобрением, персональные токены (PAT) как в GitHub |
| **Приложения** | Регистрация клиентов, **самоуправление** (приложение само ведёт своих пользователей и роли через App API), оформление страницы входа под приложение, CORS для SPA |
| **Безопасность** | Пароли — PBKDF2-SHA512; персональные данные в БД — AES-256-GCM; поиск по логину/email через HMAC; политика паролей и блокировка; журнал безопасности с хранением по типам событий; строгий CSP; rate limiting; контейнер read-only, non-root, без capabilities |
| **Кластер** | Любое число экземпляров за балансировщиком; общие ключи, сессии и настройки в БД; миграции под блокировкой; сессии переживают перезапуск и отказы |
| **БД** | Встроенная SQLite (один узел) или PostgreSQL (кластер); схема создаётся и обновляется автоматически |
| **Интеграция** | Admin API, App API, Bot API, лента событий (long-polling, SSE, вебхуки), OpenAPI + интерактивный справочник `/docs/api`, руководство `/docs` |
| **Интерфейс** | Веб-админка; страницы входа на нескольких языках (языковые пакеты), брендирование под приложение |

## Быстрый старт

```bash
docker compose up -d --build
docker logs tsl-auth | grep "временным паролем"
```

Откройте http://localhost:8080, войдите как `admin` с паролем из лога и задайте постоянный пароль.
Руководство по интеграции: http://localhost:8080/docs, справочник API: http://localhost:8080/docs/api.

Кластер (PostgreSQL + 3 узла + nginx):

```bash
cp .env.example .env    # заполните ENCRYPTION_MASTER_KEY и POSTGRES_PASSWORD
docker compose -f docker-compose.ha.yml up -d --build
```

## Документация

| Документ | Содержание |
|---|---|
| [Архитектура](docs/architecture.md) | Компоненты, модель данных, кластер, хранение ключей, схемы |
| [Развёртывание](docs/deployment.md) | Одиночный режим, кластер, внешний PostgreSQL, HTTPS, закрытый контур, обновление, резервное копирование |
| [Конфигурация](docs/configuration.md) | Все параметры окружения и настройки в БД |
| [Интеграция приложений](docs/integration.md) | Потоки OAuth со схемами, JWT, проверка токенов, token exchange, PAT, App API, события, бот |
| [Администрирование](docs/administration.md) | Работа в админке: приложения, матрица доступа, пользователи, заявки, журнал, настройки |
| [Безопасность](docs/security.md) | Модель угроз, меры защиты, результаты сканирования |
| [Тестирование](docs/testing.md) | Пирамида тестов, как запускать, результаты нагрузки и отказоустойчивости |
| [Эксплуатация](docs/operations.md) | Мониторинг, журналы, восстановление доступа, типовые проблемы |

## Структура репозитория

```
src/TslAuth/            сервис (ASP.NET Core, OpenIddict, EF Core)
tests/                  unit, интеграционные, UI (Playwright), нагрузка (k6), отказоустойчивость
samples/                демо-приложения: .NET MVC, Node.js SPA+API, Go API, Python
deploy/                 конфигурации nginx (HTTP и TLS)
scripts/                сертификаты для теста HTTPS, перенос образов в закрытый контур
docs/                   документация
```

> ⚠️ Значения в `samples/seed-demo.ps1`, `docker-compose*.yml` по умолчанию и тестах (например `demo-admin-cli-secret-2026`) —
> только для демонстрационного стенда. В продуктиве задавайте свои секреты через `.env`.
