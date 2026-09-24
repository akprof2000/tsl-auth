# TSL Auth

Сервис аутентификации и авторизации (аналог Keycloak) на .NET 10 в Docker-контейнере.
OAuth 2.0 / OpenID Connect, JWT, ролевая модель с матрицей доступа для каждого приложения,
кластерный режим без потери сессий, веб-админка и REST API. Работает полностью в закрытом контуре (без интернета).

<!-- Сборка и качество -->
[![CI](https://github.com/akprof2000/tsl-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/akprof2000/tsl-auth/actions/workflows/ci.yml)
[![E2E](https://github.com/akprof2000/tsl-auth/actions/workflows/e2e.yml/badge.svg)](https://github.com/akprof2000/tsl-auth/actions/workflows/e2e.yml)
[![Тесты](https://img.shields.io/badge/тесты-unit%20·%20интеграционные%20·%20UI%20·%20нагрузка%20·%20отказы-2ea44f)](docs/testing.md)
[![Документация](https://img.shields.io/badge/docs-проверены%20в%20CI-2ea44f?logo=markdown)](docs/)
[![License: MIT](https://img.shields.io/github/license/akprof2000/tsl-auth?color=blue)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/akprof2000/tsl-auth)](https://github.com/akprof2000/tsl-auth/commits/main)

<!-- Образ и безопасность -->
[![GHCR](https://img.shields.io/badge/ghcr.io-akprof2000%2Ftsl--auth-2496ED?logo=github)](https://github.com/akprof2000/tsl-auth/pkgs/container/tsl-auth)
[![Docker Hub](https://img.shields.io/docker/v/akprof2000/tsl-auth?sort=semver&label=docker%20hub&logo=docker&logoColor=white)](https://hub.docker.com/r/akprof2000/tsl-auth)
[![Docker Pulls](https://img.shields.io/docker/pulls/akprof2000/tsl-auth?logo=docker&logoColor=white)](https://hub.docker.com/r/akprof2000/tsl-auth)
[![Image size](https://img.shields.io/docker/image-size/akprof2000/tsl-auth/latest?logo=docker&logoColor=white)](https://hub.docker.com/r/akprof2000/tsl-auth/tags)
[![Base: distroless](https://img.shields.io/badge/base-Azure%20Linux%20distroless-0078D4?logo=linux&logoColor=white)](docs/security.md#образ-контейнера)
[![Trivy](https://img.shields.io/badge/Trivy-0%20уязвимостей-1904DA?logo=aquasecurity&logoColor=white)](docs/security.md#результаты-сканирования)
[![Dockle](https://img.shields.io/badge/Dockle-CIS%20passed-2ea44f)](docs/security.md#результаты-сканирования)
[![cosign](https://img.shields.io/badge/cosign-signed-7C3AED?logo=sigstore&logoColor=white)](docs/security.md#проверка-подлинности-образа)
[![SBOM](https://img.shields.io/badge/SBOM%20%2B%20SLSA-provenance-6f42c1)](docs/security.md#проверка-подлинности-образа)
[![Non-root](https://img.shields.io/badge/runs%20as-non--root%20·%20read--only-success)](docs/security.md#образ-контейнера)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)

<!-- Технологии -->
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![OpenIddict](https://img.shields.io/badge/OpenIddict-7.7-512BD4)](https://documentation.openiddict.com/)
[![OAuth 2.0 / OIDC](https://img.shields.io/badge/OAuth%202.0-OpenID%20Connect-EB5424?logo=openid&logoColor=white)](docs/integration.md)
[![JWT](https://img.shields.io/badge/JWT-RS256-000000?logo=jsonwebtokens&logoColor=white)](docs/integration.md#4-формат-токена-и-авторизация-в-api)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-4169E1?logo=postgresql&logoColor=white)](docs/deployment.md#кластер)
[![SQLite](https://img.shields.io/badge/SQLite-встроенная-003B57?logo=sqlite&logoColor=white)](docs/deployment.md#одиночный-режим)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docs/deployment.md)
[![nginx](https://img.shields.io/badge/nginx-HA%20кластер-009639?logo=nginx&logoColor=white)](docs/deployment.md#кластер)
[![Offline](https://img.shields.io/badge/работает-без%20интернета-informational)](docs/deployment.md#закрытый-контур-без-интернета)
[![Демо](https://img.shields.io/badge/демо-.NET%20·%20Node%20·%20Go%20·%20Python-yellow)](samples/)

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

## Образы

| Реестр | Страница | Загрузка |
|---|---|---|
| Docker Hub | [hub.docker.com/r/akprof2000/tsl-auth](https://hub.docker.com/r/akprof2000/tsl-auth) | `docker pull akprof2000/tsl-auth:latest` |
| GitHub Container Registry | [ghcr.io/akprof2000/tsl-auth](https://github.com/akprof2000/tsl-auth/pkgs/container/tsl-auth) | `docker pull ghcr.io/akprof2000/tsl-auth:latest` |

Теги: `latest` (ветка `main`), `X.Y.Z` и `X.Y` (релизы), `sha-<коммит>`. Образы собираются GitHub Actions после
тестов и сканирования, подписаны cosign и содержат SBOM — [проверка подлинности](docs/security.md#проверка-подлинности-образа).
Для закрытого контура — [перенос образов без интернета](docs/deployment.md#закрытый-контур-без-интернета).

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
                        docflow-demo — документооборот: PWA (React) + C# API + бот безопасности
deploy/                 конфигурации nginx (HTTP и TLS)
scripts/                сертификаты для теста HTTPS, перенос образов в закрытый контур
docs/                   документация
```

## Лицензия

[MIT](LICENSE) © 2026 Alexey Kozlov

> ⚠️ Значения в `samples/seed-demo.ps1`, `docker-compose*.yml` по умолчанию и тестах (например `demo-admin-cli-secret-2026`) —
> только для демонстрационного стенда. В продуктиве задавайте свои секреты через `.env`.
