# Архитектура

## Компоненты

```mermaid
flowchart TB
    subgraph Контейнер TSL Auth
        direction TB
        MW[Конвейер: заголовки безопасности → CORS для SPA → язык → rate limiting → аутентификация]
        OIDC[OpenIddict Server<br/>/connect/*, /.well-known/*]
        CTRL[AuthorizationController<br/>выдача токенов, claims из матрицы]
        UI[Razor Pages<br/>вход, регистрация, личный кабинет, админка]
        ADMIN[Admin API /api/admin]
        APP[App API /api/app]
        BOT[Bot API /api/bot]
        EVT[Events API<br/>long-polling / SSE / вебхуки]
        DOCS[OpenAPI + Scalar<br/>/docs, /docs/api]
        SVC[Сервисы: Access, Application, User, Session,<br/>Pat, Bot, Audit, Webhook, Settings, Localization]
        BG[Фоновые задачи: доставка вебхуков,<br/>пакетная запись аудита, очистка по срокам]
        EF[EF Core + шифрование полей<br/>AES-256-GCM / HMAC]
    end
    DB[(SQLite или PostgreSQL)]

    MW --> OIDC --> CTRL --> SVC
    MW --> UI --> SVC
    MW --> ADMIN & APP & BOT & EVT --> SVC
    SVC --> EF --> DB
    BG --> EF
```

| Слой | Каталог | Назначение |
|---|---|---|
| Протокол OAuth/OIDC | `Controllers/AuthorizationController.cs`, OpenIddict | Проверка запросов, выпуск и отзыв токенов, discovery, JWKS |
| Бизнес-логика | `Services/` | RBAC, приложения, пользователи, сессии, PAT, заявки, бот, аудит, события, настройки |
| API | `Api/` | Admin API, App API (самоуправление), Bot API, события |
| Интерфейс | `Pages/` | Страницы пользователя (`Account/`), админка (`Admin/`), документация (`Docs/`) |
| Инфраструктура | `Infrastructure/` | Регистрация сервисов, старт (миграции, ключи, начальные данные), безопасность, CORS, аудит-фильтры, фоновые задачи |
| Безопасность данных | `Security/` | Шифрование полей, мастер-ключ, ключи подписи, политика паролей |
| Данные | `Data/` | Модель EF Core, миграции для SQLite и PostgreSQL |
| Локализация | `Localization/` | Встроенные языковые пакеты, пакеты из БД, выбор языка |

## Модель данных

```mermaid
erDiagram
    AspNetUsers ||--o{ AccessRoleAssignments : "роли (SubjectType=User)"
    AspNetUsers ||--o{ AccessRequests : заявки
    AspNetUsers ||--o{ PersonalAccessTokens : PAT
    AspNetUsers ||--o{ ExternalIdentities : "привязка мессенджера"
    AspNetUsers ||--o{ PasswordHistory : "история паролей"
    OpenIddictApplications ||--o{ OpenIddictAuthorizations : "сессии"
    OpenIddictAuthorizations ||--o{ OpenIddictTokens : "refresh / access"
    AccessRoles ||--o{ AccessRolePermissions : матрица
    AccessPermissions ||--o{ AccessRolePermissions : матрица
    AccessRoles ||--o{ AccessRoleAssignments : назначения
    AccessRoles ||--o{ AccessRequests : "запрошенная роль"
    WebhookSubscriptions ||--o{ WebhookDeliveries : outbox
    WebhookEvents ||--o{ WebhookDeliveries : outbox

    AspNetUsers {
        guid Id
        string UserName "AES-256-GCM"
        string NormalizedUserName "HMAC-индекс"
        string Email "AES-256-GCM"
        string PasswordHash "PBKDF2-SHA512"
        bool IsActive
        bool MustChangePassword
        string CreatedByClientId
    }
    AccessRoles {
        guid Id
        string ClientId "приложение"
        string Name
        bool IsRequestable
    }
    AccessPermissions {
        guid Id
        string ClientId
        string Name
    }
    AccessRoleAssignments {
        guid RoleId
        int SubjectType "User / Client"
        string SubjectId
    }
```

Прочие таблицы: `KeyMaterials` (ключи подписи и шифрования токенов, зашифрованы), `DataProtectionKeys` (ключи cookie, зашифрованы),
`AuditLog`, `SystemSettings`, `LanguagePacks`, `BotLinkCodes`, `AccessRequests`.

**Приложение = клиент + ресурс.** Каждое зарегистрированное приложение одновременно является OAuth-клиентом
и API-ресурсом: для него создаётся scope с тем же именем. Когда клиент запрашивает scope приложения, оно
попадает в `aud` токена, а права пользователя в этом приложении — в `permissions`.

## Как формируется токен

```mermaid
flowchart LR
    R[Запрос токена<br/>client_id, scope] --> A[Аудитории:<br/>client_id + ресурсы запрошенных scope]
    A --> G[Роли субъекта в этих приложениях<br/>AccessRoleAssignments]
    G --> M[Разрешения ролей<br/>матрица AccessRolePermissions]
    M --> C["claims: role = app:роль<br/>permissions = app:разрешение<br/>resource_access = {app: {roles, permissions}}"]
    C --> L["Срок жизни: min(глобальный,<br/>приложения, запрошенный)"]
    L --> S[Подпись RS256<br/>общим ключом кластера]
```

Права вычисляются **при каждой выдаче**, в том числе при refresh, поэтому изменения матрицы и назначений
вступают в силу без повторного входа пользователя (не позже срока жизни access-токена).

## Кластер и сохранность состояния

```mermaid
flowchart TB
    subgraph Состояние только в БД
        K[Ключи подписи и шифрования токенов]
        DP[Ключи Data Protection<br/>cookie, antiforgery]
        T[Авторизации и refresh-токены]
        S[Настройки, языковые пакеты]
        E[Лента событий, outbox вебхуков]
    end
    N1[Узел 1] & N2[Узел 2] & N3[Узел 3] --> K & DP & T & S & E
```

Узлы не хранят состояния в памяти (кроме кэшей на 30 секунд), поэтому:

* запрос можно обслужить на любом узле — «липкие» сессии не нужны;
* перезапуск или отказ узла не разрывает сессии пользователей, а ранее выданные JWT остаются валидными (ключи общие);
* изменения настроек, прав и языков видны всем узлам не позже чем через 30 секунд, отзыв сессий действует сразу.

**Старт узла:**

```mermaid
sequenceDiagram
    participant N as Узел
    participant PG as PostgreSQL
    N->>PG: подключение (повторы до 60 с, пока БД стартует)
    N->>PG: CREATE DATABASE, если её нет
    N->>PG: pg_advisory_lock — одновременно стартует только один узел
    N->>PG: проверка версии схемы, применение недостающих миграций
    Note over N,PG: если БД новее образа — старт отменяется (защита от отката)
    N->>PG: загрузка ключей подписи (или создание при первом старте)
    N->>PG: начальные данные: системное приложение, роли, первый администратор
    N->>PG: снятие блокировки
    N-->>N: приём запросов
```

**Фоновые задачи в кластере** не мешают друг другу:

* доставка вебхуков — экземпляр «захватывает» доставку условным `UPDATE`, поэтому каждое событие отправляется ровно одним узлом; если узел упал, блокировка истекает и доставку подхватывает другой;
* очистка по срокам хранения стартует со случайной задержкой, повторный запуск безопасен.

## Хранение секретов

```mermaid
flowchart LR
    MK[Мастер-ключ<br/>ENCRYPTION_MASTER_KEY<br/>или файл] -- HKDF --> FK[Ключ шифрования полей<br/>AES-256-GCM]
    MK -- HKDF --> IK[Ключ HMAC-индексов]
    FK --> PD[ПДн: логин, email, телефон, имя,<br/>комментарии, детали аудита]
    FK --> KM[Ключи подписи JWT и шифрования<br/>refresh-токенов в KeyMaterials]
    FK --> DPK[Ключи Data Protection]
    IK --> BI[Поиск по логину/email<br/>без расшифровки]
```

* Мастер-ключ общий для всех узлов и **никогда** не хранится в БД. Без него данные не расшифровать — храните резервную копию отдельно от бэкапов БД.
* Пароли не шифруются, а хешируются (PBKDF2-HMAC-SHA512, 100 000 итераций, соль).
* Секреты клиентов хранятся хешем (OpenIddict), PAT — SHA-256, коды привязки бота — SHA-256.
* Refresh-токены ссылочные: клиент получает случайный идентификатор, содержимое хранится в БД зашифрованным.
