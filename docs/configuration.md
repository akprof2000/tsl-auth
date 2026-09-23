# Конфигурация

Настройки двух видов:

* **Параметры запуска** — переменные окружения (или `appsettings.json`); применяются при старте, одинаковые для всех узлов.
* **Настройки в БД** — меняются в админке («Настройки») или через `PUT /api/admin/settings` без перезапуска; узлы подхватывают их за ≤ 30 с.

## Параметры запуска

Формат переменных: `Раздел__Параметр` (двойное подчёркивание). В compose-файлах часть из них берётся из `.env`.

### База данных

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Database__Provider` | `Sqlite` | `Sqlite` или `Postgres` |
| `Database__ConnectionString` | `Data Source=data/tsl-auth.db` | Строка подключения. PostgreSQL: `Host=...;Database=...;Username=...;Password=...` |

### Шифрование

| Переменная | Описание |
|---|---|
| `Encryption__MasterKey` | Мастер-ключ (base64, ≥ 32 байт). **Обязателен для PostgreSQL**, одинаков на всех узлах |
| `Encryption__MasterKeyFile` | Путь к файлу с ключом (docker secrets: `/run/secrets/tsl_master_key`). Для SQLite без ключа — генерируется `master.key` рядом с БД |

### Сервер авторизации

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Auth__Issuer` | адрес запроса | Публичный адрес сервиса (`iss` в токенах). **Задавайте всегда** в продуктиве и кластере |
| `Auth__RequireHttps` | `true` | Отклонять OAuth-запросы по HTTP, включить HSTS |
| `Auth__TrustForwardedHeaders` | `false` | Доверять `X-Forwarded-*` (сервис за прокси) |
| `Auth__RefreshTokenReuseLeewaySeconds` | `30` | Окно повторного использования refresh-токена (защита от сетевых повторов клиента). `0` — строго одноразовые |
| `Auth__AccessTokenLifetimeMinutes` и др. | 15 / 14 дн. | Значения по умолчанию до первой настройки в БД (дальше действуют настройки из БД) |

### Первичная инициализация

| Переменная | Описание |
|---|---|
| `Bootstrap__AdminUserName` | Логин первого администратора (`admin`) |
| `Bootstrap__AdminPassword` | Его пароль; если пусто — генерируется одноразовый и выводится в лог |
| `Bootstrap__AdminEmail` | Email администратора |
| `Bootstrap__AdminApiClientId` / `...Secret` | Создать клиент Admin API с ролью `administrator` (для автоматизации) |

Администратор создаётся, только если в системе ещё нет ни одного администратора.

### Безопасность

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Security__TokenRequestsPerMinute` | `600` | Лимит запросов к `/connect/token` с одного IP в минуту (на узел) |
| `Security__LoginAttemptsPerMinute` | `30` | Лимит POST-запросов страниц входа/сброса с одного IP в минуту |

### Почта (SMTP)

| Переменная | Описание |
|---|---|
| `Smtp__Host`, `Smtp__Port` | Внутренний SMTP-сервер. Пусто — письма не отправляются, приглашения выдаются ссылкой в админке |
| `Smtp__Security` | `None`, `StartTls`, `SslOnConnect`, `StartTlsWhenAvailable`, `Auto` |
| `Smtp__UserName`, `Smtp__Password` | Учётные данные (если нужны) |
| `Smtp__From` | Отправитель: `TSL Auth <no-reply@corp.local>` |

### HTTPS в контейнере (Kestrel)

`Kestrel__Endpoints__Https__Url=https://+:8443`, `Kestrel__Endpoints__Https__Certificate__Path`,
`...__KeyPath` (PEM) или `...__Password` (PFX). Готовая конфигурация — `docker-compose.https.yml`.

## Настройки в БД

`GET/PUT /api/admin/settings` (JSON) — те же поля, что на странице «Настройки».

```json
{
  "auditRetentionDays": 365,
  "auditLogTokenRefresh": false,
  "eventsRetentionDays": 30,
  "tokensRetentionHours": 24,
  "auditRetentionByType": { "token.issued": 30, "auth.login.failed": 365, "admin.change": 1825, "auth.": 180 },
  "passwordPolicy": {
    "minLength": 8, "requireUppercase": true, "requireLowercase": true, "requireDigit": true, "requireSymbol": false,
    "minUniqueChars": 1, "historyCount": 0, "maxAgeDays": 0, "maxFailedAttempts": 5, "lockoutMinutes": 15
  },
  "tokenPolicy": {
    "accessTokenMinutes": 15, "refreshTokenDays": 14, "exchangeTokenMinutes": 5,
    "patAccessTokenMinutes": 15, "identityTokenMinutes": 15, "authorizationCodeMinutes": 5
  },
  "patPolicy": { "enabled": true, "maxLifetimeDays": 365, "maxTokensPerUser": 20 },
  "botResetPolicy": { "enabled": true, "mode": "link", "maxPerUserPerHour": 3 }
}
```

| Группа | Смысл |
|---|---|
| Хранение | Сроки хранения журнала безопасности (общий и по типам/префиксам событий — действует самое точное совпадение), ленты событий, отработанных токенов |
| `passwordPolicy` | Требования к паролю, история (запрет повтора последних N), срок действия (0 — бессрочно), блокировка после N неудачных попыток |
| `tokenPolicy` | **Максимальные** сроки жизни. Приложение может задать меньше в своей карточке, клиент — запросить меньше параметрами `expires_in` / `refresh_expires_in`; больше — нельзя |
| `patPolicy` | Разрешены ли персональные токены, их максимальный срок и число на пользователя |
| `botResetPolicy` | Сброс пароля через бота: `link` (одноразовая ссылка, бот не видит пароль) или `temporary` (временный пароль), лимит сбросов в час |

### Настройки на уровне приложения (карточка приложения / Admin API)

| Что | API |
|---|---|
| Потоки, redirect URI, scopes, самоуправление, самостоятельная регистрация | `PUT /api/admin/applications/{clientId}` |
| Сроки жизни токенов (≤ глобальных) | `PUT /api/admin/applications/{clientId}/token-lifetimes` |
| Оформление страницы входа и язык по умолчанию | `PUT /api/admin/applications/{clientId}/branding` |
| Матрица доступа | `PUT /api/admin/applications/{clientId}/matrix` |

### Языковые пакеты

`GET /api/admin/languages/template` — все ключи со значениями по умолчанию; переведите и загрузите:
`PUT /api/admin/languages/kk` с телом `{ "name": "Қазақша", "strings": { ... } }`. Можно передать только часть ключей —
остальные возьмутся из русского. Переопределить строки встроенного языка (`ru`, `en`) можно так же.
