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
| `Database__ConnectionStringFile` | — | Путь к файлу со строкой подключения (docker secrets: `/run/secrets/db_connection_string`) — пароль БД не попадает в переменные окружения |

### Шифрование

| Переменная | Описание |
|---|---|
| `Encryption__MasterKey` | Мастер-ключ (base64, ≥ 32 байт). **Обязателен для PostgreSQL**, одинаков на всех узлах |
| `Encryption__MasterKeyFile` | Путь к файлу с ключом (docker secrets: `/run/secrets/master_key`). Для SQLite без ключа генерируется `master.key` рядом с БД, но **только для новой БД**: если файл БД уже есть, а ключа нет (например, не примонтирован том), сервис не стартует — новый ключ сделал бы все зашифрованные данные нечитаемыми |

### Сервер авторизации

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Auth__Issuer` | — | Публичный адрес сервиса: `iss` в токенах, discovery и ссылки в письмах (приглашения, сброс пароля). **Обязателен** вне среды Development — без него сервис не стартует. Абсолютный адрес `http(s)://` без query, одинаковый на всех узлах. Из заголовка `Host` запроса адрес не берётся никогда. Служебным командам CLI (`admin reset-password`, `admin migrate-to-postgres`) не нужен |
| `AllowedHosts` | `*` | Допустимые значения заголовка `Host` через `;` (стандартная фильтрация ASP.NET Core). Рекомендуется задать имя из `Auth__Issuer`, например `auth.corp`: запросы с чужим `Host` получат 400 |
| `Auth__RequireHttps` | `true` | Отклонять OAuth-запросы по HTTP, включить HSTS |
| `Auth__TrustForwardedHeaders` | `false` | Сервис за обратным прокси: принимать `X-Forwarded-For` (IP клиента для лимитов и журнала) и `X-Forwarded-Proto` (схема). `X-Forwarded-Host` не принимается |
| `Auth__KnownNetworks` | loopback и частные сети | Подсети прокси (CIDR через запятую), от которых принимаются `X-Forwarded-*` при `TrustForwardedHeaders=true`. Пусто — `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`. Из этих сетей узлы не должны быть доступны напрямую, в обход прокси |
| `Auth__RefreshTokenReuseLeewaySeconds` | `30` | Окно повторного использования refresh-токена (защита от сетевых повторов клиента). `0` — строго одноразовые |
| `Auth__AccessTokenLifetimeMinutes`, `Auth__IdentityTokenLifetimeMinutes`, `Auth__RefreshTokenLifetimeDays`, `Auth__AuthorizationCodeLifetimeMinutes` | 15 мин / 15 мин / 14 дн. / 5 мин | **Значения по умолчанию** для политики токенов в БД: действуют, пока администратор не сохранил политику токенов в админке («Настройки») или через `PUT /api/admin/settings`. После сохранения действуют значения из БД, а эти переменные ни на что не влияют |

### Первичная инициализация

| Переменная | Описание |
|---|---|
| `Bootstrap__AdminUserName` | Логин первого администратора (`admin`) |
| `Bootstrap__AdminPassword` | Его пароль; если пусто — генерируется одноразовый и выводится в лог |
| `Bootstrap__AdminPasswordFile` | То же из файла (docker secrets: `/run/secrets/admin_password`) |
| `Bootstrap__AdminEmail` | Email администратора |
| `Bootstrap__AdminApiClientId` / `...Secret` | Создать клиент Admin API с ролью `administrator` (для автоматизации) |
| `Bootstrap__AdminApiClientSecretFile` | Секрет этого клиента из файла (docker secrets: `/run/secrets/admin_api_client_secret`) |

Администратор создаётся, только если в системе ещё нет ни одного администратора.

### Секреты из файлов (docker secrets)

Переменные `*File` — альтернатива передаче секретов через окружение, где их видно в `docker inspect` и окружении
процесса: `Encryption__MasterKeyFile`, `Database__ConnectionStringFile`, `Bootstrap__AdminPasswordFile`,
`Bootstrap__AdminApiClientSecretFile`. Если путь указан, а файла нет, сервис не стартует: опечатка в пути не превращается
молча в «секрет не задан». Завершающий перевод строки в файле обрезается. Готовые примеры —
`docker-compose.secrets.yml` (одиночный режим) и `docker-compose.ha-secrets.yml` (кластер), см.
[развёртывание](deployment.md#секреты-файлами-docker-secrets).

### Безопасность

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Security__TokenRequestsPerMinute` | `600` | Лимит запросов к `/connect/token`, `/connect/introspect` и `/connect/revoke` с одного IP в минуту (на узел) |
| `Security__LoginAttemptsPerMinute` | `30` | Лимит POST-запросов страниц входа/сброса с одного IP в минуту |

### Почта (SMTP)

| Переменная | Описание |
|---|---|
| `Smtp__Host`, `Smtp__Port` | Внутренний SMTP-сервер. Пусто — письма не отправляются, приглашения выдаются ссылкой в админке |
| `Smtp__Security` | `None`, `StartTls`, `SslOnConnect`, `StartTlsWhenAvailable`, `Auto` |
| `Smtp__UserName`, `Smtp__Password` | Учётные данные (если нужны) |
| `Smtp__From` | Отправитель: `TSL Auth <no-reply@corp.local>` |

### Вебхуки

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Webhooks__AllowedNetworks` | — | Подсети (CIDR через запятую), в которые разрешена доставка вебхуков; пусто — любые, кроме запрещённых. Всегда запрещены loopback, link-local (в т.ч. `169.254.169.254`), multicast и `0.0.0.0`; редиректы не выполняются, системный прокси не используется. Частные сети по умолчанию разрешены: получатели в закрытом контуре обычно именно там |
| `Docs__Public` | `true` | Руководство `/docs`, справочник `/docs/api` и `/openapi/v1.json` доступны без входа. `false` — только вошедшим пользователям с правом просмотра админки (для сервиса, опубликованного во внешнюю сеть) |

### HTTPS в контейнере (Kestrel)

`Kestrel__Endpoints__Https__Url=https://+:8443`, `Kestrel__Endpoints__Https__Certificate__Path` и
`...__KeyPath` (PEM) либо `...__Password` (PFX). Для незашифрованного PEM-ключа `Password` не задавайте вовсе: даже пустое
значение заставляет Kestrel читать ключ как зашифрованный, и сервис не стартует. Для PFX, наоборот, не задавайте
`KeyPath`. Готовые конфигурации — `docker-compose.https.yml` (PEM) и `docker-compose.https-pfx.yml` (PFX).

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
    "patAccessTokenMinutes": 15, "identityTokenMinutes": 15, "authorizationCodeMinutes": 5, "maxSessionDays": 90
  },
  "patPolicy": { "enabled": true, "maxLifetimeDays": 365, "maxTokensPerUser": 20 },
  "botResetPolicy": { "enabled": true, "mode": "link", "maxPerUserPerHour": 3 }
}
```

| Группа | Смысл |
|---|---|
| Хранение | Сроки хранения журнала безопасности (общий и по типам/префиксам событий — действует самое точное совпадение), ленты событий, отработанных токенов |
| `passwordPolicy` | Требования к паролю, история (запрет повтора последних N), срок действия (0 — бессрочно), блокировка после N неудачных попыток |
| `tokenPolicy` | **Максимальные** сроки жизни. Приложение может задать меньше в своей карточке, клиент — запросить меньше параметрами `expires_in` / `refresh_expires_in`; больше — нельзя. `maxSessionDays` — абсолютный срок сессии: refresh продлевает токены не дольше этого числа дней от входа, дальше нужен новый вход (`0` — без ограничения). Пока политика не сохранена, сроки берутся из `Auth__*LifetimeMinutes/Days` (см. выше) |
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
