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
| `Database__SchemaRepair` | `Auto` | Самовосстановление схемы при старте: `Auto` — пересобрать схему с переносом данных, если БД повреждена или её схема не та ([эксплуатация](operations.md#самовосстановление-бд)); `Off` — остановить запуск с ошибкой |
| `Database__AllowDowngrade` | `false` | Разрешить запуск на схеме новее версии сервиса (откат образа): схема пересобирается под эту версию, данные новых столбцов теряются |

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

### OpenBao (хранилище секретов, после MVP)

Для MVP OpenBao не нужен: все секреты задаются теми же ключами в переменных окружения или в `appsettings.json`
([развёртывание](deployment.md#секреты-в-переменных-и-конфиге-mvp-по-умолчанию)). Параметры ниже нужны только при переходе на OpenBao.


| Переменная | По умолчанию | Описание |
|---|---|---|
| `OpenBao__Address` | — | Адрес OpenBao, например `http://openbao:8200`. Пусто — OpenBao не используется |
| `OpenBao__Mount` | `secret` | Точка монтирования KV v2 |
| `OpenBao__Path` | `tsl-auth` | Путь секретов; несколько — через запятую, позже указанный перекрывает раньше указанный |
| `OpenBao__RoleIdFile`, `OpenBao__SecretIdFile` | — | AppRole: файлы с `role_id` и `secret_id` (`OpenBao__RoleId` — значение вместо файла) |
| `OpenBao__TokenFile` | — | Вместо AppRole: файл с токеном, например от агента OpenBao |
| `OpenBao__CaFile` | — | Корневой сертификат для HTTPS-подключения к OpenBao |
| `OpenBao__Retries` | `30` | Повторы по 2 с, пока OpenBao недоступен или запечатан. Ошибки доступа (403, неверный `secret_id`) не повторяются |

Ключ секрета совпадает с именем настройки: `Encryption__MasterKey`, `Database__ConnectionString`, `Smtp__Password` и так далее. Поэтому в OpenBao можно перенести любую настройку. Секреты читаются при старте: после ротации перезапустите сервис, в кластере поочерёдно. Подробнее — в [развёртывании](deployment.md#секреты-в-openbao-после-mvp).

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
| `Smtp__UserName`, `Smtp__Password` | Учётные данные, если нужны (`SMTP_USER`, `SMTP_PASSWORD` в `.env`; после MVP — в OpenBao) |
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

### Файл настроек вместо переменных

Все параметры запуска — те же ключи в `appsettings.json` (`Observability__Prometheus__Enabled` ≡ `"Observability": { "Prometheus": { "Enabled": … } }`).
Файл можно держать отдельно от образа:

* смонтировать поверх `/app/appsettings.Production.json` — он накладывается на встроенный `appsettings.json`, достаточно
  перечислить изменяемые ключи (пример со всеми разделами — `deploy/appsettings.Production.example.json`;
  строка монтирования закомментирована в `docker-compose.yml`);
* `APPSETTINGS_PATH=/etc/tsl-auth/appsettings.json` — явный путь к файлу (или к каталогу с `appsettings.json`);
  указан, но файла нет — сервис не стартует;
* если в каталоге приложения нет `appsettings.json`, он ищется в родительских каталогах до корня диска (то же для
  `appsettings.{Environment}.json`) — удобно при запуске из `bin/` вне контейнера.

Приоритет прежний: файлы → переменные окружения → аргументы командной строки. Откуда взяты файлы, сервис пишет в лог при старте.

**Пустая переменная окружения считается незаданной.** docker compose передаёт в контейнер все переменные из списка, в том числе
пустые (`SMTP_PASSWORD=` в `.env`). Такие переменные не перекрывают значения из файла настроек. Поэтому в MVP секреты
можно держать в `appsettings.json`, не удаляя переменные из compose. Непустая переменная по-прежнему перекрывает файл.
Пример файла со всеми секретами — `deploy/appsettings.mvp.example.json`.

### Журналирование

Логи пишет Serilog: в stdout контейнера, при необходимости — в файл и по OTLP. Сервис сам в хранилище логов не пишет:
на стенде мониторинга stdout контейнеров забирает Vector и передаёт в VictoriaLogs (см. [мониторинг](#мониторинг-prometheus-opentelemetry)).
Уровни по категориям задаются здесь как значения по умолчанию, а меняются на лету в админке
(«Настройки» → «Журналирование») или через `PUT /api/admin/settings` — на всех узлах, без перезапуска.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Logging__LogLevel__Default` | `Information` | Уровень по умолчанию: `Trace`, `Debug`, `Information`, `Warning`, `Error`, `Critical`, `None` |
| `Logging__LogLevel__<Категория>` | `Microsoft.AspNetCore`, `Microsoft.EntityFrameworkCore`, `OpenIddict`, `Serilog.AspNetCore.RequestLoggingMiddleware` — `Warning` | Уровень для категории или её префикса (самое длинное совпадение). `Serilog.AspNetCore.RequestLoggingMiddleware=Information` включает строку на каждый HTTP-запрос (метод, путь, код, время) |
| `Logging__Format` | `Text` (в compose — `Json`, переменная `LOG_FORMAT`) | Формат консоли: `Text` — для чтения глазами, `Json` — одна строка на запись со всеми полями (компактный JSON Serilog; его разбирает Vector, подходит для драйверов Docker и SIEM) |
| `Logging__File__Enabled` | `false` | Явное включение журнала на диске. Без него `Logging__File__Path` игнорируется: правило проекта — журнал только в stdout |
| `Logging__File__Path` | — | Журнал на диске (для запуска вне контейнера; в контейнере ротацию делает Docker). Шаблон `logs/tsl-auth-.log` → `tsl-auth-20260925.log`, при переполнении `…_001.log` |
| `Logging__File__SizeLimitMb` | `20` | Размер, при котором начинается новый файл |
| `Logging__File__RetainedFiles` | `5` | Сколько файлов всего держать на диске (текущий + архивы); старые удаляются |
| `Logging__File__Compress` | `true` | Ротированные файлы сжимаются в `.gz` |
| `Logging__Serilog__Enabled` | `false` | Разрешить секцию `Serilog` из конфигурации (сторонние приёмники: Seq, syslog). Без флага секция не читается, чтобы приёмник не появился незаметно |

Секция `Serilog` в `appsettings.json` тоже читается ([Serilog.Settings.Configuration](https://github.com/serilog/serilog-settings-configuration)) —
через неё подключаются дополнительные приёмники (Seq, syslog, Elasticsearch) без пересборки.

### Мониторинг (Prometheus, OpenTelemetry)

Каждая подсистема включается отдельно и только когда подключена: метрики собираются, если включён эндпоинт `/metrics`
(формат Prometheus) или экспорт по OTLP, трассировки — если задан OTLP-адрес. Ничего не задано — накладных расходов нет.
Логи сервис отдаёт только в stdout (см. [журналирование](#журналирование)). Что именно отправляется — в [эксплуатации](operations.md#мониторинг).

| Переменная | По умолчанию | Описание |
|---|---|---|
| `Observability__ServiceName` | `tsl-auth` | `service.name` во всех сигналах (на стенде — поле `service` в VictoriaLogs задаёт Vector) |
| `Observability__InstanceId` | имя хоста | `service.instance.id` / метка `instance`; в кластере — `auth1`…`auth3` (hostname контейнера) |
| `Observability__ResourceAttributes` | — | Дополнительные атрибуты ресурса: `deployment.environment=prod,dc=msk` |
| `Observability__Prometheus__Enabled` | `false` | Эндпоинт `/metrics` в формате Prometheus (на каждом узле; на стенде его опрашивает VictoriaMetrics) |
| `Observability__Prometheus__Path` | `/metrics` | Путь эндпоинта |
| `Observability__Prometheus__AllowedNetworks` | loopback и частные сети | Подсети (CIDR через запятую), откуда разрешён опрос; из других — 403 |
| `Observability__Prometheus__Token`, `...TokenFile` | — | Bearer-токен для опроса (в конфигурации опроса VictoriaMetrics/Prometheus — `authorization.credentials`); без него — 401 |
| `Observability__OpenTelemetry__Endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | Адрес коллектора или бэкенда OTLP: `http://otel-collector:4317` (gRPC) или `:4318` (HTTP). Пусто — OTLP выключен |
| `Observability__OpenTelemetry__Protocol` | `grpc` | `grpc` или `http` (http/protobuf; пути `/v1/traces`, `/v1/metrics`, `/v1/logs` добавляются сами) |
| `Observability__OpenTelemetry__Headers`, `...HeadersFile` | — | Заголовки запросов к коллектору: `Authorization=Bearer …,X-Scope-OrgID=team` |
| `Observability__OpenTelemetry__Traces` / `Metrics` / `Logs` | `true` (в compose `Metrics` и `Logs` — `false`: `OBS_OTLP_METRICS`, `OBS_OTLP_LOGS`) | Какие сигналы отправлять по OTLP (например, `Metrics=false`, если метрики забираются с `/metrics`, `Logs=false`, если логи собираются из stdout) |
| `Observability__OpenTelemetry__TraceSamplingRatio` | `1.0` | Доля трассируемых запросов (0–1); решение вышестоящего сервиса (`traceparent`) уважается |
| `Observability__OpenTelemetry__MetricsExportIntervalSeconds` | `30` | Период отправки метрик по OTLP |

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
  "botResetPolicy": { "enabled": true, "mode": "link", "maxPerUserPerHour": 3 },
  "loggingPolicy": { "defaultLevel": "Information", "overrides": { "Serilog.AspNetCore.RequestLoggingMiddleware": "Information", "TslAuth": "Debug" } }
}
```

| Группа | Смысл |
|---|---|
| Хранение | Сроки хранения журнала безопасности (общий и по типам/префиксам событий — действует самое точное совпадение), ленты событий, отработанных токенов |
| `passwordPolicy` | Требования к паролю, история (запрет повтора последних N), срок действия (0 — бессрочно), блокировка после N неудачных попыток |
| `tokenPolicy` | **Максимальные** сроки жизни. Приложение может задать меньше в своей карточке, клиент — запросить меньше параметрами `expires_in` / `refresh_expires_in`; больше — нельзя. `maxSessionDays` — абсолютный срок сессии: refresh продлевает токены не дольше этого числа дней от входа, дальше нужен новый вход (`0` — без ограничения). Пока политика не сохранена, сроки берутся из `Auth__*LifetimeMinutes/Days` (см. выше) |
| `patPolicy` | Разрешены ли персональные токены, их максимальный срок и число на пользователя |
| `botResetPolicy` | Сброс пароля через бота: `link` (одноразовая ссылка, бот не видит пароль) или `temporary` (временный пароль), лимит сбросов в час |
| `loggingPolicy` | Глубина логирования поверх конфигурации: уровень по умолчанию и переопределения по категориям/префиксам (`null` или отсутствие поля — только конфигурация). Применяется на всех узлах за ≤ 35 с без перезапуска |

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
