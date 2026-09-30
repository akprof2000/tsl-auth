# TSL Auth — инструкции для Claude Code

Сервис аутентификации и авторизации (аналог Keycloak) для ERP «Уклад»: OIDC/OAuth 2.0, матрица доступа
приложений, админка, App API, Bot API, клиентские библиотеки на пяти языках. Работает в **закрытом контуре**
без интернета. Этот файл — всё, что нужно, чтобы продолжить работу в новой среде или сессии.

## Поддержка этого файла

**Этот файл обязательно поддерживать актуальным.** После любого изменения, которое влияет на то, как работать
с проектом (стек, структура, команды, правила, репозитории, CI, агенты, секреты и где они лежат, особенности GitFlic,
принятые решения пользователя), обновить соответствующий раздел здесь в том же коммите. Новые проверенные факты
и обходные решения — дописывать; устаревшее — исправлять или удалять, а не оставлять рядом. Перед завершением
задачи сверить файл с тем, что изменилось.

## Язык и общение

- Пользователь пишет по-русски; отвечать, писать документацию, комментарии в коде и сообщения коммитов — по-русски.
- Пароли и секреты никогда не вводить в поля браузера и не печатать в чат/журналы: пользователь вводит их сам.
  Значения токенов из локальных файлов не выводить, только имена ключей.

## Стек

- .NET 10, ASP.NET Core, OpenIddict 7, ASP.NET Identity, EF Core; Razor Pages для админки и страниц входа.
- БД: SQLite (одиночный режим) или PostgreSQL (кластер). Схема обновляется при старте (миграции EF, advisory-lock).
- Шифрование ПДн AES-256-GCM + слепые индексы HMAC; пароли PBKDF2. Мастер-ключ — `Encryption__MasterKey` или файл.
- Логи — только Serilog в stdout (JSON); файл лишь при `Logging__File__Enabled=true`. Метрики `/metrics`, OTLP.
- Секреты MVP — переменные окружения и файлы настроек; OpenBao — необязательный оверлей (`docker-compose.openbao.yml`).
- Никаких CDN и внешних вызовов в рантайме; образы переносятся `scripts/export-images.ps1` / `import-images.*`.

## Структура

| Путь | Что |
|---|---|
| `src/TslAuth` | сервис (Api, Controllers, Pages, Services, Infrastructure, Data) |
| `tests/TslAuth.UnitTests` | unit |
| `tests/TslAuth.IntegrationTests` | интеграционные: SQLite и PostgreSQL/OpenBao через Testcontainers (нужен Docker) |
| `tests/TslAuth.UiTests` | Playwright против стенда с демо-приложениями |
| `tests/load`, `tests/resilience`, `tests/e2e` | k6, сценарии отказов, запуск демо для E2E |
| `tests/sdk-contract` | контрактные тесты SDK: `make-vectors.py` + `run.ps1` |
| `sdk/{dotnet,node,go,python,java}` | клиентские библиотеки; контракт — `docs/client-contract.md`; `sdk/VERSION` = MAJOR.MINOR |
| `samples/` | демо: dotnet-mvc 5101, node-spa 5102, go-api 5103, python-app 5104, java-api 5105, docflow-demo; `seed-demo.ps1` |
| `docs/` | ЧТЗ (`tz.md` + Word), архитектура, развёртывание, конфигурация, интеграция, SDK, тестирование, релизная политика, GitFlic |
| `deploy/` | nginx, примеры appsettings, стенд мониторинга (Victoria), OpenBao |
| `scripts/` | экспорт/импорт образов, проверка документации, утилиты GitFlic (см. ниже) |
| `gitflic-ci.yaml` | единственный рабочий конвейер CI/CD |

## Команды

```powershell
dotnet build TslAuth.sln -c Release -warnaserror
dotnet test tests/TslAuth.UnitTests
dotnet test tests/TslAuth.IntegrationTests          # нужен запущенный Docker (Docker Desktop сам не стартует после перезагрузки)
docker compose up -d --build                         # стенд на http://localhost:8080
./samples/seed-demo.ps1                              # демо-приложения, матрицы, alice/bob
./tests/sdk-contract/run.ps1                         # стенд + контрактные тесты пяти SDK
pwsh scripts/validate-docs.ps1 -SkipMermaid          # ссылки, якоря, таблицы в README и docs/*.md
```

После изменения схем Mermaid в документации — `scripts/render-diagrams.ps1` (картинки в `docs/diagrams`).

## Правила работы

- **Коммиты сразу в `main`**, без веток и pull request'ов. В конце сообщения коммита — строка соавторства.
- **Полная пирамида тестов** для любого изменения/проекта: unit → интеграционные (SQLite и PostgreSQL) → нагрузка →
  отказоустойчивость → наблюдаемость → UI-автотесты. В отчёте указывать, какие уровни прогнаны.
- Документация и ЧТЗ меняются вместе с поведением; расхождение — дефект, блокирует релиз.
- Демо используют опубликованный образ, а не сборку из исходников (кроме E2E-стенда в CI).
- Место ограничено: артефакты CI живут до суток, в реестрах и релизах — не больше трёх версий.
- Релизная политика — `docs/release-policy.md` (semver, что блокирует релиз, откат).

## Репозитории и CI

- **Основной репозиторий — GitFlic** `https://gitflic.ru/project/uklad/tsl-auth` (remote `origin`).
  **GitHub** `akprof2000/tsl-auth` — зеркало (remote `github`); все workflow на GitHub отключены, новые не добавлять.
- `git push origin main` отправляет в оба (у `origin` два push-URL). Задание `mirror-github` конвейера тоже
  зеркалирует (переменная проекта `GITHUB_MIRROR_TOKEN`).
- Учётные данные git для GitFlic: `git config credential.https://gitflic.ru.helper '!sh scripts/git-credential-gitflic.sh'` —
  берёт токен из `C:\Projects\TSL\Key\gitflic-tokens.env` (строка `GITFLIC_API_TOKEN=…`, файл вне репозитория).
- Релиз: тег `vX.Y.Z` на `main` → конвейер по тегу → образ и пакеты в реестры GitFlic + релиз GitFlic.
  Версия прогонов `main` на GitFlic: `sdk/VERSION` + unix-время коммита (например `1.4.1790745826`).
- Реестры GitFlic: образ `registry.gitflic.ru/project/uklad/tsl-auth/tsl-auth`, пакеты
  `https://registry.gitflic.ru/project/uklad/tsl-auth/package/-/<nuget|npm|pypi|maven>`.
- Переменные проекта GitFlic (значения не трогать и не выводить): `GITFLIC_PKG_USER`, `GITFLIC_PKG_TOKEN`
  (транспортный токен), `GITFLIC_API_TOKEN` (очистка), `GITHUB_MIRROR_TOKEN`, `GITFLIC_PUBLISH_FROM_AGENT` (`false` выключает
  публикацию), `DRY_RUN` (`1` — очистка только показывает).

### Работа с GitFlic без браузера

`scripts/gitflic.ps1` (REST API api.gitflic.ru, токен из того же файла):

```powershell
./scripts/gitflic.ps1 pipelines -Top 5      # конвейеры
./scripts/gitflic.ps1 jobs 47               # задания конвейера
./scripts/gitflic.ps1 runners               # агенты
./scripts/gitflic.ps1 prune-pipelines -Keep 3   # удалить старые конвейеры вместе с артефактами
./scripts/gitflic.ps1 raw GET /project/uklad/tsl-auth/cicd/job/347/artifacts
```

Журнал задания — артефакт с `fileType: trace` (скачать по `downloadUrl` с заголовком `Authorization: token …`).
Запуск конвейера: `POST /project/uklad/tsl-auth/cicd/pipeline/start` с телом `{"ref":"main"}`.

### Агенты

- Два агента на сервере в Хельсинки `77.42.83.24`: `tsl-auth-hel-1`, `tsl-auth-hel-2`, теги `tsl-auth,tsl-auth-hel`.
  Compose в `~/gitflic-runner` (образ `registry.gitflic.ru/company/gitflic/runner:latest`, `PRIVILEGED=true`, `REG_URL` с явным `:443`).
- SSH: `ssh -p 443 alexey_kozlov@77.42.83.24`, ключ `C:\Projects\TSL\Key\id_ed25519` с парольной фразой —
  пользователь загружает его в ssh-agent Windows (`ssh-add`), подключаться через `ssh.exe` из PowerShell (Git Bash агент не видит).
- На сервере живут чужие сервисы (`uklad-gitflic-runner`, plaudio, youtrack, platform_dev) — их не трогать.
- Задания с docker:dind оставляют анонимные тома (до 100 ГБ в сутки): чистить висячие тома, в которых есть
  `overlay2`, `containers`, `image`. Теги уже зарегистрированного агента меняются через API (`runner-tags`), а не `TAGS` в compose.
- `net-check-hel` в каждом конвейере проверяет, что с сервера качается слой из реестра GitFlic (раньше путь обрывался).

### Особенности GitFlic (проверено)

- Имена заданий не должны совпадать с ключевыми словами (`image`, `release`, `services`), иначе файл даёт 0 заданий.
- Парсер YAML GitFlic отвергает строки `script`, где в кавычках есть `: ` или `%{…}` — такие команды выносить в `scripts/*.sh`.
- `$CI_PIPELINE_ID` — UUID, `CI_PROJECT_PATH` нет (путь брать из `CI_REGISTRY_IMAGE`), клон неглубокий.
- Артефакты с glob-путями не переносятся; после каждого `dotnet test` — `scripts/ci-check-trx.sh` (выполнено > 0, упавших 0).
- Публикация образа — `crane` в alpine; NuGet — прямой `PUT` (`scripts/gitflic-nuget-push.sh`, `dotnet nuget push` даёт 404);
  PyPI — через `.pypirc` без `--skip-existing`; AssemblyVersion .NET не больше 65535 (время коммита только в PackageVersion).
- GitFlic сам не удаляет просроченные артефакты — их убирает удаление старых конвейеров (задание `cleanup`).
- Координатор выдаёт агенту примерно одно задание в минуту: статус «Ожидает выполнения» между заданиями — норма.

## Текущая задача: подчинённые клиенты и вход по ключу (в коде не начата)

Постановка — [`docs/task-managed-clients.md`](docs/task-managed-clients.md) (от 30.09.2026, закрывает РС-16 проекта 1c-import).
Код ещё не менялся; ниже — что уже выяснено и план. Выполнять по порядку, после каждого этапа — сборка и тесты.

### Что выяснено в коде (OpenIddict 7.7.1)

- **`private_key_jwt` поддерживается из коробки:** у приложения есть `OpenIddictApplicationDescriptor.JsonWebKeySet`
  (колонка `JsonWebKeySet` в таблице приложений уже есть в миграциях), сервер сам извлекает и проверяет `client_assertion`
  (обработчики `ValidateClientAssertion`, `…Audience`, `…Issuer`, `…WellknownClaims`), discovery публикует методы через
  `AttachClientAuthenticationMethods`. Confidential-клиенту достаточно JWKS без секрета — проверить тестом.
- **Не делает сам OpenIddict** (дописать): ограничение алгоритма ES256 (отклонять `none`, HS*, RSA, другую кривую),
  срок `exp − iat ≤ 5 мин`, одноразовый `jti` для всех узлов, публикация `token_endpoint_auth_signing_alg_values_supported: ES256`,
  подробная причина отказа в аудите (OpenIddict отдаёт общее «client assertion is invalid»).
- **DPoP (этап 2) в OpenIddict 7.7.1 нет** (в XML-документации пакетов упоминаний нет) — отложить и записать в ЧТЗ.
- Token Exchange уже есть (`AuthorizationController.Exchange`, ветка `IsTokenExchangeGrantType`): токен с `sub` = пользователь,
  `act.sub` = клиент-обменщик; для App API — scope `tsl-auth-app` (resource `tsl-auth-app`).
- Флаги приложения хранятся в `Properties` OpenIddict (`tsl_system`, `tsl_self_management`, `tsl_self_registration`) —
  по тому же образцу добавить `tsl_managed_clients` (политика JSON), `tsl_owner`, `tsl_disabled`.
- Отзыв токенов клиента — `SessionService.RevokeByClientAsync`; сроки токена приложения — `TokenLifetimeService.SetForAppAsync`
  (не больше глобальных); роли сервисной учётной записи — `AccessService.SetAssignmentsAsync(SubjectType.Client, …)`;
  проверка права пользователя по БД — `AccessService.HasPermissionAsync` (как в `AdminPermissionHandler`).
- Аудит ошибок токен-эндпоинта — `TokenErrorAuditHandler` (`Infrastructure/AuditHooks.cs`); метрики — `TslAuthMetrics`;
  лимиты — `SecurityMiddleware` (политики RateLimiter); неактивность пользователей — `TokenPruningService` + `UserService.DisableInactiveAsync`.
- Миграции EF — две ветки: `Data/Migrations/Sqlite` и `Data/Migrations/Postgres`
  (`dotnet tool restore`, затем `dotnet ef migrations add … --context SqliteAuthDbContext` и `PostgresAuthDbContext`).
- Интеграционные тесты: `AuthScenarios<TFixture>` запускаются на SQLite и PostgreSQL; `fx.Start()` — второй узел на той же БД
  (для общего кэша `jti`); помощники `TestApi` (`TokenAsync`, `AdminAsync`, `PostJsonAsync`, `Unique`, `NewPassword`).

### План

1. **Модель.** Свойства приложения: `tsl_managed_clients` — политика `{prefix, roles[], grantTypes: ["client_credentials"],
   authMethods: ["private_key_jwt" | "client_secret"], maxClients, accessTokenLifetime (мин, по умолчанию 5), requireDelegation (true),
   managePermission ("agents.manage"), inactiveDays (0 — выкл.)}`; у подчинённого `tsl_owner`, у любого приложения `tsl_disabled`.
   Новая таблица `ClientAssertionJti` (Jti PK, ClientId, ExpiresAt) + миграции SQLite и PostgreSQL; очистка просроченных — в `TokenPruningService`.
2. **`ManagedClientService`** (Services): политика (пишет только админ); создание подчинённого — префикс, `[a-z0-9-]`, длина ≤ 64,
   генерация суффикса, лимит `maxClients`, роли только из белого списка своего приложения, JWKS (только EC P-256,
   `kid` = отпечаток RFC 7638, до 2 ключей) или секрет, если политика разрешает; дескриптор: confidential, только
   `client_credentials`, scope только владельца, без redirect URI; срок токена из политики. Список, карточка (отпечатки ключей,
   последний выданный токен — по таблице токенов), смена ключей, disable/enable, новый секрет, удаление с отзывом токенов.
   Чужой или не подчинённый клиент — всегда 404.
3. **Защита от обхода:** `ApplicationService.UpdateAsync` и Admin API `service-roles` для подчинённых — только отключение/удаление
   и роли из белого списка владельца; `tsl-auth-admin`, `tsl-auth-app` и чужие приложения — 400 во всех API.
4. **App API `/api/app/clients*`** (отдельная группа и политика): GET — сервисный токен владельца или делегированный;
   изменения — только делегированный токен (`sub` = пользователь, `act.sub` = владелец, `aud` содержит `tsl-auth-app`),
   пользователь активен и имеет `managePermission` в матрице владельца (проверка по БД на каждый запрос), иначе 403;
   `requireDelegation=false` разрешает сервисный токен (тестовые стенды). Лимит 30 изменений/мин на владельца (RateLimiter).
5. **Вход по ключу:** обработчик OpenIddict на этапе аутентификации клиента после встроенных проверок assertion:
   `alg == ES256`, `exp − iat ≤ 300 с`, `jti` одноразовый через `ClientAssertionJti` (вставка по уникальному ключу — общая для узлов);
   отказ — `invalid_client` без подробностей, причина — в аудит (Warning) и метрику `tsl_auth.client_assertion.rejected{reason}`.
   Обработчик discovery добавляет `token_endpoint_auth_signing_alg_values_supported: ["ES256"]`; проверить, что
   `token_endpoint_auth_methods_supported` содержит `private_key_jwt`.
6. **Отключение клиента:** в `AuthorizationController` (token и authorize) отключённый клиент получает `invalid_client`;
   при отключении — `RevokeByClientAsync` (introspection старых токенов → `active=false`); вебхуки `application.disabled`
   и `application.enabled`, в `application.deleted` добавить `owner`. Доступно админу и владельцу.
7. **Предел по client_id на токен-эндпоинте** при ошибках входа (счётчик отказов из `TokenErrorAuditHandler`, блокировка на минуту).
8. **Аудит:** каждое действие с подчинённым — кто (`sub`), через кого (`act.sub`), что, клиент, отпечаток ключа;
   `ClientId` записи = владелец, чтобы запись была видна в `/api/app/audit`. Метрика — число подчинённых по владельцам (gauge в снимке).
9. **Admin API и админка:** `GET/PUT /api/admin/applications/{id}/managed-clients-policy`, `GET …/{id}/managed-clients`,
   `POST …/{id}/disable` и `…/enable`; в `ApplicationDto` — `Owner`, `Disabled`, `ManagedClients`. Страница Apps/Edit — блок политики
   и список подчинённых с кнопками «Отключить / Включить / Удалить»; Apps/Index — владелец и статус.
10. **Этап 2:** неактивность подчинённых (`inactiveDays`) → автоотключение с событием, как у пользователей. DPoP отложен (см. выше).
11. **Тесты (полная пирамида, SQLite и PostgreSQL):** юнит — политика и проверка assertion (подпись, `aud`, `exp`, повтор `jti`,
    `alg=none`, HS256 с открытым ключом как секретом, ключ другой кривой); интеграционные — все сценарии раздела 4 постановки,
    включая два узла и общий `jti`; нагрузка k6 — 200 подчинённых, токен каждому раз в 5 минут (сжатый сценарий);
    UI Playwright — владелец и подчинённые в админке, отключение; контрактные тесты SDK — вход по `private_key_jwt`.
12. **SDK:** в `TokenClient` .NET и Go — `private_key_jwt` (ES256, `jti`, `exp` = +60 с, `aud` = token endpoint); описать
    в `docs/client-contract.md`; остальные SDK — по возможности тем же контрактом.
13. **Документы:** `docs/integration.md` (подчинённые клиенты, `private_key_jwt`, делегирование), `docs/security.md`,
    `docs/tz.md` (+ Word), `docs/configuration.md`, `docs/client-contract.md`, этот файл.
14. **Выпуск:** `sdk/VERSION` → `1.5`, тег `v1.5.0` на `main` в GitFlic; сообщить версию образа и отличия от постановки
    (раздел 5 постановки), в том числе что DPoP отложен.

## Открытые темы

- Интеграция с Active Directory (LDAP-вход и синхронизация, затем Kerberos/SPNEGO) — обсуждалась как вопрос, не начата;
  отладка на Samba AD DC в Docker, прозрачный вход проверять на машине Windows в домене.
- Кластер, стенд мониторинга, OpenBao и секреты из файла настроек в конвейер не входят — проверяются вручную
  `tests/resilience/run-*.ps1` перед релизом.
