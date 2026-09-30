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
| `scripts/` | экспорт/импорт образов, проверка документации, `build-tz-docx.py` (Word-версия ЧТЗ), утилиты GitFlic (см. ниже) |
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
./tests/load/run-managed-load.ps1                    # k6: 200 подчинённых клиентов по private_key_jwt (стенд запущен)
python scripts/build-tz-docx.py --version 2.2 --date 30.09.2026   # Word-версия ЧТЗ из docs/tz.md (python-docx)
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
- Релиз: тег `vX.Y.Z` на `main` → конвейер по тегу → образ и пакеты в реестры GitFlic + релиз GitFlic
  (фактически на 30.09.2026 конвейер по тегу не запускается — см. ниже про публикацию с рабочей станции).
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
- **30.09.2026 путь снова оборвался**: `net-check-hel` — WARNING, `publish-image` (crane с сервера) падает на тайм-аутах
  PATCH blob. Выпуск 1.5.0 опубликован с рабочей станции: `docker login registry.gitflic.ru` (логин `GITFLIC_API_USER`,
  пароль `GITFLIC_TRANSPORT_TOKEN` из `C:\Projects\TSL\Key\gitflic-tokens.env`), `docker push` образа с тегами
  `sha-<sha>`, `MAJOR.MINOR.<unix-время коммита>`, `X.Y.Z`, `latest`; пакеты SDK — теми же командами, что в заданиях
  `publish-sdk-*` (`PKG_BASE=https://registry.gitflic.ru/project/uklad/tsl-auth/package/-`, `GITFLIC_PKG_USER/TOKEN`).
  Когда `net-check-hel` снова зелёный — публикация возвращается на агент (ничего менять не нужно).
- GitFlic **не создаёт конвейер на push тега** (`git push origin vX.Y.Z` — в списке конвейеров ничего), а
  `POST …/cicd/pipeline/start` с `{"ref":"vX.Y.Z"}` запускает обычный прогон `main`. Релиз GitFlic через
  `POST /project/uklad/tsl-auth/release` тоже не создаётся (500 на любые поля) — страницу релиза заводить в веб-интерфейсе.

### Особенности GitFlic (проверено)

- Имена заданий не должны совпадать с ключевыми словами (`image`, `release`, `services`), иначе файл даёт 0 заданий.
- Парсер YAML GitFlic отвергает строки `script`, где в кавычках есть `: ` или `%{…}` — такие команды выносить в `scripts/*.sh`.
- `$CI_PIPELINE_ID` — UUID, `CI_PROJECT_PATH` нет (путь брать из `CI_REGISTRY_IMAGE`), клон неглубокий.
- Артефакты с glob-путями не переносятся; после каждого `dotnet test` — `scripts/ci-check-trx.sh` (выполнено > 0, упавших 0).
- Публикация образа — `crane` в alpine; NuGet — прямой `PUT` (`scripts/gitflic-nuget-push.sh`, `dotnet nuget push` даёт 404);
  PyPI — через `.pypirc` без `--skip-existing`; AssemblyVersion .NET не больше 65535 (время коммита только в PackageVersion).
- GitFlic сам не удаляет просроченные артефакты — их убирает удаление старых конвейеров (задание `cleanup`).
- Координатор выдаёт агенту примерно одно задание в минуту: статус «Ожидает выполнения» между заданиями — норма.

## Подчинённые клиенты и вход по ключу (выполнено, версия 1.5.0)

Постановка — [`docs/task-managed-clients.md`](docs/task-managed-clients.md) (раздел 7 — итог и отличия); закрывает РС-16
проекта 1c-import. Описание для интеграторов — `docs/integration.md` §11, архитектура — `docs/architecture.md`
(«Подчинённые клиенты и вход по ключу»), ЧТЗ — Ф-28…Ф-30, Б-11, В-11.

### Где что в коде

- `Services/ManagedClientsPolicy.cs` — политика (`tsl_managed_clients`), разбор JWKS (`ManagedClientKeys`, только EC P-256,
  `kid` = отпечаток RFC 7638, ≤ 2 ключей), правила assertion (`ClientAssertionRules`: ES256, `exp − iat ≤ 5 мин`, `jti`).
- `Services/ManagedClientService.cs` — CRUD подчинённых (владелец из токена, чужой → 404), аудит `managed_client.change`
  с `ClientId` = владелец, предел неактивности (`DisableInactiveAsync`, вызывается из `TokenPruningService`).
- `Services/ApplicationService.cs` — свойства `tsl_owner`, `tsl_disabled`, `tsl_created_at`; `SetDisabledAsync`
  (отзыв токенов + вебхуки `application.disabled/enabled`), запрет `UpdateAsync`/`RegenerateSecretAsync` для подчинённых,
  каскадное удаление подчинённых вместе с владельцем, `ListManagedClientsAsync` (фильтр по JSON-колонке `Properties`).
- `Api/ManagedClientsApi.cs` — группа `/api/app/clients` с политикой `app-managed-clients` (`ManagedClientsHandler`:
  сервисный токен — чтение, делегированный `act.sub` = владелец + `managePermission` по БД — изменения) и фильтром
  лимита 30 изменений/мин на владельца.
- `Infrastructure/ClientAuthHandlers.cs` — обработчики OpenIddict: `ClientAssertionPolicyHandler` (перед `ValidateClientId`;
  `jti` → таблица `ClientAssertionJtis`), `ClientAssertionErrorNormalizer` (`invalid_token` → `invalid_client`),
  `ClientAssertionMetadataHandler` (discovery), `DisabledClientHandler` (token и authorize), `ClientFailureLimiter`
  + `ClientFailureLimitHandler` (блок `client_id` после `Security__ClientAuthFailuresPerMinute` отказов).
- Admin API: `…/managed-clients-policy` (GET/PUT/DELETE), `…/managed-clients`, `…/disable`, `…/enable`; `service-roles`
  проверяет белый список. Админка: `Pages/Admin/Apps/Edit` (политика, таблица подчинённых, отключение), `Index` (владелец/статус).
- SDK: .NET `ClientKeys` + `Internal/ClientAssertionSigner`, Go `clientkeys.go`; настройки `TSL_AUTH_CLIENT_KEY_PEM|FILE|ID`.
  Node/Python/Java входят секретом (не реализовано — «по возможности»).
- Тесты: `tests/TslAuth.UnitTests/ManagedClientsTests.cs`, `tests/TslAuth.IntegrationTests/ManagedClientScenarios.cs`
  (SQLite + PostgreSQL, `fx.Start(extra)` — узел с другими настройками), UI `Admin_ManagedClients_*`,
  контрактные тесты SDK (.NET `Private_key_jwt_managed_client`, Go `TestPrivateKeyJWTManagedClient`; вектор `managedOwner`
  в `make-vectors.py`), нагрузка `tests/load/run-managed-load.ps1` (k6, WebCrypto ES256, 200 подчинённых),
  сквозной сценарий «внешний сервис» `tests/e2e/external-service` (`go run .` при поднятом стенде; образец для 1c-import).

### Проверено на OpenIddict 7.7.1 (не очевидно из документации)

- Assertion принимается **только с заголовком `typ: client-authentication+jwt`**; без `typ` или с `typ: JWT` — «token is not
  of the expected type» (ID2089). Confidential-клиент с `JsonWebKeySet` и без секрета создаётся и входит нормально.
- `aud` assertion — только issuer в точности как в discovery (`http://localhost/`); адрес token endpoint отвергается
  («doesn't contain any valid audience»); отказ встроенной проверки `aud`/`exp` идёт как
  `invalid_token` — нормализуется в `invalid_client`. `invalid_client` OpenIddict отдаёт со статусом **401** (и на authorize).
- Порядок обработчиков: `ValidateClientAssertion` → `…WellknownClaims` → `…Issuer` → `…Audience` (устаревший класс, не
  ссылаться) → `ValidateClientId` → `ValidateClientType` → `ValidateClientSecret`; свой — `ValidateClientId.Order − 500`.
  Класс обработчиков authorize-эндпоинта называется `OpenIddictServerHandlers.Authentication` (не `Authorization`).
- `OpenIddictParameter` для массива строк — `new OpenIddictParameter(ImmutableArray.Create<string?>(…))`.
- Через Bash-инструмент heredoc с python-кодом иногда обрывается («unexpected EOF») — патчи класть в файл `*.py` и запускать.

## Открытые темы

- Интеграция с Active Directory (LDAP-вход и синхронизация, затем Kerberos/SPNEGO) — обсуждалась как вопрос, не начата;
  отладка на Samba AD DC в Docker, прозрачный вход проверять на машине Windows в домене.
- Кластер, стенд мониторинга, OpenBao и секреты из файла настроек в конвейер не входят — проверяются вручную
  `tests/resilience/run-*.ps1` перед релизом.
