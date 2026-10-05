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
| `scripts/` | демо-стенд (`demo.cmd`/`demo.ps1` — Windows, `demo.sh` — Linux), экспорт/импорт образов, проверка документации, `build-tz-docx.py` (Word-версия ЧТЗ), утилиты GitFlic (см. ниже) |
| `gitflic-ci.yaml` | единственный рабочий конвейер CI/CD |

## Команды

```powershell
dotnet build TslAuth.sln -c Release -warnaserror
dotnet test tests/TslAuth.UnitTests
dotnet test tests/TslAuth.IntegrationTests          # нужен запущенный Docker (Docker Desktop сам не стартует после перезагрузки)
docker compose up -d --build                         # стенд на http://localhost:8080
./samples/seed-demo.ps1                              # демо-приложения, матрицы, alice/bob (секреты confidential-клиентов перевыпускает)
scripts\demo.cmd  |  ./scripts/demo.ps1  |  scripts/demo.sh   # демо-стенд целиком: образ GitFlic (или -Build/--build), seed, 4 приложения; stop / clean
# demo.ps1: каждое демо-приложение — в своём окне «demo <имя>» с живым stdout (журналы только в stdout); в CI/тестах
# (tests/e2e/start-demos.ps1 без -Console) stdout сохраняется в tests/artifacts/demo, окна скрыты
$env:UI_HEADED=1; dotnet test tests/TslAuth.UiTests  # UI-тесты с видимым браузером (скриншоты — tests/artifacts/ui)
./tests/sdk-contract/run.ps1                         # стенд + контрактные тесты пяти SDK
pwsh scripts/validate-docs.ps1 -SkipMermaid          # ссылки, якоря, таблицы в README и docs/*.md
./tests/load/run-managed-load.ps1                    # k6: 200 подчинённых клиентов по private_key_jwt (стенд запущен)
python scripts/build-tz-docx.py --version 2.6 --date 05.10.2026   # Word-версия ЧТЗ из docs/tz.md (python-docx); версию поднимать при каждом изменении tz.md
python scripts/build-tz-docx.py --src docs/task-active-directory.md --out docs/TZ-active-directory.docx --version 1.1 --date 03.10.2026 --status "постановка для согласования, реализация не начата"
```

После изменения схем Mermaid в документации — `scripts/render-diagrams.ps1` (картинки в `docs/diagrams`).

## Правила работы

- **Имена — с префиксом `tsl-`** (Алексей, 05.10.2026, правило в `../CLAUDE.md`): образ `tsl-auth`, контейнер `tsl-auth`
  (на общем стенде `../Money` — тоже `tsl-auth`; оба стенда сразу не поднимать — имя занято).
- Compose-проект `tsl-auth` (HA — `tsl-auth-ha`), OpenBao — контейнер `tsl-auth-openbao`; пример docflow-demo — проект `tsl-auth-docflow-demo`,
  контейнеры и образы `tsl-auth-docflow-auth`, `tsl-auth-docflow-api`, `tsl-auth-docflow-bot`, `tsl-auth-docflow-openbao`.
- **Коммиты сразу в `main`**, без веток и pull request'ов. В конце сообщения коммита — строка соавторства.
- **Полная пирамида тестов** для любого изменения/проекта: unit → интеграционные (SQLite и PostgreSQL) → нагрузка →
  отказоустойчивость → наблюдаемость → UI-автотесты. В отчёте указывать, какие уровни прогнаны.
- Документация и ЧТЗ меняются вместе с поведением; расхождение — дефект, блокирует релиз.
- **Каждый модуль с REST API** публикует документацию как TSL Auth: `/docs` — руководство, `/docs/api` — справочник Scalar,
  `/openapi/v1.json`; у каждого метода — подпись и нужное разрешение матрицы ([`docs/integration.md` §12](docs/integration.md#12-документация-rest-api-модуля-docs-и-docsapi)).
  .NET — `Scalar.AspNetCore` (образец `samples/docflow-demo/shared/ApiDocs.cs`); остальные — общие `guide.html`/`reference.html`
  из `samples/go-api/docs` (копии в node-spa и java-api должны совпадать — проверяет `validate-docs.ps1`), скрипт Scalar —
  с TSL Auth (`<issuer>docs/api/scalar.js`), не CDN.
- Демо используют опубликованный образ, а не сборку из исходников (кроме E2E-стенда в CI и `scripts/demo.* -Build`).
- Демо-приложения проверяются по `127.0.0.1`, а не `localhost`: Python-демо слушает только IPv4, а HttpClient PowerShell
  сначала пробует `::1` и ждёт таймаут.
- Локально после работы в Docker не оставлять ничего своего (решение пользователя 01.10.2026): стенд —
  `docker compose down -v` из корня репозитория, демо-приложения — остановить (порты 5101–5105, окна «demo …»), свои
  лишние образы (k6, trivy, mermaid, postgres тестов, промежуточные tsl-auth) и тома удалить. Образ выпуска
  `tsl-auth:latest` можно оставить — по нему стенд поднимается снова. На машине
  идут и другие проекты (1c-import, tsl-dev, tslmesh, openbao-config) — их контейнеры, тома и сборщики buildx не трогать:
  никаких `docker rm` по всем контейнерам, `docker volume prune -a` и `docker builder prune` по общему кэшу (30.09.2026 так
  были потеряны стенды 1c-import и tsl-dev). В реестре GitFlic — текущий выпуск (`X.Y.Z`, плавающие `X.Y`, `X`,
  `latest`) и последние сборки main; вручную после выпуска убрать и временные версии сборок:
  `KEEP=0 KEEP_RELEASES=1 KEEP_PIPELINES=1 CI_REGISTRY_IMAGE=registry.gitflic.ru/project/uklad/tsl-auth CI_PROJECT_PATH=uklad/tsl-auth sh scripts/gitflic-prune.sh`
  (с `GITFLIC_API_TOKEN` в окружении; сначала `DRY_RUN=1`).
- Место ограничено: артефакты CI живут до суток, в реестрах и релизах — не больше трёх версий.
- `*.docx` хранятся в **Git LFS** (`.gitattributes`): после клона — `git lfs install --local` и `git lfs pull`.
  Другие большие двоичные файлы — тоже через LFS, добавив шаблон. Обязательная настройка рабочей копии (проверено
  30.09.2026): у `origin` два push-URL, и без неё git-lfs шлёт объекты на **последний** (GitHub), а GitFlic остаётся
  с указателями без содержимого (404 при скачивании); проверку блокировок GitFlic отвергает (403):
  ```
  git config remote.origin.lfsurl https://gitflic.ru/project/uklad/tsl-auth.git/info/lfs
  git config remote.origin.lfspushurl https://gitflic.ru/project/uklad/tsl-auth.git/info/lfs
  git config lfs.https://gitflic.ru/project/uklad/tsl-auth.git/info/lfs.locksverify false
  ```
  На GitHub объекты переносит задание `mirror-github` (`git lfs push`), но `git push origin main` с рабочей станции
  GitHub **отклоняет** («pre-receive hook declined», объектов LFS нет), если коммит меняет `*.docx` — GitFlic при этом
  принимает. Поэтому при изменении `*.docx` перед push: `git lfs push https://github.com/akprof2000/tsl-auth.git main`
  (после push — то же и `git push github main`).
  Проверка — чистый клон GitFlic и `git lfs pull`: файлы полного размера, а не указатели по 130 байт.
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
Настройки проекта (название, описание, язык, темы): `PUT /project/uklad/tsl-auth/setting/change-setting` с JSON
`{title, description, language, topics}` (`PUT`/`PATCH` на `/project/…` — 405). С 04.10.2026: «Сервис идентификации и
доступа TSL Auth», язык C#, темы oauth2, openid-connect, jwt, authentication, authorization, dotnet, uklad.

### Агенты

- Два агента на сервере в Хельсинки `77.42.83.24`: `tsl-auth-hel-1`, `tsl-auth-hel-2`, теги `tsl-auth,tsl-auth-hel`.
  Compose в `~/gitflic-runner` (образ `registry.gitflic.ru/company/gitflic/runner:latest`, `PRIVILEGED=true`, `REG_URL` с явным `:443`).
- SSH: `ssh -p 443 alexey_kozlov@77.42.83.24`, ключ `C:\Projects\TSL\Key\id_ed25519` с парольной фразой —
  пользователь загружает его в ssh-agent Windows (`ssh-add`), подключаться через `ssh.exe` из PowerShell (Git Bash агент не видит).
- На сервере живут чужие сервисы (`uklad-gitflic-runner`, plaudio, youtrack, platform_dev) — их не трогать.
- Задания с docker:dind оставляют анонимные тома (до 100 ГБ в сутки): чистить висячие тома, в которых есть
  `overlay2`, `containers`, `image`. С 30.09.2026 это делает cron на сервере каждые 3 часа —
  `~/gitflic-runner/hel-cleanup.sh` (копия `scripts/hel-cleanup.sh`, журнал `~/gitflic-runner/hel-cleanup.log`): только
  анонимные висячие тома (пустые или dind) и образы без тега старше суток, именованные тома чужих сервисов не трогает.
  После своих заданий и выпусков — проверить `df -h /` и при нехватке запустить скрипт вручную; при изменении скрипта —
  заново `scp` на сервер (команды — в заголовке скрипта). Теги уже зарегистрированного агента меняются через API (`runner-tags`), а не `TAGS` в compose.
- `net-check-hel` в каждом конвейере проверяет, что с сервера качается слой из реестра GitFlic (раньше путь обрывался).
- **30.09.2026 путь снова оборвался**: `net-check-hel` — WARNING, `publish-image` (crane с сервера) падает на тайм-аутах
  PATCH blob. Выпуск 1.5.0 опубликован с рабочей станции: `docker login registry.gitflic.ru` (логин `GITFLIC_API_USER`,
  пароль `GITFLIC_TRANSPORT_TOKEN` из `C:\Projects\TSL\Key\gitflic-tokens.env`), `docker push` образа с тегами
  `sha-<sha>`, `MAJOR.MINOR.<unix-время коммита>`, `X.Y.Z`, `latest`; пакеты SDK — теми же командами, что в заданиях
  `publish-sdk-*` (`PKG_BASE=https://registry.gitflic.ru/project/uklad/tsl-auth/package/-`, `GITFLIC_PKG_USER/TOKEN`).
  Когда `net-check-hel` снова зелёный — публикация возвращается на агент (ничего менять не нужно).
  Так же опубликован 1.5.1 (30.09.2026): образ `1.5.1`/`latest` (digest `sha256:97640efb…`), пакеты SDK `1.5.1790790170`.
  **03.10.2026 путь снова работает**: в конвейере #73 `net-check-hel` зелёный, образ и пакеты опубликованы с агента.
- **Выпуск 1.6.0 (04.10.2026)**: тег `v1.6.0` на `9184fb4` (конвейер #73 зелёный), образ `1.6.0`/`1.6`/`1`/`latest`
  (digest `sha256:bd1d9594…`), пакеты SDK `1.6.0` (NuGet, npm, PyPI, Maven), релиз GitFlic
  https://gitflic.ru/project/uklad/tsl-auth/release/68ee3ce5-468e-4ad7-89a3-f49658af83f4 с четырьмя архивами.
  Теги выпуска — `scripts/gitflic-image-tag.sh sha-<коммит> X.Y.Z X.Y X` (копия манифеста через Registry API, без Docker);
  архив образа — `scripts/gitflic-image-archive.sh X.Y.Z <файл>` (из реестра, формат `docker save`): сам `docker save`
  в Docker Desktop (хранилище containerd) у образов, выгруженных `crane`, отдаёт пустой архив 8 КБ. npm: временную
  версию `X.Y.<время>` удалить до публикации `X.Y.Z`. Полная инструкция — `docs/gitflic-runners.html`.
- GitFlic **не создаёт конвейер на push тега** (`git push origin vX.Y.Z` — в списке конвейеров ничего), а
  `POST …/cicd/pipeline/start` с `{"ref":"vX.Y.Z"}` запускает обычный прогон `main`.
- **Релиз GitFlic вручную (как 1.5.1, образец — релиз openbao-config 1.0.0):** `POST /project/uklad/tsl-auth/release`
  с JSON `{title, tagName, description, isDraft, isPreRelease}` (другие имена полей — 500); файлы —
  `POST …/release/<id>/file`, multipart-поле `files` (текстовые файлы — 415, поэтому SHA-256 — в описании);
  удалить — `DELETE …/release/<id>`. Состав: `tsl-auth-image-X.Y.Z-linux-amd64.tar.gz` (`docker save | gzip`),
  `tsl-auth-sdk-X.Y.Z.tar.gz` (`scripts/build-sdk-packages.sh X.Y.Z`), `tsl-auth-deploy-X.Y.Z.tar.gz` (compose,
  `.env.example`, `deploy/`, демо- и импорт-скрипты), `tsl-auth-docs-X.Y.Z.zip`; образ с тегами `X.Y.Z`, `X.Y`, `X`,
  `latest`; пакеты SDK — версией `X.Y.Z` (временные `X.Y.<время>` удалить; npm не публикует «меньшую» версию, пока
  есть большая — сначала удалить её).
- **Очистка реестра (`scripts/gitflic-prune.sh`, задание `cleanup`) с 04.10.2026 различает виды версий**: плавающие
  `latest`/`X`/`X.Y` не трогает, выпусков `X.Y.Z` оставляет `KEEP_RELEASES` (1), временных `X.Y.<время>` и `sha-…` —
  `KEEP` (3). Удаление версии образа через API снимает только тег (манифест и другие теги остаются — проверено).
  Прежняя версия считала всё вместе, и прогоны main удалили теги выпуска `1.5.1` и `1.5`.
- На сервере агентов кончалось место (30.09.2026, `No space left on device` в integration/e2e): тома docker:dind —
  проверка `ssh.exe -p 443 alexey_kozlov@77.42.83.24 'df -h /; docker system df'`.

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
- `Infrastructure/ClientAuthHandlers.cs` — обработчики OpenIddict: `ClientAssertionPrecheckHandler` (до
  `ValidateClientAssertion`: `iat/nbf/exp` в секундах — иначе сама OpenIddict падает 500), `ClientAssertionPolicyHandler`
  (перед `ValidateClientId`; `jti` → `INSERT … ON CONFLICT DO NOTHING` в `ClientAssertionJtis`), `ClientAuthErrorHandler`
  (событие `ProcessErrorContext` для token/introspection/revocation: `invalid_token`/ID2171–2173 → `invalid_client`,
  счёт отказов), `ClientAssertionMetadataHandler` (discovery), `DisabledClientHandler` (token и authorize; отказ не
  считается), `ClientFailureLimiter` + `ClientFailureLimitHandler` (после `ValidateAuthentication`, ключ «client_id + IP»).
- Активность подчинённых — таблица `ClientActivities` (upsert в `AuthorizationController` при client_credentials через
  `ManagedClientService.RecordTokenIssuedAsync`); списки подчинённых — `ApplicationService.ReadManagedClientsAsync`
  (один запрос) + пакетные роли и активность. Отключение/удаление подчинённого пишет `managed_client.change` в журнал
  владельца внутри `ApplicationService` (любой путь: App API, Admin API, админка, обслуживание).
- `OwnerOf`/`AppSelfHandler`: клиентский токен с claim `act` (получен обменом) владельцем не считается.
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
- Встроенные проверки assertion отвечают `invalid_request` (ID2171/ID2172 — claim неверного формата / отсутствует) и
  `invalid_grant` (ID2173 — iss/sub ≠ client_id), подпись/aud/срок — `invalid_token`; `iat` в миллисекундах валит
  `MapInternalClaims` исключением (500). Assertion проверяется и на introspection/revocation; `client_id` OpenIddict
  выводит из `iss` assertion, если он не передан (в `Validate*RequestContext` после `ValidateAuthentication`).
- Ошибки конвейера правятся в `ProcessErrorContext` до `AttachErrorParameters` (порядок `int.MinValue + 100 000`).
- Через Bash-инструмент heredoc с python-кодом иногда обрывается («unexpected EOF») — патчи класть в файл `*.py` и запускать.

## Сервис-робот вместо пользователя (токен подключения, версия 1.6)

Задача пользователя 03.10.2026: сервис работает с правами пользователя по токену, который пользователь выписал ему сам.
Описание — `docs/integration.md` §6 «Сервис-робот вместо пользователя», ЧТЗ — Ф-5, контракт SDK — `client-contract.md` §6.

- Это PAT с привязкой к сервису: `PersonalAccessToken.ClientId` (робот) и `AllApplications` (права во всех приложениях
  пользователя по ролям на момент обмена); миграция `PatServiceTokens` (SQLite и PostgreSQL).
- Разрешение администратора — поток `connection_token` у confidential-приложения (`AppGrantTypes.ConnectionToken` =
  `urn:tsl:grant-type:pat`, тот же grant, что у `tsl-pat`; `AppGrantTypes.ShortName` — короткие имена для UI/API).
- Обмен — `AuthorizationController` (ветка `PatGrantType`): токен робота принимается только от его `client_id`
  (секрет проверяет OpenIddict), PAT для скриптов — только от `tsl-pat`; иначе `invalid_grant`. Клиент без потока
  `connection_token` получает от OpenIddict `unauthorized_client` раньше этой проверки. В JWT — `act.sub` = робот,
  `client_id` = робот, без refresh. При удалении приложения его токены отзываются (`ApplicationService.DeleteOneAsync`).
- Выпуск — `PatService.CreateAsync` (`ServiceClientsAsync` — роботы, которым можно выписать токен), страница
  `Pages/Account/Tokens` («Кто будет пользоваться токеном», «Все мои приложения»), `_PatTable` (пометки робота).
- SDK (все пять): `ConnectionTokenAsync` / `ConnectionToken` / `connection_token` / `connectionToken`, кэш по значению
  токена до `expiresAt − 30 с` общим механизмом с `client_credentials`.
- Тесты: интеграционные `RobotTokenScenarios.cs` (SQLite + PostgreSQL), UI `ConnectionToken_IssuedInUi_RobotActsAsUser`
  (Node API отвечает `calledVia` = робот), контрактные тесты SDK `connection_token_robot` (вектор `robot` в
  `make-vectors.py`: `sdk-operator` выписывает токен через вход и форму «Мои токены», как в браузере).

## Выпуск PAT по праву и самообслуживание (05.10.2026)

Просьба Алексея: токен для работы через API выписывает себе сам пользователь, но только после того, как администратор
назначит ему роль («Доступ по API» модуля «Пользователи» ERP, `tsl-users:api-tokens.issue`).

- `PatPolicy.RequiredPermission` («приложение:разрешение»; пусто — как раньше, без ограничения); проверка —
  `PatService.CanIssueAsync` в `CreateAsync` (любой путь: страница, API, админка), поле в `Admin/Settings`, страница
  `Account/Tokens` без права показывает пояснение вместо формы. Ф-31 ЧТЗ, `docs/integration.md` §6.
- `Api/AccountApi.cs` — `/api/account/tokens` (options, список, выпуск, отзыв своих) access-токеном пользователя
  (схема валидации OpenIddict, audience `tsl-auth-admin`, `subject_type=user`); токен подключения робота здесь не выпускается.
- Тесты: `tests/TslAuth.IntegrationTests/AccountTokenScenarios.cs` (SQLite + PostgreSQL).
- **Выпуск 1.7.0 (05.10.2026)**: тег `v1.7.0` на `392da87` (конвейер #76 зелёный), образ `1.7.0`/`1.7`/`1`/`latest`
  (digest `sha256:3a8c3b17…`, теги — `scripts/gitflic-image-tag.sh`). SDK не менялись (`sdk/VERSION` 1.6, пакеты 1.6.0);
  релиз GitFlic с архивами не публиковался.

## Документация в YouTrack (база знаний UKA)

- ЧТЗ TSL Auth опубликованы в базе знаний проекта **UKA** («Уклад - ERP Лавра», id проекта `0-1`), раздел
  04.09 «Информационная безопасность» (UKA-A-128):
  - **UKA-A-315** «04.09.01. ЧТЗ. Сервис идентификации и доступа TSL Auth» — основное ЧТЗ; вложения `TZ-tsl-auth.docx`,
    `auth-architecture.drawio`, картинки `auth-NN.png` (в тексте `![…](auth-02.png){width=100%}`), редакция 2.0;
  - **UKA-A-316** «04.09.01.01. Реестр уточнений и открытых вопросов» (В-1…);
  - **UKA-A-326** «04.09.01.02. ЧТЗ. Интеграция TSL Auth с Active Directory» (02.10.2026, из `docs/task-active-directory.md`:
    схема — вложение `ad-states.png`, Word — `TZ-active-directory.docx`, ссылки на репозиторий — адреса GitFlic);
  - **UKA-A-341** «04.09.01.03. ЧТЗ. Подчинённые клиенты и вход по ключу (private_key_jwt)» (03.10.2026, из
    `docs/task-managed-clients.md`, Word — `TZ-managed-clients.docx`; закрывает РС-16 импортера 1С).
  - Ссылки на них из смежных подразделов ТЗ: 04.09 (UKA-A-128) — на 315, 326, 341; 03.01 «Роли, полномочия и области
    доступа» (UKA-A-91) — на 315 (робот, Ф-5) и 326; реестр импортера 03.05.01.01 (UKA-A-310) — на 341.
- Доступ (YouTrack на сервере сборки, `youtrack-server` на `127.0.0.1:8082`): туннель
  `ssh.exe -p 443 -N -L 127.0.0.1:18082:127.0.0.1:8082 alexey_kozlov@77.42.83.24`, затем REST API
  `http://127.0.0.1:18082/api/...` с заголовком `Authorization: Bearer <YOU_TRACK_TOCKEN>` из
  `C:\Projects\TSL\Key\gitflic-tokens.env` (учётная запись Kozlov_Alex). Статьи: `GET /api/articles?query=project:UKA`,
  изменить — `POST /api/articles/<id>` с `{content}`, создать дочернюю — `POST /api/articles` с
  `{summary, content, project:{id:"0-1"}, parentArticle:{id}}`, вложение — `POST /api/articles/<id>/attachments` (multipart `file`).
- **Статьи YouTrack обновлять всегда, без напоминания** (Алексей, 03.10.2026): любое изменение ЧТЗ или постановки в
  репозитории (`docs/tz.md`, `docs/task-*.md`, их Word-версии) в той же работе переносится в YouTrack — UKA-A-315
  (основное ЧТЗ и `TZ-tsl-auth.docx`), UKA-A-316 (реестр вопросов), UKA-A-326 (ЧТЗ по AD и `TZ-active-directory.docx`);
  новый документ-постановка — новой дочерней статьёй UKA-A-315 (`04.09.01.NN. ЧТЗ. …`, Word — `docs/TZ-<тема>.docx` через
  `scripts/build-tz-docx.py --src`) **и ссылкой из каждого подраздела ТЗ, который он затрагивает** (04.09 — всегда;
  03.01 — роли и доступ; 03.05 — импорт; 04.04 — интеграция; 04.15 — аудит и т. п.), а сам список выше в этом файле —
  дописывается. Это постоянная обязанность: публиковать и дописывать при каждой новой постановке, не дожидаясь просьбы.
  Курируемый текст статьи сохранять: менять только
  затронутые места, Word-вложение заменять (`DELETE …/attachments/<id>`, затем загрузить заново), об изменении —
  пометка под строкой редакции. В отчёте указывать, какие статьи обновлены. Офлайн-экспорт базы знаний —
  `C:\Projects\TSL\UKA_KNOWLEDGE_BASE.md` (может отставать от YouTrack).

## Открытые темы

- Интеграция с Active Directory — постановка [`docs/task-active-directory.md`](docs/task-active-directory.md) (Ф-AD-1…16,
  этапы 1.7 вход и группы → 1.8 синхронизация → 1.9 Kerberos/SPNEGO; 1.6 — сервис-робот), реализация не начата; открытые вопросы — раздел 12
  (ручные роли для записей AD, заранее создаваемые записи, число доменов). Отладка на Samba AD DC в Docker, прозрачный
  вход проверять на машине Windows в домене. Word — `docs/TZ-active-directory.docx`; в YouTrack — UKA-A-326. Рабочая копия — Claude Doc
  https://claude.ai/code/artifact/d57b291b-8a8d-4801-8c23-f95e1a87f1c1; изменения переносить в репозиторий.
- Кластер, стенд мониторинга, OpenBao и секреты из файла настроек в конвейер не входят — проверяются вручную
  `tests/resilience/run-*.ps1` перед релизом.
