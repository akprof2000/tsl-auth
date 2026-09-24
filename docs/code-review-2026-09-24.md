# TSL Auth — полная ревизия кода

Ветка `claude/admiring-ptolemy-c4puoa` (HEAD `521076d`). Ревизия статическая: `dotnet` в контейнере нет, сборка и тесты не запускались. Каждое замечание проверено по исходникам; ссылки — `файл:строка` относительно корня репозитория (для `src/TslAuth/…` префикс опущен).

## Общая оценка

Проект заметно выше среднего уровня для self-hosted auth-сервера: PKCE обязателен глобально и на клиента, refresh-токены ссылочные с ротацией и окном повтора, права пересчитываются из БД при каждой выдаче, API-политики привязаны к bearer-схеме (cookie админки на `/api/*` не работает → нет CSRF на API), PAT — SHA-256 от 256-битного секрета, поля и ключи шифруются AES-GCM мастер-ключом с blind-index, CSP строгий без inline-скриптов, `Html.Raw` в представлениях отсутствует, open redirect закрыт `Url.IsLocalUrl`, SQL-инъекций в raw-SQL нет, снимки схем SQLite и PostgreSQL идентичны, языковые пакеты симметричны (132/132 ключа), образ distroless/non-root с cosign-подписью и SBOM. Комментарии объясняют «почему». Тестов три уровня плюс нагрузка и отказоустойчивость.

Критичных дефектов (обход аутентификации, утечка секретов) не найдено. Проблемы группируются в пять тем:

1. **Зависимость от заголовка `Host`** при пустом `Auth:Issuer` — ссылки сброса пароля/приглашений и `iss` подделываются.
2. **Различия SQLite ↔ PostgreSQL, которые тесты на SQLite не ловят**: `DateTime.Kind`, длины столбцов, регистр PK.
3. **Аудит и уведомления**: валидационные ошибки API пишутся как 500 и порождают `security.alert`; SSE-пульс падает; общий `DbContext` с `WebhookService` ломает «уведомления не мешают операции».
4. **Пробелы в политике паролей/сессий**: refresh не проверяет `MustChangePassword`, `/Account/*` доступны с временным паролем, refresh продлевается бесконечно.
5. **Покрытие тестами**: основной поток authorization code + PKCE не покрыт интеграционными тестами вообще, только еженедельными UI-тестами.

---

## Высокий приоритет

### H1. Ссылки сброса пароля/приглашений и `iss` строятся из `Host` запроса при пустом Issuer
`Services/AccountLinks.cs:84-88`, `appsettings.json:10` (`AllowedHosts: "*"`), `:23` (`Issuer: ""`), `Infrastructure/ServiceSetup.cs:144-145`.
Классический Host-header poisoning: `POST /Account/ForgotPassword` с `Login=<жертва>` и `Host: evil.example` → жертва получает письмо с валидным reset-токеном, ведущим на чужой домен → захват аккаунта. Discovery-документ и `iss` в токенах тоже следуют за `Host`. Compose задаёт `AUTH_ISSUER`, но bare-metal-развёртывание по README уязвимо.
**Фикс:** fail-fast на старте, если `Issuer` пуст вне Development; убрать fallback на `Host` в `BuildUrl`; выставлять `HostFilteringOptions.AllowedHosts` из Issuer.

### H2. Дубликаты email допускаются, поиск по email — `SingleOrDefault` → анонимно провоцируемый 500 и «сквоттинг» логина
`Infrastructure/ServiceSetup.cs:86` (`RequireUniqueEmail = false`), `Services/UserService.cs:84`, саморегистрация `Pages/Account/Register.cshtml.cs` → `AccessRequestService.RegisterAsync` не проверяет занятость email.
Атакующий регистрируется с email администратора → вход, «забыли пароль» и password grant по email для админа падают 500 (`InvalidOperationException` из `FindByEmailAsync`). Второй вектор: логин, равный email жертвы — `FindByNameAsync` срабатывает первым, reset-письмо уходит атакующему.
**Фикс:** `RequireUniqueEmail = true` + проверка существующих данных; запретить `@` в логинах (или требовать совпадения с собственным email); проверка занятости email при саморегистрации.

### H3. SSE-поток `/api/admin/events/stream` падает на первом же пульсе
`Api/EventsApi.cs:122` — `new EventDto(…, default)`; `Services/WebhookService.cs:35` — `JsonElement Data`. `default(JsonElement)` при сериализации бросает `InvalidOperationException` (`CheckValidInstance`). Через ~15 с тишины стрим обрывается, клиент бесконечно переподключается. Тестов на стрим нет.
**Фикс:** `JsonElement? Data` и `null` для ping (или `JsonSerializer.SerializeToElement(new {})`); интеграционный тест, держащий стрим > 15 с.

### H4. Любая 4xx-ошибка API аудируется как 500 и порождает `security.alert`
`Api/AdminApi.cs:41-42`, `AppApi.cs:38-39`, `EventsApi.cs:52-53` (`HandleErrors` добавлен первым → он внешний), `Infrastructure/AuditHooks.cs:42` (`status = error is not null ? 500 : …`), `:47` (Warning при ≥ 500), `Services/AuditService.cs:149-155` (Warning → немедленный fan-out `security.alert`).
`AdminException` 400/404/409 доходит до `ApiAuditFilter` как исключение → запись «500, success=false, Warning» → алерт всем подпискам и SSE. Журнал безопасности искажён, лента алертов засоряется.
**Фикс:** `ex is AdminException a ? a.StatusCode : 500` в фильтре, либо поменять порядок фильтров (аудит снаружи).

### H5. Фильтр журнала по датам ломает Admin/App API на PostgreSQL
`Api/AdminApi.cs:46-54`, `Api/AppApi.cs:43-45`, `Services/AuditService.cs:172-173`. `DateTime?` из query без зоны имеет `Kind=Unspecified`; Npgsql отказывается писать его в `timestamptz` → 500 на `GET /api/admin/audit?from=…`, `/audit.csv`, `/api/app/audit`. Razor-страница делает `ToUniversalTime()` (`Pages/Admin/Audit/Index.cshtml.cs:28`), API — нет. На SQLite (где идут тесты) работает.
**Фикс:** нормализовать `Kind` в одной точке (`AuditQuery`), тест на Postgres.

### H6. Два языковых пакета, различающихся регистром кода, кладут весь сервис
`Localization/LocalizationService.cs:96-97, 114` (регистрозависимый поиск/PK), `EnsureLoadedAsync` строит словарь с `OrdinalIgnoreCase` → `ArgumentException`; `LanguageMiddleware` вызывает его на каждом запросе до маршрутизации → 500 везде, включая `DELETE /languages/{culture}`. Одна опечатка администратора (`PUT /languages/RU`) = полный отказ всех узлов.
**Фикс:** канонизировать код при сохранении/удалении; `TryAdd`/`GroupBy` при загрузке; при ошибке загрузки не ронять middleware, оставлять прежний кэш.

### H7. Узлы кластера доступны напрямую при `TrustForwardedHeaders=true`
`docker-compose.ha.yml:33, 68, 74, 80` (порты 8081–8083 наружу), `Infrastructure/ServiceSetup.cs:239-246` (`KnownProxies/KnownIPNetworks.Clear()` — доверие любому источнику; комментарий требует недоступности напрямую), `docs/deployment.md:299` узаконивает.
Запрос на `:8081` с `X-Forwarded-For` обходит rate-limit по IP и подделывает IP в аудите/PAT; `X-Forwarded-Proto: https` обходит `RequireHttps`.
**Фикс:** убрать `ports` у `auth1..3` (или `127.0.0.1:8081:8080`); добавить опцию `Auth:KnownNetworks` вместо очистки списков; поправить документацию.

### H8. Authorization code + PKCE не покрыт интеграционными тестами
`tests/TslAuth.IntegrationTests/AuthScenarios.cs` — ни одного запроса к `/connect/authorize` (единственное упоминание — `:528`, внутри returnUrl теста логина). Не проверяются: отказ без `code_challenge`, неверный `code_verifier`, чужой `redirect_uri`, повтор кода, `prompt=none`, `MustChangePassword`-редирект, `/connect/logout`, `/connect/introspect`, `/connect/revoke`, `form_post` + CSP-хеш. UI-тесты (`e2e.yml`) идут только по cron раз в неделю и PR не гейтят.
**Фикс:** сценарий на `WebApplicationFactory` (login → authorize → code → token с verifier + негативные варианты); introspect/revoke; `e2e.yml` на push в `main` до публикации `latest`.

---

## Средний приоритет

### Безопасность / политики
- **M1. Refresh-грант не проверяет `MustChangePassword` и истечение пароля** — `Controllers/AuthorizationController.cs:227-231` (только `IsActive`), тогда как authorize, password grant, token exchange и PAT блокируют. Refresh-токены, выданные до выдачи временного пароля, продлеваются бесконечно. Также `RecordLoginAsync(mustChangePassword: true)` не отзывает сессии.
- **M2. `/connect/introspect` и `/connect/revoke` без rate limiter и без аудита `invalid_client`** — `ServiceSetup.cs:114-119` (без passthrough), лимитер только на `Exchange` (`AuthorizationController.cs:139`); `TokenErrorAuditHandler` (`AuditHooks.cs:106-128`) только для token. Перебор client_secret не ограничен.
- **M3. `/Account/Tokens`, `/Account/Messenger`, `/Account/RequestAccess` доступны с временным паролем** — `ServiceSetup.cs:221-232` (`MustChangePasswordFilter` только на `/Admin`). Знающий временный пароль может привязать мессенджер — альтернативный канал сброса пароля.
- **M4. Перечисление пользователей по времени ответа** — `UserService.cs:226-240` синхронно шлёт SMTP только для существующих; `Login.cshtml.cs:63-72`, `AuthorizationController.cs:149-156` не выполняют PBKDF2 для неизвестного логина. Фикс: фоновая очередь писем, фиктивный `VerifyHashedPassword`.
- **M5. `MasterKeyResolver` молча генерирует новый ключ при отсутствии файла (SQLite)** — `Security/MasterKeyResolver.cs:30-40`. Не примонтированный том с ключом при существующей БД → все зашифрованные поля и ключи подписи нечитаемы, а новый ключ перезаписывает путь. Генерировать только если БД ещё нет.
- **M6. SSRF через подписки вебхуков** — `Api/EventsApi.cs:63-67` (только схема http/s), `Infrastructure/WebhookDispatcher.cs:98` (следует редиректам, буферизует тело). Роль `notifier` может направить события (логины, email, алерты) на `169.254.169.254`/localhost; код/текст ответа виден в `/deliveries`. Фикс: отклонять loopback/link-local/private, `AllowAutoRedirect=false`, `ResponseHeadersRead`.
- **M7. App API `/users/link` — оракул существования и раскрытие профиля любому self-managed приложению** — `Services/AppSelfService.cs:95-103, 204-208`: линкует любого пользователя системы (включая администраторов) и отдаёт email/флаги. Отдавать минимум, логировать как Warning, рассмотреть подтверждение.
- **M8. `AppSelfService.UpdateUserAsync`** — `:106-118`: при смене email `EmailConfirmed` не сбрасывается (`email_verified=true` для непроверенного адреса, ср. `UserService.UpdateAsync:126`); `input.UserName.Trim()` без null-проверки → 500; `Password`/`MustChangePassword` в DTO молча игнорируются.
- **M9. `SetRoleRequestable`/`UpdateRole` не защищены для системного приложения** — `Services/AccessService.cs:102, 112-119` (`GuardSystem` только в Delete*), UI лишь прячет кнопки (`Pages/Admin/Apps/Matrix.cshtml:80-96`). POST делает роль `administrator` «запрашиваемой».
- **M10. `/connect/logout` по GET без `id_token_hint` — logout-CSRF** — `AuthorizationController.cs:337-345`; `docs/security.md:15` утверждает «выход только POST» (верно лишь для Razor-страницы). Показывать подтверждение при GET без валидного `id_token_hint`.

### Корректность / данные
- **M11. `WebhookService.PublishAsync` глотает ошибку, но оставляет сущности в трекере** — `Services/WebhookService.cs:63-82`; общий scoped `DbContext` с `AccessRequestService.cs:119-124`, `AppSelfService.cs:81-87`, `UserService.cs:114-116`. Следующий `SaveChangesAsync` вызывающего кода повторяет вставку и падает наружу. Публиковать в отдельном scope (как `AuditService`) или отсоединять сущности в `catch`.
- **M12. Удаление приложения не снимает владение пользователями** — `Services/ApplicationService.cs:186-199`: `AppUser.CreatedByClientId`/`ExternalIdentity.LinkedByClientId` остаются; повторная регистрация того же `client_id` наследует управление всеми пользователями.
- **M13. Неатомарные составные операции** — `AccessService.cs:69-87` (`AddRoleAsync`: роль сохранена, затем 404 на разрешении → 409 при повторе), `AccessRequestService.cs:189-196` (`DecideAsync`: Approved, затем `AssignAsync` падает — не переоткрыть), `BotService.cs:73-77`, `ApplicationService.cs:193-197` (4 шага без транзакции). `SetMatrixAsync` показывает, что транзакции уже применяются.
- **M14. App API `/users` без пагинации + N+1** — `AppSelfService.cs:54-61, 204-208`; мягче то же в `UserService.ListAsync:72-76` (≤500 × `GetAssignmentsAsync`).
- **M15. Диспетчер вебхуков: head-of-line blocking** — `WebhookDispatcher.cs:50-65`: ≤20 доставок строго последовательно с таймаутом 10 с — одна зависшая подписка тормозит остальные до 200 с.
- **M16. Bot API: лимит сбросов на best-effort аудите** — `BotService.cs:122-131, 146-148`: счётчик читается из `AuditLog`, запись после сброса и может быть проглочена (`AuditService.cs:142-161`); каждый сброс даёт два `security.alert`; каждый неверный `/link` — синхронный fan-out.

### UI
- **M17. Форма «Оформление входа» затирает все цвета в `#000000`** — `Pages/Admin/Apps/Branding.cshtml:50-53` (`<input type="color">` всегда отправляет значение, пустое → `#000000`), `Branding.cshtml.cs:59-60` передаёт как есть. Любое сохранение (даже только заголовка) делает страницу входа чёрной. Фикс: чекбокс «задать цвет» или текстовое поле с `pattern`.
- **M18. Обработчики удаления игнорируют ошибку и показывают «успешно»** — `Pages/Admin/Languages/Index.cshtml.cs:69-74`, `Pages/Admin/Webhooks/Index.cshtml.cs:61-66` (`TryAsync` без проверки результата, затем `Flash` + redirect).
- **M19. `TempData["Flash"]` хранит то ключ, то текст** — `ChangePassword.cshtml.cs:61-63`, `Tokens.cshtml.cs:52`, `Messenger.cshtml.cs:40` пишут ключи; `_Layout.cshtml:78-81` в админской ветке печатает без `L[]`. После смены временного пароля админ видит «change.done».
- **M20. Страница ошибки зависит от полного макета и БД** — `Pages/Error.cshtml`: `_Layout` ходит в `BrandingService`/`LanguagesAsync`; при падении БД страница ошибки тоже падает; нет `[IgnoreAntiforgeryToken]`, `no-store`; текст только русский, ссылка на `/Admin`.
- **M21. При ошибке валидации введённое затирается из БД** — `Branding.cshtml.cs:63`, `Settings/Index.cshtml.cs:61-68`.
- **M22. Hardcoded русские строки в `wwwroot/js/site.js:18-26`** («Показать/Скрыть пароль» в `aria-label`).
- **M23. Доступность: `<label>` без `for`, поля только с placeholder** — `Apps/Edit.cshtml:48,62,66,75,96`, `Apps/Matrix.cshtml:32-47`, `Audit/Index.cshtml:20-44`, `Sessions/Index.cshtml:12`, `Users/Index.cshtml:15`, `Languages/Index.cshtml:30`, `Requests/Index.cshtml:36`, `Settings/Index.cshtml:106-108`, `Webhooks/Index.cshtml:55`.

### Деплой / CI / документация
- **M24. PFX через `TLS_KEY_PATH=` не работает** — `docker-compose.https.yml:19` (`${TLS_KEY_PATH:-…}` подставляет default и при пустом значении), рецепт `docs/deployment.md:366` даёт `KeyPath=/certs/tls.key` → Kestrel не стартует. Фикс: `${TLS_KEY_PATH-…}` или отдельный overlay без `KeyPath`.
- **M25. Пароль PostgreSQL по умолчанию `tsl_auth_dev`** — `docker-compose.ha.yml:29,54`; `ENCRYPTION_MASTER_KEY` защищён `:?`, пароль БД — нет.
- **M26. Docker secrets задокументированы, но не поддержаны** — `docs/configuration.md:157`, `docs/security.md:100`, `docs/deployment.md:434` vs ни одного `secrets:` в compose; для `Bootstrap__AdminPassword`/`AdminApiClientSecret` нет `*File`-варианта.
- **M27. nginx обрывает long-polling раньше `wait`** — `deploy/nginx.conf:38` (`proxy_read_timeout 30s`), `Api/EventsApi.cs:35` (`wait ≤ 60`), `docs/integration.md:200` рекомендует `wait=30` → 504 и повтор на следующих узлах через `proxy_next_upstream`. `nginx-tls.conf:49` — 60 с, та же граница.
- **M28. `Auth__AccessTokenLifetimeMinutes` и др. не действуют** — `Services/TokenLifetimeService.cs:26-43` при каждой выдаче перекрывает `OpenIddictServerOptions` значениями из `RuntimeSettings.Tokens` (дефолты в `SettingsService.cs:454-460`); `docs/configuration.md:167` обещает обратное.
- **M29. Actions по тегам, `dockle:latest` с docker.sock** — `.github/workflows/ci.yml:27-200`, `e2e.yml:26-34,86`, `ci.yml:145`. Пайплайн ставит keyless-подпись — компрометация тега action = подпись чужого образа. Pin по SHA.
- **M30. Сканируется и подписывается не тот же артефакт** — `ci.yml:118-124` (`tsl-auth:scan`, `load: true`) и `:157-165` (повторная сборка с `push: true`); подпись на digest непросканированного образа. Собирать один раз по digest, сканировать его, затем `imagetools create` + `cosign sign`.
- **M31. Unit-тест подписи вебхука не проверяет значение** — `tests/TslAuth.UnitTests/SecurityTests.cs:162-163` сравнивает только `.Length`. Ожидаемое: `sha256=aa9e2e3575f5d7098b6caccd790888c36d5fdb63342a73bada2d6a51747a8494` для `("secret", "{\"a\":1}")`.
- **M32. Не тестируются**: rate limiting (в фикстуре 100000/мин → код 429 не срабатывает), окно повтора refresh (в тестах `Leeway=0`, дефолт 30), refresh с чужим `client_id` / после смены пароля, детализация admin-ролей (`auditor` GET vs POST, `notifier` видит только свои подписки), PAT (истёкший, `enabled=false`, `maxTokensPerUser`, снятые роли), сквозная доставка вебхука с `X-TSL-Signature`, CORS, заголовки безопасности, приглашение/сброс по ссылке, `bot maxPerUserPerHour`.
- **M33. Python-пример раздаёт App API анонимам** — `samples/python-app/app.py:160-175` (список логинов/email без `session`), `:247-255` (`/users/create`, `/users/delete` без проверки сессии). Референсный пример из `docs/integration.md`.

---

## Низкий приоритет

### Ядро/безопасность
- L1. Cookie входа без `SecurePolicy=Always` при `RequireHttps` — `ServiceSetup.cs:98-106`.
- L2. `AcceptInviteAsync`/`CompletePasswordResetAsync` не проверяют `IsActive` — `UserService.cs:197-213, 246-261`.
- L3. `PasswordHistory` не обрезается и не чистится; запись добавляется до `UpdateUserAsync` — `Security/PasswordPolicyServices.cs:67-78`.
- L4. Refresh-токены продлеваются бесконечно (нет абсолютного срока сессии) — `Services/TokenLifetimeService.cs:37-41`.
- L5. Аудит пишет сырое поле «логин» при неудачном входе (пользователи вводят туда пароли) — `Login.cshtml.cs:68-69`, `AuthorizationController.cs:153-154`.
- L6. `FieldCrypto.Decrypt` принимает значения без префикса как открытый текст — `Security/FieldCrypto.cs:51`.
- L7. Dev-конфигурация с известным секретом `admin-cli`/`dev-admin-cli-secret` с ролью administrator — `appsettings.Development.json:5-8` (из образа удаляется — хорошо).
- L8. Сгенерированный пароль администратора в логах — `StartupInitializer.cs:256-258`.
- L9. `SessionService.RevokeAsync` — два `ExecuteUpdate` без транзакции — `:71-79`.
- L10. PAT-аудитории не перепроверяются при использовании — `PatService.cs:95-112`, `TokenPrincipalFactory.cs:81-92`; `docs/integration.md:165` обещает «текущие права».
- L11. Сообщение «locked» раскрывает существование аккаунта — `Login.cshtml.cs:76-84`, `AuthorizationController.cs:170-172`.
- L12. `AuditService` Info-очередь `FullMode.Wait` — при заторе >50k входы виснут — `AuditService.cs:60-64, 137`; при остановке дописывается ≤1000 событий — `:79-82, 92-103`.
- L13. `SettingsService.ApplyLockout` мутирует singleton `IdentityOptions` — `:184-188, 207, 229`.
- L14. Мёртвый код: обработка `AspNet.Identity.SecurityStamp` — `TokenPrincipalFactory.cs:134-135`, `AuthorizationController.cs:292`; дубли `Guid? uid` — `:236, 271`; дубли `HandleErrors`/`Caller` в четырёх Api-файлах.
- L15. Advisory-lock на пулируемом соединении: `pg_advisory_unlock_all` уходит только перед следующей командой — другие узлы могут ждать до `Connection Idle Lifetime` — `StartupInitializer.cs:97-105`; `Pooling=false` как в `:121`.
- L16. `PostgresMigration.cs:175-189` читает таблицы целиком в память (большой `AuditLog`).

### Сервисы/данные
- L17. Отсутствие проверок длины → `DbUpdateException` только на PostgreSQL: `UserService.cs:98-100,124-128`, `AccessRequestService.cs:192` (`DecisionComment`), `WebhookService.cs:176-179`, `LocalizationService.cs:97` (`Culture` PK `varchar(20)`), `AccessService.cs:51,79`.
- L18. Несогласованный актор: `AdminApi.Caller` → `user:{логин}`, `AuditService.ResolveActor` → `user:{id}`; владение подпиской (`EventsApi.cs:61,140`) теряется после переименования.
- L19. `POST /webhooks/test` шлёт всем подпискам, а не только своим — `EventsApi.cs:87-91`.
- L20. `ExternalId` триммится только в `LinkAsync` — `BotService.cs:60, 87, 99, 115`.
- L21. Вычисляемые свойства настроек сериализуются в БД и в `GET /settings` — `SettingsService.cs:29-32, 47, 222` (`[JsonIgnore]`).
- L22. `string.Format` с текстом из пакета БД — непарная `{` → `FormatException` на странице — `Texts.cs:22`.
- L23. `uri.ToString()` разэкранирует URL вебхука — `WebhookService.cs:177` (`AbsoluteUri`).
- L24. Дубли pending-заявок при параллельной отправке — `AccessRequestService.cs:136-153` (нет уникального индекса).
- L25. `GetPropertiesAsync` ×3 на DTO — `ApplicationService.cs:307-309`.

### UI
- L26. `style-src 'unsafe-inline'` из-за inline-стилей; `LoginBranding.GetAsync` не ревалидирует JSON из БД — `SecurityMiddleware.cs:80-83`, `_Layout.cshtml:35-45`, `LoginBranding.cs:46-53`.
- L27. Ссылка «Запросить доступ» копирует весь query string (в т.ч. `uid`/`token`) — `_Layout.cshtml:106`.
- L28. `AdminException` и ошибки биндинга показываются только по-русски на английском UI — `Register.cshtml.cs:59-62`, `RequestAccess.cshtml.cs:48-51`, `Tokens.cshtml.cs:40-43`, `AcceptInvite.cshtml.cs:46-49`; политика паролей уже сделана через ключи — распространить.
- L29. Fallback после входа — `/Admin` для всех → обычный пользователь попадает на AccessDenied — `Login.cshtml.cs:141`, `ChangePassword.cshtml.cs:63`.
- L30. `Index.cshtml:3-5` — редирект из тела представления.
- L31. Даты фильтра аудита в зоне сервера, без пометки UTC — `Audit/Index.cshtml.cs:27-29`.
- L32. `OnGetTemplate(from)` принимает произвольную культуру — `Languages/Index.cshtml.cs:43-45`.
- L33. Дублирование разметки: таблицы PAT/сессий, чекбоксы ролей, выражение статуса, `ToLocalTime().ToString("dd.MM.yyyy HH:mm")` ~20 раз.
- L34. `/docs`, `/docs/api`, `/openapi/v1.json` публичны — `Pages/Docs/Index.cshtml:1`, `ApiDocs.cs:70-73` (осознанно, но для внешнего контура закрыть).
- L35. Секреты в cookie-TempData; `ResolveFromReturnUrlAsync` ×3 на запрос страницы входа.

### Деплой/CI/доки/примеры
- L36. `HEALTHCHECK` каждые 10 с поднимает полный CLR внутри `mem_limit: 512m` — `Dockerfile:47-48`; нет `--mount=type=cache` для NuGet — `:19`.
- L37. nginx: `add_header X-Upstream` раскрывает внутренние IP, нет `server_tokens off` в HTTP-конфиге, двойной HSTS — `deploy/nginx.conf:39`, `nginx-tls.conf:36` + `Program.cs:112-113`.
- L38. PostgreSQL без `pids_limit`/`mem_limit`/`cap_drop` — `docker-compose.ha.yml:46-62`.
- L39. `.dockerignore` не исключает `samples`, `docs`, `.github`, `deploy`.
- L40. `postgres`/`nginx`/`mermaid-cli`/`k6` по тегу, а `docs/security.md:22,40` и `README.md:20` утверждают «по digest».
- L41. `.env.example:14` — `AUTH_REQUIRE_HTTPS=false` как шаблон.
- L42. `cleanup.yml:26-34` ежедневно стирает gha build-кэш и всю историю запусков.
- L43. `prune-releases.yml` обслуживает несуществующий процесс релизов; плюс файл намеренно в CRLF (`172277d`), что конфликтует с `*.yml text eol=lf` в `.gitattributes` — git показывает фантомный диф на каждом `status`. Нормализовать в LF либо добавить исключение в атрибуты.
- L44. cosign подписывает один digest по нескольку раз — `ci.yml:178-181`; нет `timeout-minutes`/`concurrency` в `ci.yml`; `dotnet list package --vulnerable` только для `src/TslAuth`; Dependabot не видит `samples/dotnet-mvc`; демо-приложения в `e2e.yml:47-56` стартуют без перенаправления вывода.
- L45. Документация: `docs/integration.md:4` «пять стеков» (четыре); имена тома/сети `auth_*` вместо `tsl-auth_*` (`docs/deployment.md:286,330,343,353`); `.github/dockerhub/README.md:402-407` без упоминания `RequireHttps`/`TrustForwardedHeaders`.
- L46. Примеры: `samples/dotnet-mvc/Program.cs:398,414` — `/refresh`, `/logout` по GET; `samples/node-spa/public/app.js:237-246` — `pkce` не удаляется из `sessionStorage` после обмена (повторный callback с тем же state пройдёт); `samples/go-api/main.go:98-100` — ошибки base64 при разборе JWK игнорируются.
- L47. Хрупкие тесты: `AuthScenarios.cs:450-451` (`Task.Delay(300)` перед long-poll), проверки по русским фрагментам текста (`:191,208,484`, `UiScenarios.cs:24,64,97`), конфигурация через `Environment.SetEnvironmentVariable` (`AuthFixture.cs:56`), `UiScenarios.cs:246-251` создаёт PAT без удаления (упрётся в `maxTokensPerUser=20`), нагрузочный тест бесконечно логинит одного `alice` (`tests/load/auth-load.js:20,64-70`).
- L48. `TslAuth.csproj` — нет `Deterministic`/`ContinuousIntegrationBuild`, `Version` не из тега; `scripts/export-images.ps1:5-6` `[switch]$WithPostgres = $true`; `scripts/validate-docs.ps1:79` `chmod 777`.

---

## Рекомендуемый порядок работ

**До следующего релиза (1–2 дня):** H1, H2, H3, H4, H5, H6, M17, M24, M31 — все точечные, без рефакторинга.

**Ближайшая итерация:** H7 + M25/M26 (compose), M1, M2, M3, M9, M11, M12, M8, M27, M28, M33; H8 + M32 — тесты authorize/PKCE и запуск интеграционных тестов на PostgreSQL в CI (закрывает класс проблем H5/L17).

**Планово:** M4–M7, M10, M13–M16, M18–M23, M29/M30, L-серия.

## Что проверено и в порядке
PKCE (глобально + requirement на клиента); token exchange проверяет `aud ∋ client_id`; rate limiter на `/connect/token` срабатывает до проверки секрета; API-политики только bearer; CORS без `Allow-Credentials` с `Vary: Origin`; Data Protection в БД под мастер-ключом; PAT-хранение; `Url.IsLocalUrl` на всех returnUrl; antiforgery на всех POST; `Referrer-Policy: no-referrer`; нет `Html.Raw`; авторизация каждой API-группы и всех Admin-страниц через `AdminPageModel`; роли из форм сверяются с белым списком; `[BindProperty]` только на скалярах; секреты не текут через DTO; raw-SQL без инъекций; снимки схем идентичны; локализация 132/132; все `Section__Key`, CLI-команды, endpoint'ы и счётчики тестов в документации совпадают с кодом; `seed-demo.ps1` идемпотентен; Dockerfile в остальном образцовый.
