# Контракт клиентских библиотек (SDK)

Один документ для всех пяти SDK (`sdk/dotnet`, `sdk/node`, `sdk/go`, `sdk/python`, `sdk/java`): что именно проверяет
клиент, в каком порядке, какие ошибки возвращает и как читает права. Библиотеки на разных языках обязаны вести себя
**одинаково** — это проверяют контрактные тесты (`tests/sdk-contract`) против живого контейнера TSL Auth. Расхождение
с контрактом — дефект SDK, а не «особенность языка».

Обзор библиотек, установка и примеры — в [`docs/sdk.md`](sdk.md); формат токена — в [`integration.md`](integration.md#4-формат-токена-и-авторизация-в-api).

## 1. Конфигурация

Все SDK читают одни и те же переменные окружения (явные параметры конструктора имеют приоритет):

| Переменная | Обязательна | По умолчанию | Назначение |
|---|---|---|---|
| `TSL_AUTH_ISSUER` | да | — | Адрес сервиса, как в `iss` токена, например `https://auth.corp/` |
| `TSL_AUTH_AUDIENCE` | для API | — | `client_id` этого API: токен принимается, только если `aud` его содержит |
| `TSL_AUTH_CLIENT_ID` | для клиента токенов | — | `client_id` приложения (client_credentials, exchange, refresh, introspection) |
| `TSL_AUTH_CLIENT_SECRET` | для confidential-клиента | — | Секрет приложения |
| `TSL_AUTH_CLIENT_KEY_PEM` / `TSL_AUTH_CLIENT_KEY_FILE` | для входа по ключу (.NET, Go) | — | Закрытый ключ EC P-256 в PEM (строкой или файлом): вместо секрета клиент подписывает assertion `private_key_jwt` |
| `TSL_AUTH_CLIENT_KEY_ID` | нет | отпечаток RFC 7638 | `kid` ключа в заголовке assertion |
| `TSL_AUTH_JWKS_URI` | нет | из discovery | Прямой адрес JWKS (стенды без discovery, тесты) |
| `TSL_AUTH_CLOCK_SKEW_SECONDS` | нет | `30` | Допуск на расхождение часов при проверке `exp`/`nbf` |
| `TSL_AUTH_JWKS_TTL_SECONDS` | нет | `600` | Срок кэша ключей |
| `TSL_AUTH_JWKS_MIN_REFRESH_SECONDS` | нет | `10` | Не чаще этого перечитывать JWKS по неизвестному `kid` |
| `TSL_AUTH_INTROSPECT` | нет | `false` | После локальной проверки спрашивать `/connect/introspect` (мгновенный отзыв) |
| `TSL_AUTH_HTTP_TIMEOUT_SECONDS` | нет | `10` | Таймаут HTTP-запросов к сервису |

Discovery: `GET {issuer}/.well-known/openid-configuration` → `jwks_uri`, `token_endpoint`, `introspection_endpoint`,
`revocation_endpoint`, `authorization_endpoint`, `end_session_endpoint`. Ответ discovery кэшируется на срок `JWKS_TTL`.
Сравнение `iss` и `issuer` — после удаления завершающего `/` (`https://auth.corp` ≡ `https://auth.corp/`).

Подключение к своему стеку — одной строкой (см. таблицу в `docs/sdk.md`): SDK сам берёт настройки из окружения,
находит ключи через discovery и добавляет middleware/фильтр/dependency, который кладёт principal в контекст запроса.

## 2. Проверка access-токена (resource server)

Порядок строго такой; первая неудача завершает проверку с указанным кодом:

| № | Проверка | Код ошибки |
|---|---|---|
| 1 | Токен передан в `Authorization: Bearer <jwt>` (регистр слова `Bearer` не важен), не пуст | `missing` |
| 2 | Три части, разделённые `.`; заголовок и payload — JSON в base64url | `malformed` |
| 3 | `alg` заголовка равен `RS256` (иные, включая `none` и `HS256`, отвергаются до любых обращений к ключам) | `unsupported_alg` |
| 4 | В заголовке есть `kid` | `malformed` |
| 5 | Ключ с таким `kid` найден в кэше JWKS (см. §3) | `unknown_key` |
| 6 | Подпись RSASSA-PKCS1-v1_5 / SHA-256 верна | `bad_signature` |
| 7 | `iss` совпадает с настроенным issuer | `bad_issuer` |
| 8 | `exp` есть и `now ≤ exp + skew`; если есть `nbf` — `now ≥ nbf − skew` | `expired` / `not_yet_valid` |
| 9 | `aud` (строка или массив) содержит `TSL_AUTH_AUDIENCE` | `bad_audience` |
| 10 | При `TSL_AUTH_INTROSPECT=true`: `POST introspection_endpoint` с `client_id`/`client_secret` API вернул `active: true` | `revoked` (`active: false`), `introspection_unavailable` (сеть/5xx) |

Подпись проверяется **до** чтения claims (шаги 7–9): содержимое неподписанного токена не интерпретируется.
`typ` заголовка не проверяется (сервис ставит `at+jwt`). Время берётся из инжектируемых «часов»: у каждого
SDK есть способ подменить `now` (нужно тестам и не только).

Результат успешной проверки — **principal** (§4). Результат неудачи — ошибка с полем `code` из таблицы и
человекочитаемым описанием; текст описания не является частью контракта, код — является.

## 3. Кэш ключей (JWKS)

- Ключи загружаются лениво при первой проверке и хранятся `JWKS_TTL` секунд; по истечении — перечитываются при
  следующей проверке (старый набор используется, если перечитать не удалось; тогда ошибка сети не роняет проверку).
- Неизвестный `kid` → немедленное перечитывание JWKS (ротация ключей на сервере), но не чаще
  `JWKS_MIN_REFRESH` секунд: поток мусорных токенов со случайными `kid` не должен превращаться в DoS на `/.well-known/jwks`.
  Если после перечитывания `kid` по-прежнему нет — `unknown_key`.
- Одновременные проверки не делают параллельных загрузок: перечитывание выполняется один раз, остальные ждут (single-flight).
- Принимаются только ключи `kty=RSA` с `use` отсутствующим или `sig`; ключи с некорректными `n`/`e` пропускаются
  (не превращаются в «пустой» ключ), остальной набор используется.

## 4. Principal и чтение прав

Из claims строится объект с одинаковым составом во всех SDK (имена в стиле языка):

| Поле | Источник | Примечание |
|---|---|---|
| `subject` | `sub` | id пользователя или `client_id` сервиса |
| `subjectType` | `subject_type` | `user` / `client` |
| `username` | `preferred_username` | у сервисных токенов отсутствует |
| `name`, `email` | `name`, `email` | по scope |
| `roles` | `role` | только роли **этого** API: значения `"<audience>:<role>"` с обрезанным префиксом |
| `permissions` | `permissions` | только разрешения этого API, с обрезанным префиксом `"<audience>:"` |
| `allRoles`, `allPermissions` | `role`, `permissions` | как в токене, с префиксами (для API-шлюзов) |
| `scopes` | `scope` | строка через пробел → список |
| `amr` | `amr` | список; `isMfa = amr содержит "mfa"` |
| `actor` | `act` | цепочка token exchange: `{sub, act?}`; `null`, если токена обмена нет |
| `expiresAt` | `exp` | момент истечения |
| `claims` | весь payload | сырые claims для всего остального |

Правила чтения:

- Claim-список (`role`, `permissions`, `aud`, `amr`) может прийти **строкой** (одно значение) или **массивом** — оба
  варианта нормализуются в список. Отсутствующий claim — пустой список.
- `hasPermission("orders.read")` ⇔ `permissions` (уже без префикса) содержит значение; `hasRole(...)` аналогично.
  Полная форма (`"orders-api:orders.read"`) в этих методах **не** принимается — иначе приложения начнут смешивать формы.
- `resource_access` не используется для авторизации (дублирует `role`/`permissions`); доступен через `claims`.

## 5. Авторизация в middleware

Каждый SDK даёт защиту маршрута с одной и той же семантикой:

| Требование | Проверка | Отказ |
|---|---|---|
| аутентификация | §2 | `401` |
| `permission = "x"` | `hasPermission("x")` | `403`, код `insufficient_permissions` |
| `anyPermission = [...]` | хотя бы одно | `403`, `insufficient_permissions` |
| `role = "r"` | `hasRole("r")` | `403`, `insufficient_role` |
| `mfa = true` | `isMfa` | `403`, `mfa_required` |
| `subjectType = "user"` | `subjectType` | `403`, `subject_type_not_allowed` |

Формат ответов (RFC 6750):

- `401`: заголовок `WWW-Authenticate: Bearer realm="tsl-auth", error="invalid_token", error_description="<код §2>"`;
  тело `{"error":"invalid_token","error_description":"<код §2>"}`. Для отсутствующего токена `error_description` = `missing`.
- `403`: заголовок `WWW-Authenticate: Bearer realm="tsl-auth", error="insufficient_permissions", error_description="<audience>:<permission>"`
  (для роли — `insufficient_role`, для MFA — `mfa_required`); тело `{"error":"<код>","error_description":"<что требовалось>"}`.
- Тело — `application/json; charset=utf-8`. Ошибки проверки **не** содержат ничего из токена, кроме кода.
- Principal кладётся в контекст запроса (`HttpContext.User` / `req.auth` / `context.Value` / `request.state.auth` /
  атрибут запроса `tslauth.principal`), чтобы обработчик мог читать права.

## 6. Клиент токенов

Один класс `TokenClient` (имя в стиле языка) с методами; все обращаются к `token_endpoint` из discovery
формой `application/x-www-form-urlencoded`, `client_id` всегда в теле, `client_secret` — если задан.

| Метод | grant_type | Параметры |
|---|---|---|
| `clientCredentials(scopes)` | `client_credentials` | `scope` |
| `exchange(subjectToken, scopes)` | `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `scope` |
| `connectionToken(token)` | `urn:tsl:grant-type:pat` | `token` — токен подключения (`tslpat_…`), который пользователь выписал этому сервису-роботу; в ответе JWT пользователя с `act.sub` = `client_id` робота, без refresh-токена ([integration.md](integration.md#сервис-робот-вместо-пользователя-токен-подключения)) |
| `refresh(refreshToken, scopes?)` | `refresh_token` | `refresh_token` |
| `password(username, password, scopes)` | `password` | только серверные приложения |
| `authorizationCode(code, redirectUri, codeVerifier)` | `authorization_code` | PKCE обязателен |
| `introspect(token)` | — | `POST introspection_endpoint`, `token` |
| `revoke(token)` | — | `POST revocation_endpoint`, `token`; успех — `200` |

**Вход по ключу (`private_key_jwt`, RFC 7523; реализовано в .NET и Go).** Если секрет не задан, а задан
`TSL_AUTH_CLIENT_KEY_PEM`/`_FILE`, каждый запрос к token/introspection/revocation endpoint вместо `client_secret` несёт
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` и `client_assertion` — JWS ES256:
заголовок `{"alg":"ES256","typ":"client-authentication+jwt","kid":<отпечаток RFC 7638 или TSL_AUTH_CLIENT_KEY_ID>}`,
payload `iss = sub = client_id`, `aud` = issuer из discovery (с завершающим «/»), случайный `jti` (новый на каждый запрос), `iat`/`nbf` = сейчас,
`exp = iat + 60 с`. Помощники: `ClientKeys.GeneratePrivateKeyPem()`, `ClientKeys.PublicJwks(pem)`, `ClientKeys.KeyId(pem)`
(.NET); `tslauth.GenerateClientKeyPEM()`, `tslauth.PublicJWKS(key)`, `tslauth.KeyID(key)` (Go) — открытый JWK передаётся
владельцу для регистрации подчинённого клиента (`POST /api/app/clients`, см. `integration.md`, §11). Остальные SDK
(Node.js, Python, Java) входят секретом; вход по ключу в них — по мере необходимости тем же контрактом.

Ответ — `TokenSet`: `accessToken`, `refreshToken?`, `idToken?`, `expiresAt` (вычислен из `expires_in` в момент
получения), `scope`, `tokenType`. Ошибка (`4xx` с JSON `error`) — исключение `TokenError` с полями `error`,
`errorDescription`, `status`; сетевые ошибки и `5xx` — то же исключение с `error = "unavailable"`.

Правила:

- **Ротация refresh.** Ответ на `refresh` содержит новый `refresh_token`; SDK обязан вернуть его вызывающему, а
  встроенные хранилища (браузерный клиент, кэш сервисного токена) — заменить старый новым немедленно. Повторное
  использование старого refresh-токена допускается сервером лишь в окне повтора (30 с по умолчанию) и не должно
  использоваться как «запас».
- **Кэш сервисного токена.** `clientCredentials` с одинаковым `scope` кэшируется до `expiresAt − 30 с`; параллельные
  вызовы при протухшем кэше делают один запрос (single-flight). Ошибка запроса кэш не портит.
- **Токен подключения.** `connectionToken` кэшируется по значению токена до `expiresAt − 30 с` тем же механизмом
  (single-flight, ошибка кэш не портит): робот вызывает его перед каждым запросом к API, не нагружая TSL Auth.
  Константа grant — `ConnectionTokenGrantType` (.NET, Go), `CONNECTION_TOKEN_GRANT` (Python, Node.js, Java).
- **Exchange** не кэшируется (токен привязан к пользователю); вызывающий отвечает за его срок.
- Никакие секреты и токены не пишутся в журналы SDK.

## 7. Браузерный клиент (`@tsl/auth-client/browser`)

- `login()` — authorization code + PKCE S256: `code_verifier` (43–128 символов base64url) и `state` (≥16 байт) создаются
  `crypto.getRandomValues`, кладутся в `sessionStorage`, затем redirect на `authorization_endpoint`.
- `handleCallback()` — проверяет `state` (несовпадение — ошибка `state_mismatch`, обмен не выполняется), удаляет
  `pkce` из хранилища **до** обмена (одноразовость), убирает `code`/`state` из адресной строки (`history.replaceState`),
  обменивает код на токены.
- `getAccessToken()` — возвращает токен из памяти; если истекает менее чем через 30 с и есть refresh-токен —
  обновляет (single-flight) и сохраняет новую пару (ротация §6); при отказе refresh очищает сессию и возвращает `null`.
- Токены хранятся в `sessionStorage` (очищаются при закрытии вкладки) — не в cookie и не в `localStorage`.
- `logout()` — очищает хранилище и ведёт на `end_session_endpoint` с `id_token_hint` и `post_logout_redirect_uri`.
- `fetch(url, init)` — обёртка, добавляющая `Authorization: Bearer` (с автообновлением).

## 8. Контрактные тесты

`tests/sdk-contract/` — общий генератор и запуск:

1. `make-vectors.py` (stdlib) через Admin API создаёт приложение-API `sdk-contract-api` (разрешения `orders.read`,
   `orders.write`; роли `viewer` → read, `operator` → read+write), клиент `sdk-contract-client` (confidential,
   `password`, `refresh_token`, `client_credentials`, `token_exchange`; scope `sdk-contract-api`), пользователей
   `sdk-operator` (operator) и `sdk-viewer` (viewer), владельца подчинённых клиентов `sdk-contract-owner` (самоуправление,
   роль `uploader`, политика: префикс `sdk-agent-`, вход по ключу и секрету, `requireDelegation=false`), сервис-робот
   `sdk-contract-robot` (confidential, поток `connection_token`) и токен подключения к нему: `sdk-operator` выписывает
   его на все свои приложения через вход и форму «Мои токены» (как в браузере; прежние токены пользователя
   отзываются), получает токены и пишет `vectors.json`:

   ```json
   { "issuer": "...", "audience": "sdk-contract-api", "jwksUri": "...",
     "client": { "id": "sdk-contract-client", "secret": "..." },
     "managedOwner": { "id": "sdk-contract-owner", "secret": "...", "prefix": "sdk-agent-", "role": "uploader" },
     "robot": { "id": "sdk-contract-robot", "secret": "...", "connectionToken": "tslpat_..." },
     "users": { "operator": { "username": "sdk-operator", "password": "..." }, "viewer": { ... } },
     "cases": [ { "name": "ok_user", "token": "...", "expect": "ok" },
                { "name": "alg_none", "token": "...", "expect": "unsupported_alg" }, ... ] }
   ```

2. Каждый SDK читает `vectors.json` (`SDK_CONTRACT_VECTORS`, по умолчанию `../../tests/sdk-contract/vectors.json`)
   и для каждого случая ожидает **ровно** тот код, что в `expect`; для `ok_*` — ещё и поля principal (§4):

   | Случай | Ожидание |
   |---|---|
   | `ok_user` | `ok`; `subjectType=user`, `username=sdk-operator`, `permissions=[orders.read, orders.write]`, `roles=[operator]` |
   | `ok_viewer` | `ok`; `permissions=[orders.read]`; `hasPermission("orders.write")=false` |
   | `ok_client` | `ok`; `subjectType=client`, `subject=sdk-contract-client`, `username` отсутствует |
   | `ok_exchanged` | `ok`; `actor.sub=sdk-contract-client` |
   | `wrong_audience` | `bad_audience` (токен client_credentials без scope этого API) |
   | `tampered_payload` | `bad_signature` (изменён `permissions`) |
   | `tampered_issuer` | `bad_signature` (изменён `iss` — подпись проверяется раньше) |
   | `alg_none` | `unsupported_alg` |
   | `alg_hs256` | `unsupported_alg` (подписан HMAC с открытым ключом как секретом) |
   | `unknown_kid` | `unknown_key` |
   | `no_kid` | `malformed` |
   | `two_parts`, `garbage`, `empty` | `malformed` (`empty` в middleware — `missing`) |
   | `expired` | `expired` — тот же `ok_user`, но часы SDK переведены на `exp + 60 с` |
   | `not_yet_valid` | `not_yet_valid` — часы переведены на `iat − 120 с` (только если в токене есть `nbf`; иначе случай пропускается) |
   | `bad_issuer` | `bad_issuer` — SDK настроен на issuer `https://other.example/` и `jwksUri` из vectors |

3. Живые сценарии (каждый SDK, против того же контейнера):
   - `refresh_rotation`: `password` → `refresh` → новый `refresh_token` отличается от старого и работает повторно;
     после `revoke(refresh)` новый `refresh` — `TokenError.error = invalid_grant`.
   - `introspection_revoked`: `TSL_AUTH_INTROSPECT=true`; access-токен проходит; после `revoke(accessToken)` — `revoked`.
   - `client_credentials_cache`: два вызова подряд возвращают один и тот же токен; после подмены часов на `exp` — новый.
   - `jwks_rotation`: заглушка JWKS в тесте сначала отдаёт пустой набор, затем настоящий: первая проверка — `unknown_key`,
     вторая (после `JWKS_MIN_REFRESH`) — `ok`; счётчик обращений к заглушке подтверждает лимит частоты.
   - `private_key_jwt` (.NET, Go): SDK генерирует ключ P-256, сервисным токеном `managedOwner` регистрирует подчинённого
     (`POST /api/app/clients` с открытым JWK), получает токен без секрета — в нём роль `sdk-contract-owner:uploader`;
     клиент с тем же `client_id`, но другим ключом получает `invalid_client`; подчинённый удаляется.
   - `connection_token_robot`: робот (`robot.id`/`secret`) вызывает `connectionToken(robot.connectionToken)` — повторный
     вызов возвращает тот же `TokenSet` (кэш), refresh-токена нет; JWT проходит проверку: `subjectType=user`,
     `username=sdk-operator`, `actor.sub=sdk-contract-robot`, разрешения `orders.read`, `orders.write`
     (`expected.robot`); обычный клиент без потока `connection_token` получает `unauthorized_client`.
   - `middleware`: HTTP-сервер SDK: без токена `401`+`missing`; `ok_viewer` на маршрут с `orders.write` — `403`
     `insufficient_permissions`; `ok_user` — `200` и тело с `username`; заголовок `WWW-Authenticate` по §5.

4. Запуск: `tests/sdk-contract/run.ps1` поднимает стенд (`docker compose up -d --build`, `seed` не нужен),
   генерирует vectors, запускает тесты всех пяти SDK и гасит стенд. В CI — workflow `sdk.yml` на каждый push.

## 9. Версии и совместимость

- Версия SDK = версия сервиса (`vX.Y.Z` репозитория); пакеты публикуются тем же тегом, что и образ.
- Состав principal и коды ошибок могут только расширяться в MINOR; удаление/переименование — MAJOR (см. `release-policy.md`).
- SDK совместим с сервисом той же MAJOR-версии; новые claims сервиса SDK игнорирует, но отдаёт в `claims`.
