# Задача: подчинённые клиенты и вход по ключу в tsl-auth (закрывает РС-16)

Исполнитель — Алексей (tsl-auth). После выпуска tsl-auth Claude переводит на новые функции 1c-import (раздел 6).
Составлено 30.09.2026 по коду tsl-auth `e9cf0f7` (OpenIddict 7.7.1) и 1c-import `4877693`.

## 1. Зачем

Сейчас (РС-16) Import API заводит клиентов агентов через **Admin API** tsl-auth клиентом с правом
`tsl-auth-admin:manage`. У этого ключа три проблемы:

1. **Слишком широкие права.** Утечка ключа из Import API = полный контроль над tsl-auth (любые приложения,
   пользователи, роли, настройки). Нарушен принцип наименьших привилегий и разделение технического
   администрирования и прикладных ролей (04.09 ТЗ «Уклад»).
2. **Общий секрет у агента.** Секрет клиента агента создаётся на сервере, передаётся по сети (пусть и зашифрованным
   ключом агента) и хранится в файле. Утечка файла = вход с любой машины.
3. **Блокировка только в Import API.** tsl-auth продолжает выдавать токены заблокированному агенту; в журнале tsl-auth
   не видно, какой человек одобрил агента.

## 2. Целевое решение (лучшие практики)

| Практика | Стандарт | Что даёт |
|---|---|---|
| Делегированное управление только своими клиентами вместо Admin API | идея RFC 7591/7592 (Dynamic Client Registration / Management), App API tsl-auth | ключ Import API не может ничего, кроме клиентов агентов с ролью `uploader` |
| Вход клиента по ключу, без секрета | `private_key_jwt`, RFC 7523, OIDC Core §9, ES256 | закрытый ключ не покидает машину агента, передавать и хранить на сервере нечего |
| Действие от имени человека | Token Exchange, RFC 8693 (`act`) — уже есть в tsl-auth | tsl-auth сам проверяет права оператора и пишет в аудит человека, а не сервис |
| Отключение клиента в tsl-auth | — | блокировка действует на выдачу токенов, а не только в Import API |
| Короткие токены и событие об отзыве | RFC 7009, вебхуки tsl-auth | отключённый агент теряет доступ за минуты во всех сервисах |
| Токен, привязанный к ключу (этап 2) | DPoP, RFC 9449 (или mTLS, RFC 8705) | украденный access-токен бесполезен без закрытого ключа |

## 3. Требования к tsl-auth

### 3.1. Подчинённые клиенты (managed clients) в App API

- Новый флаг приложения **«Подчинённые клиенты»** (свойство `tsl_managed_clients`, рядом с `tsl_self_management`)
  и **политика** к нему, задаётся только администратором tsl-auth (Admin API и админка), приложение само её менять
  не может:
  - `prefix` — обязательный префикс `client_id` (для import-api: `import-agent-`);
  - `roles` — белый список ролей **своего** приложения, которые можно выдавать (для import-api: `uploader`);
  - `grantTypes` — только `client_credentials` (другие типы, redirect URI, public-клиенты запрещены);
  - `authMethods` — `private_key_jwt` и/или `client_secret` (по умолчанию только `private_key_jwt`);
  - `maxClients` — предел числа подчинённых (для import-api: 200);
  - `accessTokenLifetime` — время жизни токена подчинённых (по умолчанию 5 минут).
- Владелец записывается в свойство подчинённого (`tsl_owner = import-api`). Scope подчинённого — только audience
  владельца. Выдать подчинённому scope `tsl-auth-admin`, `tsl-auth-app` или роль в чужом приложении невозможно
  ни одним API.
- Маршруты App API (политика как у `/api/app`, `client_id` владельца берётся из `sub` токена, не из URL):

| Метод | Путь | Что |
|---|---|---|
| GET | `/api/app/clients` | список своих подчинённых (без секретов и ключей) |
| POST | `/api/app/clients` | создать: `clientIdSuffix` или `clientId` с префиксом, `displayName`, `roles`, `jwks` (открытый ключ) **или** запрос секрета |
| GET | `/api/app/clients/{clientId}` | карточка, состояние, отпечатки ключей, последний выданный токен |
| PUT | `/api/app/clients/{clientId}/keys` | заменить ключи (до 2 одновременно, для плавной смены по `kid`) |
| POST | `/api/app/clients/{clientId}/disable` / `enable` | отключить / включить |
| POST | `/api/app/clients/{clientId}/secret` | новый секрет (только если политика разрешает `client_secret`) |
| DELETE | `/api/app/clients/{clientId}` | удалить с отзывом токенов |

- Чужой клиент (другой владелец или не подчинённый) — всегда **404**, а не 403, чтобы не раскрывать, что он есть.
- `client_id` проверяется: префикс, `[a-z0-9-]`, длина ≤ 64; суффикс со случайной частью генерирует tsl-auth, если
  не передан.
- Admin API и админка показывают у подчинённого владельца и позволяют администратору всё то же (отключить,
  удалить), страница приложения-владельца — список его подчинённых.

### 3.2. Действие от имени оператора

- Изменяющие маршруты `/api/app/clients*` принимают **только делегированный токен**: пользовательский токен
  оператора, обменянный Import API через Token Exchange (RFC 8693) на токен с `sub` = пользователь,
  `act.sub` = `import-api`, `aud` = `tsl-auth-app`.
- tsl-auth проверяет по своей БД (на каждый запрос, как `AdminPermissionHandler`), что у пользователя есть
  разрешение владельца `agents.manage` в матрице `import-api`. Нет разрешения — 403.
- Токен сервиса без пользователя (`client_credentials` import-api) допускается только для чтения
  (`GET /api/app/clients*`) — для фоновой сверки.
- Флаг политики `requireDelegation` (по умолчанию `true`) позволяет в тестовых стендах разрешить и сервисный токен.

### 3.3. Вход по ключу (`private_key_jwt`)

- Токен-эндпоинт принимает `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` и
  `client_assertion` (JWS). В OpenIddict 7 это делается через `JsonWebKeySet` у приложения; проверить на 7.7.1 и
  дописать недостающее.
- Требования к assertion: алгоритм только **ES256** (P-256) и, по желанию, EdDSA; `iss` = `sub` = `client_id`;
  `aud` — issuer или адрес токен-эндпоинта; `exp` не больше 5 минут от `iat`; `jti` одноразовый (кэш использованных
  `jti` до истечения `exp`, общий для узлов кластера — в БД или PostgreSQL); `alg=none` и HS* отклоняются.
- Ключ хранится как JWK (открытая часть) с `kid` = отпечаток по RFC 7638. Закрытых ключей tsl-auth не видит.
- В ответах об ошибке — только `invalid_client` без подробностей; подробности (неверная подпись, повтор `jti`,
  истёк `exp`) — в аудит с уровнем Warning, как сейчас у introspection.
- Метаданные OIDC: `token_endpoint_auth_methods_supported` включает `private_key_jwt`,
  `token_endpoint_auth_signing_alg_values_supported` — `ES256`.

### 3.4. Отключение клиента

- Свойство `tsl_disabled`. Отключённый клиент не получает токены (`invalid_client`), его refresh-токены и
  авторизации отзываются (`SessionService.RevokeByClientAsync`), introspection его токенов возвращает
  `active=false`.
- Событие вебхука `application.disabled` / `application.enabled` / `application.deleted` с `client_id` и `owner` —
  чтобы сервисы отсекали уже выданные JWT до истечения.
- Отключение и удаление доступны администратору tsl-auth и владельцу (3.1).

### 3.5. Аудит и защита

- Каждое действие с подчинённым — в журнал безопасности: кто (пользователь из `sub`), через кого (`act.sub`),
  что, клиент, отпечаток ключа. Владелец видит эти записи в `/api/app/audit`.
- Предел частоты на `/api/app/clients*` (например, 30 изменений в минуту на владельца) и на токен-эндпоинт по
  `client_id` при ошибках входа.
- Метрики: число подчинённых по владельцам, отказы `private_key_jwt` по причинам.

### 3.6. Этап 2 (по возможности)

- **DPoP** (RFC 9449) для токенов подчинённых: `cnf.jkt` в токене, проверка DPoP-proof на стороне сервиса
  (Tsl.Mesh и SDK). Если OpenIddict 7 не поддерживает DPoP — отложить и зафиксировать в ТЗ tsl-auth.
- Предел неактивности: подчинённый, не получавший токен N дней, отключается автоматически (как неактивные
  пользователи), с событием.

## 4. Приёмка в tsl-auth

Полная пирамида по правилам tsl-auth (SQLite и PostgreSQL):

- **Юнит:** проверка политики (префикс, роли, grant, лимит), разбор и проверка assertion (подпись, `aud`, `exp`,
  повтор `jti`, `alg=none`, HS256 с открытым ключом как секретом, ключ другой кривой).
- **Интеграционные:** владелец создаёт подчинённого с ключом → подчинённый получает токен по `private_key_jwt` →
  в токене роль `import-api:uploader` и срок из политики; повтор того же assertion — отказ; отключение → нет
  токена, introspection `active=false`, вебхук; удаление; чужой клиент — 404; роль не из белого списка, чужое
  приложение, `tsl-auth-admin` в scope — 400; сервисный токен без делегирования на изменение — 403; пользователь
  без `agents.manage` — 403; `maxClients`; смена ключа с двумя `kid`; два узла кластера и общий кэш `jti`.
- **Нагрузка:** 200 подчинённых, токен каждому раз в 5 минут — без роста ошибок.
- **UI:** владелец и подчинённые видны в админке, отключение из админки.
- **Документы:** `docs/integration.md` (подчинённые клиенты, `private_key_jwt`), `docs/security.md`, ЧТЗ tsl-auth,
  `client-contract.md` и SDK (Go и .NET: вход по `private_key_jwt`), CLAUDE.md tsl-auth.
- Выпуск: минорная версия (новые функции, без несовместимых изменений), образ в реестр GitFlic.

## 5. Что сообщить после выпуска

Версию образа tsl-auth и отличия от этой задачи, если что-то сделано иначе. Больше ничего не нужно: регистрацию
приложения import-api (флаг и политика подчинённых) Claude добавит в `scripts/tsl-auth/import-api.json` и
`tsl-auth-app.sh`.

## 6. Что сделает Claude в 1c-import после выпуска

- **Import API:** вместо `TslAuthAdmin` (Admin API) — клиент App API `/api/app/clients` с токеном оператора,
  обменянным через Token Exchange; настройки `Agents__TslAuth__AdminClient*` и секрет
  `AUTH_ADMIN_API_CLIENT_*` у import-api удаляются (в OpenBao — путь `1c-import/tsl-auth-admin`).
- **Одобрение:** Import API передаёт в tsl-auth открытый ключ подписи агента (он уже есть в заявке, P-256) как JWK.
  Шифрованная передача секрета (ECIES) для новых агентов больше не нужна; остаётся для агентов с секретом.
- **Агент:** получает токен по `private_key_jwt` своим ключом подписи из `enroll-keys.pem`; файла `client-secret`
  у зарегистрированных через UI агентов нет. Агенты, поставленные `agent-fleet.sh` с секретом, работают как раньше.
- **Блокировка:** кроме проверки в Import API — `disable` в tsl-auth; удаление — `DELETE` с отзывом токенов;
  Import API подписывается на вебхук `application.*`.
- **Тесты и документы:** интеграционные с настоящим tsl-auth нового выпуска, e2e «Агенты», `agent-enrollment.md`,
  `agent-rollout.md`, ТЗ (РС-16 закрывается), CLAUDE.md.

До выпуска tsl-auth текущая схема (РС-16) остаётся в силе для MVP.

## 7. Итог реализации (tsl-auth 1.5.0, 30.09.2026)

Сделано всё из разделов 3.1–3.5 и этап 2 в части предела неактивности. Отличия и уточнения:

| Пункт | Как сделано |
|---|---|
| 3.3, заголовок assertion | OpenIddict 7.7 принимает assertion только с явным типом `typ: client-authentication+jwt` (без `typ` или с `typ: JWT` — отказ). SDK .NET и Go ставят его сами; агенту 1c-import — ставить тоже |
| 3.3, `aud` | принимается issuer в точности как в discovery (`https://auth.corp/`); адрес token endpoint OpenIddict 7.7 отвергает («no valid audience») — SDK берут `issuer` из discovery |
| 3.3, EdDSA | не поддерживается: только ES256 (P-256) |
| 3.3, ответ | `invalid_client` всегда со статусом HTTP 401 (так отвечает OpenIddict); описание одинаковое, причина — в журнале (`token.rejected`, warning, `details.reason`: `alg`, `lifetime`, `jti_replay`, `server_validation` …) и метрике `tsl_auth.client_assertion.rejected{reason}` |
| 3.1, владелец | политика ставится только confidential-клиенту с включённым самоуправлением (App API); поток `token_exchange` нужен владельцу для делегированного токена |
| 3.1, удаление владельца | удаляет и его подчинённых |
| 3.5, предел на токен-эндпоинт | 20 отказов `invalid_client` за минуту по паре «`client_id` + IP» → блокировка на минуту (`Security__ClientAuthFailuresPerMinute`), считается на узел; так же на introspection и revocation; отказы отключённого клиента не считаются |
| 3.5, предел App API | 30 изменений в минуту на владельца (`Security__ManagedClientChangesPerMinute`), GET не считается |
| 3.6, DPoP | отложен — в OpenIddict 7.7 нет поддержки; зафиксировано в ЧТЗ (В-11) |
| 3.6, неактивность | `inactiveDays` в политике; отключение при обслуживании БД (раз в час) с событием `security.alert` и записью `managed_client.change` |
| SDK | вход по ключу — .NET и Go (`ClientKeys` / `tslauth.GenerateClientKeyPEM`); Node.js, Python, Java входят секретом |
| Admin API | `GET/PUT/DELETE …/managed-clients-policy`, `GET …/managed-clients`, `POST …/disable|enable`; в `ApplicationDto` — `owner`, `disabled`, `managedClients` |

Для 1c-import (раздел 6): регистрация `import-api` — `selfManagement: true`, `grantTypes: ["client_credentials","token_exchange"]`,
затем `PUT /api/admin/applications/import-api/managed-clients-policy` с `prefix: "import-agent-"`, `roles: ["uploader"]`,
`managePermission: "agents.manage"` (разрешение и роль оператора завести в матрице `import-api`).
