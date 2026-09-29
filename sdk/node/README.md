# @tsl/auth-client — SDK TSL Auth для Node.js и браузера

Клиентская библиотека TSL Auth без единой зависимости: проверка access-токенов (RS256 по JWKS), middleware для
Express/Connect и чистого `node:http`, клиент токенов (все grant'ы, introspection, revocation) и браузерный клиент для SPA
(authorization code + PKCE). Поведение — строго по [контракту SDK](../../docs/client-contract.md); одинаковое с SDK для
.NET, Go, Python и Java.

Требования: Node.js 20+ (встроенные `fetch`, `node:crypto`, WebCrypto). Работает в закрытом контуре: сеть нужна только
до самого сервиса TSL Auth.

## Установка

```bash
npm install @tsl/auth-client
```

Для закрытого контура — из tarball: `npm install ./tsl-auth-client-X.Y.Z.tgz` (собирается `npm pack`, см. ниже).

## Подключение одной строкой

```js
import { tslAuth } from "@tsl/auth-client";

app.use("/api", tslAuth()); // настройки — из окружения, ключи — через discovery, principal — в req.auth
```

## Переменные окружения

| Переменная | Обязательна | По умолчанию | Назначение |
|---|---|---|---|
| `TSL_AUTH_ISSUER` | да | — | Адрес сервиса, как в `iss` токена, например `https://auth.corp/` |
| `TSL_AUTH_AUDIENCE` | для API | — | `client_id` этого API: токен принимается, только если `aud` его содержит |
| `TSL_AUTH_CLIENT_ID` | для клиента токенов | — | `client_id` приложения |
| `TSL_AUTH_CLIENT_SECRET` | для confidential-клиента | — | Секрет приложения |
| `TSL_AUTH_JWKS_URI` | нет | из discovery | Прямой адрес JWKS (стенды без discovery, тесты) |
| `TSL_AUTH_CLOCK_SKEW_SECONDS` | нет | `30` | Допуск на расхождение часов при проверке `exp`/`nbf` |
| `TSL_AUTH_JWKS_TTL_SECONDS` | нет | `600` | Срок кэша ключей и discovery |
| `TSL_AUTH_JWKS_MIN_REFRESH_SECONDS` | нет | `10` | Не чаще этого перечитывать JWKS по неизвестному `kid` |
| `TSL_AUTH_INTROSPECT` | нет | `false` | После локальной проверки спрашивать `/connect/introspect` (мгновенный отзыв) |
| `TSL_AUTH_HTTP_TIMEOUT_SECONDS` | нет | `10` | Таймаут HTTP-запросов к сервису |

Явные параметры конструкторов (`issuer`, `audience`, `clientId`, `clientSecret`, `jwksUri`, `clockSkew`, `jwksTtl`,
`jwksMinRefresh`, `introspect`, `httpTimeout`) имеют приоритет над окружением. Дополнительно: `now` — часы
(функция, возвращающая `Date` или число секунд), `fetch` — своя реализация fetch.

## Защита маршрута

### Express / Connect

```js
import express from "express";
import { tslAuth } from "@tsl/auth-client";

const app = express();
const auth = tslAuth({ issuer: "https://auth.corp/", audience: "orders-api" });

app.get("/api/me", auth, (req, res) => res.json({ username: req.auth.username }));
app.get("/api/orders", auth.require({ permission: "orders.read" }), (req, res) => res.json([]));
app.post("/api/orders", auth.require({ permission: "orders.write", mfa: true }), (req, res) => res.sendStatus(201));
app.get("/api/reports", auth.require({ anyPermission: ["reports.read", "reports.admin"] }), handler);
app.get("/api/admin", auth.require({ role: "admin", subjectType: "user" }), handler);
```

### Чистый `node:http`

```js
import { createServer } from "node:http";
import { tslAuth } from "@tsl/auth-client";

const auth = tslAuth(); // из окружения
const me = auth.protect((req, res) => res.end(JSON.stringify({ username: req.auth.username })));
const orders = auth.protect((req, res) => res.end("[]"), { permission: "orders.read" });

createServer((req, res) => (req.url === "/me" ? me(req, res) : orders(req, res))).listen(8081);
```

Требования: `permission`, `anyPermission`, `role`, `mfa`, `subjectType`. Отказы строго по контракту (RFC 6750):

- `401` — `WWW-Authenticate: Bearer realm="tsl-auth", error="invalid_token", error_description="<код>"`,
  тело `{"error":"invalid_token","error_description":"<код>"}`; без токена код — `missing`.
- `403` — `error` = `insufficient_permissions` / `insufficient_role` / `mfa_required` / `subject_type_not_allowed`,
  `error_description` = что требовалось (`orders-api:orders.write`).

Principal в `req.auth`: `subject`, `subjectType`, `username`, `name`, `email`, `roles`, `permissions` (этого API, без
префикса), `allRoles`, `allPermissions`, `scopes`, `amr`, `isMfa`, `actor` (цепочка token exchange), `expiresAt`,
`claims`; методы `hasPermission("orders.read")`, `hasAnyPermission([...])`, `hasRole("manager")`. Полная форма
`"orders-api:orders.read"` в методах намеренно **не** принимается.

### Проверка токена без middleware

```js
import { createVerifier, TslAuthError } from "@tsl/auth-client";

const verifier = createVerifier({ issuer: "https://auth.corp/", audience: "orders-api" });
try {
  const principal = await verifier.verify(token);
} catch (e) {
  if (e instanceof TslAuthError) console.log(e.code); // missing | malformed | unsupported_alg | unknown_key | bad_signature |
} //                                                   bad_issuer | expired | not_yet_valid | bad_audience | revoked | introspection_unavailable
```

Дополнительный код `jwks_unavailable` — JWKS не удалось загрузить ни разу (сеть); при протухшем кэше используется старый набор.

## Клиент токенов

```js
import { createTokenClient, TokenError } from "@tsl/auth-client";

const tokens = createTokenClient({ issuer: "https://auth.corp/", clientId: "orders-api", clientSecret: process.env.TSL_AUTH_CLIENT_SECRET });

const service = await tokens.clientCredentials("reports-api");            // кэш по scope до expiresAt − 30 с, single-flight
const onBehalf = await tokens.exchange(incomingBearerToken, "reports-api");   // token exchange (не кэшируется)
const renewed = await tokens.refresh(refreshToken);                       // refreshToken в ответе — новый (ротация)
const info = await tokens.introspect(accessToken);                        // { active, ... }
await tokens.revoke(refreshToken);

try {
  await tokens.password("user", "secret", "openid orders-api");           // только серверные приложения
} catch (e) {
  if (e instanceof TokenError) console.log(e.error, e.errorDescription, e.status); // invalid_grant ... 400; unavailable — сеть/5xx
}
```

`TokenSet`: `accessToken`, `refreshToken?`, `idToken?`, `expiresAt` (Date), `scope`, `tokenType`, `raw`.

## Браузерный клиент (`@tsl/auth-client/browser`)

```js
import { createBrowserClient } from "@tsl/auth-client/browser";

const auth = createBrowserClient({
  issuer: "https://auth.corp/",
  clientId: "orders-web",
  scope: "openid profile offline_access orders-api",
  redirectUri: `${location.origin}/callback`,         // по умолчанию
  postLogoutRedirectUri: `${location.origin}/`,       // по умолчанию
});

if (location.pathname === "/callback") await auth.handleCallback(); // state, одноразовый PKCE, обмен кода
document.getElementById("login").onclick = () => auth.login();      // PKCE S256 → redirect на authorization_endpoint
document.getElementById("logout").onclick = () => auth.logout();    // очистка + end_session_endpoint

const res = await auth.fetch("/api/orders");        // Authorization: Bearer с автообновлением
const token = await auth.getAccessToken();          // null, если сессии нет или refresh отклонён
const claims = auth.getClaims();                    // только декодирование, БЕЗ проверки подписи — для интерфейса
auth.isLoggedIn();
```

Токены хранятся в `sessionStorage` (ключи `tsl-auth:*`), не в cookie и не в `localStorage`. `getAccessToken()`
обновляет токен, если он истекает менее чем через 30 с и есть refresh-токен (параллельные вызовы — один запрос);
новая пара заменяет старую немедленно. `getClaims()` не проверяет подпись: доверять этим данным для решений о доступе
нельзя — проверяет API на сервере. Ошибки — `BrowserAuthError` с `code` (`state_mismatch`, `missing_code`,
`discovery_failed` или код OAuth 2.0 от сервера).

## Тесты

Контрактные тесты (`node:test`, без зависимостей) работают против живого TSL Auth и `tests/sdk-contract/vectors.json`
(путь — `SDK_CONTRACT_VECTORS`, по умолчанию `../../tests/sdk-contract/vectors.json`):

```bash
cd sdk/node && npm test
```

- `tests/vectors.test.js` — все векторы §8.2 и поля principal;
- `tests/live.test.js` — `refresh_rotation`, `introspection_revoked`, `client_credentials_cache`, `jwks_rotation`
  (локальная заглушка JWKS на `node:http`);
- `tests/middleware.test.js` — HTTP-сервер на свободном порту: `/me`, `/orders`, `/orders/write`, форматы 401/403;
- `tests/browser.test.js` — браузерный клиент в Node с подменой `sessionStorage`, `location`, `history`, `fetch`.

Сборка пакета: `cd sdk/node && npm pack` (в tarball — только `src/`, `README.md`, `package.json`).
