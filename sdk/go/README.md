# TSL Auth SDK для Go (`tslauth`)

Клиентская библиотека TSL Auth для Go: проверка access-токенов (RS256, JWKS с кэшем и ротацией), principal
с правами, middleware для `net/http` и клиент токенов. **Только стандартная библиотека** — работает в закрытом
контуре. Поведение задано общим контрактом SDK: [`docs/client-contract.md`](../../docs/client-contract.md).

Требования: Go 1.22+.

## Установка

```bash
go get github.com/akprof2000/tsl-auth/sdk/go@v1.2.3     # версия = тег сервиса (vX.Y.Z)
```

Модуль публикуется тегом `sdk/go/vX.Y.Z` в том же репозитории, что и образ сервиса, той же версией.

Закрытый контур (без доступа к GitHub и proxy.golang.org):

```bash
# 1. Локальная копия репозитория (или распакованный архив) и replace в вашем go.mod:
#    require github.com/akprof2000/tsl-auth/sdk/go v0.0.0
#    replace github.com/akprof2000/tsl-auth/sdk/go => ../tsl-auth/sdk/go
# 2. Либо vendor: на машине с доступом — go mod vendor, в контуре — сборка с GOFLAGS=-mod=vendor.
# 3. Либо зеркало GitFlic (модуль под тем же путём в зеркале, без proxy):
GOPROXY=direct GONOSUMDB=go.gitflic.ru GOFLAGS=-mod=mod go get go.gitflic.ru/uklad/tsl-auth/sdk/go@v1.2.3
```

## Подключение одной строкой

```go
import tslauth "github.com/akprof2000/tsl-auth/sdk/go"

v, err := tslauth.New(tslauth.OptionsFromEnv())            // настройки из TSL_AUTH_*
mux.Handle("/orders", v.Protect(orders, tslauth.Require{Permission: "orders.read"}))
```

## Переменные окружения

| Переменная | Обязательна | По умолчанию | Назначение |
|---|---|---|---|
| `TSL_AUTH_ISSUER` | да | — | Адрес сервиса, как в `iss` токена (`https://auth.corp/`) |
| `TSL_AUTH_AUDIENCE` | для API | — | `client_id` этого API: токен принимается, только если `aud` его содержит |
| `TSL_AUTH_CLIENT_ID` | для клиента токенов | — | `client_id` приложения (client_credentials, exchange, refresh, introspection) |
| `TSL_AUTH_CLIENT_SECRET` | для confidential-клиента | — | Секрет приложения |
| `TSL_AUTH_JWKS_URI` | нет | из discovery | Прямой адрес JWKS (стенды без discovery, тесты) |
| `TSL_AUTH_CLOCK_SKEW_SECONDS` | нет | `30` | Допуск на расхождение часов (`exp`/`nbf`) |
| `TSL_AUTH_JWKS_TTL_SECONDS` | нет | `600` | Срок кэша ключей и discovery |
| `TSL_AUTH_JWKS_MIN_REFRESH_SECONDS` | нет | `10` | Не чаще этого перечитывать JWKS по неизвестному `kid` |
| `TSL_AUTH_INTROSPECT` | нет | `false` | После локальной проверки спрашивать `/connect/introspect` (мгновенный отзыв) |
| `TSL_AUTH_HTTP_TIMEOUT_SECONDS` | нет | `10` | Таймаут HTTP-запросов к сервису |

Явные поля `Options` имеют приоритет над окружением. `Options.Now` — инжектируемые часы, `Options.HTTPClient` —
свой транспорт (корпоративный CA, прокси).

## Защита маршрута

```go
v, err := tslauth.New(tslauth.Options{Issuer: "https://auth.corp/", Audience: "orders-api"})
if err != nil { log.Fatal(err) }

mux := http.NewServeMux()
// Только аутентификация — principal в контексте запроса.
mux.Handle("/me", v.Protect(func(w http.ResponseWriter, r *http.Request) {
    p, _ := tslauth.FromContext(r.Context())
    fmt.Fprintf(w, "%s (%s), права: %v", p.Username, p.SubjectType, p.Permissions)
}, tslauth.Require{}))
// Требования: Permission, AnyPermission, Role, MFA, SubjectType (401/403 по контракту §5).
mux.Handle("/orders", v.Protect(listOrders, tslauth.Require{Permission: "orders.read"}))
mux.Handle("/orders/approve", v.Protect(approve, tslauth.Require{Permission: "orders.write", MFA: true}))
// Как обычный middleware:
mux.Handle("/reports/", v.Middleware(tslauth.Require{Role: "manager"})(reports))
```

Ответы отказа: `401` — `WWW-Authenticate: Bearer realm="tsl-auth", error="invalid_token", error_description="<код>"`
и тело `{"error":"invalid_token","error_description":"<код>"}`; `403` — код `insufficient_permissions` /
`insufficient_role` / `mfa_required` / `subject_type_not_allowed`. Ничего из токена в ответ не попадает.

Проверка вручную:

```go
p, err := v.Verify(ctx, token)
if errors.Is(err, tslauth.ErrExpired) { ... }        // sentinel-ошибки по кодам §2
var ae *tslauth.AuthError
if errors.As(err, &ae) { log.Println(ae.Code) }      // missing, malformed, unsupported_alg, unknown_key,
                                                     // bad_signature, bad_issuer, expired, not_yet_valid,
                                                     // bad_audience, revoked, introspection_unavailable
p.HasPermission("orders.read"); p.HasRole("manager"); p.IsMFA(); p.Actor(); p.Claims["resource_access"]
```

## Клиент токенов

```go
tc, err := tslauth.NewTokenClient(tslauth.Options{
    Issuer: "https://auth.corp/", ClientID: "billing-worker", ClientSecret: os.Getenv("TSL_AUTH_CLIENT_SECRET"),
})
// Токен самого сервиса: кэш до ExpiresAt−30 с, параллельные вызовы — один запрос (single-flight).
ts, err := tc.ClientCredentials(ctx, "orders-api")
req.Header.Set("Authorization", "Bearer "+ts.AccessToken)

// От имени пользователя (token exchange, RFC 8693) — не кэшируется.
ts, err = tc.Exchange(ctx, userAccessToken, "orders-api")

// Refresh с ротацией: сохраняйте ts.RefreshToken, старый больше не используйте.
ts, err = tc.Refresh(ctx, refreshToken)
ts, err = tc.Password(ctx, username, password, "openid", "offline_access", "orders-api")
ts, err = tc.AuthorizationCode(ctx, code, redirectURI, codeVerifier)   // PKCE обязателен
info, err := tc.Introspect(ctx, token)                                  // info.Active, info.Claims
err = tc.Revoke(ctx, token)

var te *tslauth.TokenError
if errors.As(err, &te) { log.Println(te.Code, te.Status) }  // invalid_grant, invalid_client, …; сеть/5xx — unavailable
```

`TokenSet`: `AccessToken`, `RefreshToken`, `IDToken`, `ExpiresAt`, `Scope`, `TokenType`.

## Тесты

Контрактные тесты (`docs/client-contract.md` §8) идут против живого TSL Auth и `tests/sdk-contract/vectors.json`:

```bash
# из корня репозитория: docker compose up -d, затем
TSL_AUTH_ISSUER=http://localhost:8080/ ADMIN_CLIENT_SECRET=... python tests/sdk-contract/make-vectors.py
cd sdk/go && go test ./... -count=1        # путь к векторам — SDK_CONTRACT_VECTORS
go vet ./... && gofmt -l .
```

Полный прогон всех SDK — `tests/sdk-contract/run.ps1`.

## Лицензия

MIT, © akprof2000.
