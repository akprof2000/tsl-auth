# TslAuth.Client — .NET SDK для TSL Auth

Проверка access-токенов TSL Auth (RS256 по JWKS), principal с правами, схема аутентификации ASP.NET Core с ответами
401/403 по контракту и клиент токенов. Без сторонних зависимостей — только `Microsoft.AspNetCore.App`
(`System.Text.Json`, `System.Security.Cryptography`). Цели: `net8.0`, `net10.0`. Поведение описано в
[`docs/client-contract.md`](https://github.com/akprof2000/tsl-auth/blob/main/docs/client-contract.md).

## Установка

```shell
dotnet add package TslAuth.Client
```

В закрытом контуре — из локального фида (`dotnet nuget add source <папка или URL>`), пакет `TslAuth.Client.<версия>.nupkg`
из релиза репозитория.

## Подключение одной строкой

```csharp
builder.Services.AddTslAuth();          // настройки из переменных окружения TSL_AUTH_*
// или: builder.Services.AddTslAuth(builder.Configuration);   // секция "TslAuth" appsettings.json, TSL_AUTH_* поверх
// или: builder.Services.AddTslAuth(o => { o.Issuer = "https://auth.corp/"; o.Audience = "orders-api"; });

var app = builder.Build();
app.UseAuthentication();   // стандартные middleware; отдельного app.UseTslAuth() нет и не нужно
app.UseAuthorization();
```

`AddTslAuth` регистрирует схему аутентификации `TslAuth` (Bearer из заголовка `Authorization`), делает её схемой по
умолчанию, если приложение не задало другую, и добавляет обработчики авторизации. В DI доступны `TslAuthOptions`,
`TslAuthVerifier`, `TokenClient`.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `TSL_AUTH_ISSUER` | — (обязательна) | адрес сервиса, как в `iss` токена |
| `TSL_AUTH_AUDIENCE` | — | `client_id` этого API (проверка `aud`, обрезка префиксов прав) |
| `TSL_AUTH_CLIENT_ID` / `TSL_AUTH_CLIENT_SECRET` | — | приложение для `TokenClient` и интроспекции |
| `TSL_AUTH_JWKS_URI` | из discovery | прямой адрес JWKS |
| `TSL_AUTH_CLOCK_SKEW_SECONDS` | `30` | допуск на часы при `exp`/`nbf` |
| `TSL_AUTH_JWKS_TTL_SECONDS` | `600` | срок кэша ключей и discovery |
| `TSL_AUTH_JWKS_MIN_REFRESH_SECONDS` | `10` | не чаще перечитывать JWKS по неизвестному `kid` |
| `TSL_AUTH_INTROSPECT` | `false` | после локальной проверки спрашивать introspection endpoint |
| `TSL_AUTH_HTTP_TIMEOUT_SECONDS` | `10` | таймаут HTTP к сервису |

В секции конфигурации ключи те же без префикса, интервалы — `ClockSkewSeconds`, `JwksTtlSeconds`,
`JwksMinRefreshSeconds`, `HttpTimeoutSeconds`. Переменные окружения имеют приоритет над секцией
(`AddTslAuth(configuration, environmentOverrides: false)` — отключить).

## Защита маршрутов

```csharp
app.MapGet("/me", (HttpContext ctx) => new { username = ctx.GetTslPrincipal()!.Username })
   .RequireTslAuth();                                   // только аутентификация → иначе 401
app.MapGet("/orders", ...).RequireTslPermission("orders.read");            // 403 insufficient_permissions
app.MapPost("/orders", ...).RequireTslAnyPermission("orders.write", "orders.admin");
app.MapDelete("/orders/{id}", ...).RequireTslRole("manager");             // 403 insufficient_role
app.MapPost("/payments", ...).RequireTslMfa();                            // 403 mfa_required
app.MapGet("/internal", ...).RequireTslSubjectType("client");             // 403 subject_type_not_allowed
```

Разрешения и роли указываются в короткой форме (без префикса `<audience>:`). Для контроллеров и
`[Authorize(Policy = ...)]` — `options.AddPolicy("orders.read", TslAuthEndpointExtensions.Policy(new TslPermissionRequirement("orders.read")))`.

Ответы отказа (RFC 6750): `401` — `WWW-Authenticate: Bearer realm="tsl-auth", error="invalid_token", error_description="<код>"`
и тело `{"error":"invalid_token","error_description":"<код>"}`, где код — `missing`, `malformed`, `unsupported_alg`,
`unknown_key`, `bad_signature`, `bad_issuer`, `expired`, `not_yet_valid`, `bad_audience`, `revoked`,
`introspection_unavailable`; `403` — `error="<insufficient_permissions|insufficient_role|mfa_required|subject_type_not_allowed>"`,
`error_description="<что требовалось>"` (например `orders-api:orders.write`).

В обработчике: `HttpContext.GetTslPrincipal()` (или `HttpContext.Features.Get<TslPrincipal>()`) — `Subject`,
`SubjectType`, `Username`, `Roles`/`Permissions` (этого API), `AllRoles`/`AllPermissions` (с префиксами), `Scopes`,
`Amr`, `IsMfa`, `Actor` (цепочка token exchange), `ExpiresAt`, `Claims`, `HasPermission(...)`, `HasRole(...)`.
`HttpContext.User` — `ClaimsPrincipal` с claims как в токене (`role`, `permissions` с префиксами), `Identity.Name` = `preferred_username`.

## Проверка токена без ASP.NET Core

```csharp
var verifier = new TslAuthVerifier(TslAuthOptions.FromEnvironment());
try
{
    TslPrincipal p = await verifier.VerifyAsync(jwt);
}
catch (TslAuthException ex)
{
    Console.WriteLine(ex.Code); // код из контракта, §2
}
```

Часы подменяются через `TslAuthOptions.TimeProvider`, HTTP — через `TslAuthOptions.HttpMessageHandler`.

## Клиент токенов

```csharp
var tokens = new TokenClient(TslAuthOptions.FromEnvironment()); // нужны TSL_AUTH_CLIENT_ID/SECRET

TokenSet svc = await tokens.ClientCredentialsAsync(new[] { "orders-api" });   // кэш до exp − 30 с, single-flight
TokenSet onBehalf = await tokens.ExchangeAsync(userAccessToken, new[] { "orders-api" });
TokenSet fresh = await tokens.RefreshAsync(refreshToken);                       // fresh.RefreshToken — новый, сохраните его
TokenSet code = await tokens.AuthorizationCodeAsync(code, redirectUri, codeVerifier);
TokenIntrospection i = await tokens.IntrospectAsync(accessToken);               // i.Active
await tokens.RevokeAsync(refreshToken);
```

Ошибки — `TokenError` с `Error` (`invalid_grant`, … или `unavailable` для сети/5xx), `ErrorDescription`, `Status`.
Секреты и токены SDK не логирует.

## Тесты

Контрактные тесты (`tests/TslAuth.Client.Tests`) идут против живого TSL Auth и `tests/sdk-contract/vectors.json`
(путь — переменная `SDK_CONTRACT_VECTORS`, по умолчанию файл ищется вверх по каталогам):

```shell
python tests/sdk-contract/make-vectors.py     # TSL_AUTH_ISSUER, ADMIN_CLIENT_SECRET
dotnet test sdk/dotnet/TslAuth.Client.sln -c Release
```

Сборка пакета: `dotnet pack sdk/dotnet/TslAuth.Client/TslAuth.Client.csproj -c Release -p:Version=1.2.3 -o dist`.
