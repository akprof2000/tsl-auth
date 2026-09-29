# TSL Auth Client для Java

Клиентская библиотека TSL Auth для Java 11+: проверка access-токенов по JWKS, фильтр авторизации для
`jakarta.servlet` и `com.sun.net.httpserver`, клиент token endpoint. Поведение — строго по
[контракту SDK](../../docs/client-contract.md); зависимости — только `jackson-databind` (и `jakarta.servlet-api`
как `provided` для фильтра), поэтому библиотека работает в закрытом контуре.

## Установка

Maven:

```xml
<dependency>
  <groupId>ru.tsl.auth</groupId>
  <artifactId>tsl-auth-client</artifactId>
  <version>1.2.3</version> <!-- версия = версия сервиса TSL Auth -->
</dependency>
```

Gradle: `implementation("ru.tsl.auth:tsl-auth-client:1.2.3")`.

В закрытом контуре положите jar из релиза в свой Nexus/Artifactory или соберите сами и установите в локальный
репозиторий: `./mvnw -B -Drevision=1.2.3 install` (без интернета Maven потребуется зеркало для зависимостей).

## Подключение одной строкой

```java
TslAuthVerifier verifier = TslAuthVerifier.fromEnvironment(); // TSL_AUTH_ISSUER, TSL_AUTH_AUDIENCE, ...
```

Явные параметры имеют приоритет над окружением:

```java
TslAuthVerifier verifier = new TslAuthVerifier(TslAuthOptions.builder()
    .issuer("https://auth.corp/").audience("orders-api").build());
```

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `TSL_AUTH_ISSUER` | — (обязательна) | адрес сервиса, как в `iss` токена |
| `TSL_AUTH_AUDIENCE` | — | `client_id` этого API: токен принимается, только если `aud` его содержит |
| `TSL_AUTH_CLIENT_ID` / `TSL_AUTH_CLIENT_SECRET` | — | приложение для `TokenClient` и интроспекции |
| `TSL_AUTH_JWKS_URI` | из discovery | прямой адрес JWKS (стенды без discovery) |
| `TSL_AUTH_CLOCK_SKEW_SECONDS` | `30` | допуск на расхождение часов для `exp`/`nbf` |
| `TSL_AUTH_JWKS_TTL_SECONDS` | `600` | срок кэша ключей и discovery |
| `TSL_AUTH_JWKS_MIN_REFRESH_SECONDS` | `10` | не чаще этого перечитывать JWKS по неизвестному `kid` |
| `TSL_AUTH_INTROSPECT` | `false` | после локальной проверки спрашивать `/connect/introspect` (мгновенный отзыв) |
| `TSL_AUTH_HTTP_TIMEOUT_SECONDS` | `10` | таймаут HTTP-запросов к сервису |

Часы (`java.time.Clock`) подменяются через `TslAuthOptions.builder().clock(...)` — так тесты проверяют `exp`/`nbf`.

## Проверка токена и principal

```java
try {
    Principal p = verifier.verify(jwt);          // или verifier.verifyAuthorization(headerValue) — даёт missing
    p.subject(); p.subjectType(); p.username();  // user / client; username у сервисных токенов null
    p.permissions(); p.roles();                  // права этого API без префикса "<audience>:"
    p.hasPermission("orders.read"); p.hasRole("operator"); p.isMfa();
    p.allPermissions(); p.allRoles();            // как в токене, с префиксами (для шлюзов)
    p.actor();                                   // цепочка token exchange или null
    p.claims();                                  // сырые claims
} catch (TslAuthException e) {
    e.getCode(); // missing, malformed, unsupported_alg, unknown_key, bad_signature, bad_issuer,
                 // expired, not_yet_valid, bad_audience, revoked, introspection_unavailable
}
```

Дополнительный код `jwks_unavailable` — ключи не удалось загрузить ни разу (сервис недоступен при первой проверке);
при уже загруженном наборе сетевая ошибка проверку не роняет.

## Защита маршрута

Требования (`Require`) одинаковы для всех интеграций: `permission`, `anyPermission`, `role`, `mfa`, `subjectType`.
Ответы — RFC 6750: `401` с `WWW-Authenticate: Bearer realm="tsl-auth", error="invalid_token", error_description="<код>"`,
`403` с кодом `insufficient_permissions` / `insufficient_role` / `mfa_required` / `subject_type_not_allowed`;
тело `{"error":..., "error_description":...}`. Principal — в атрибуте запроса `tslauth.principal`.

### `com.sun.net.httpserver` (JDK)

```java
TslAuthHandler auth = new TslAuthHandler(verifier);
server.createContext("/me", auth.protect(ex -> { Principal p = TslAuthHandler.principal(ex); ... }));
server.createContext("/orders", auth.protect(ordersHandler, Require.permission("orders.read")));
server.createContext("/admin", auth.protect(adminHandler, Require.role("admin").andMfa()));
```

### `jakarta.servlet` (Tomcat, Jetty, Spring Boot)

```java
TslAuthFilter filter = new TslAuthFilter(verifier, Require.permission("orders.read"));
Principal p = TslAuthFilter.principal(request); // в сервлете
```

Spring Boot — без зависимости SDK на Spring, через `FilterRegistrationBean`:

```java
@Bean FilterRegistrationBean<TslAuthFilter> ordersAuth(TslAuthVerifier verifier) {
    var reg = new FilterRegistrationBean<>(new TslAuthFilter(verifier, Require.permission("orders.read")));
    reg.addUrlPatterns("/api/orders/*");
    return reg;
}
@Bean TslAuthVerifier tslAuthVerifier() { return TslAuthVerifier.fromEnvironment(); }
```

## Клиент токенов

```java
TokenClient tokens = TokenClient.fromEnvironment(); // TSL_AUTH_ISSUER, TSL_AUTH_CLIENT_ID, TSL_AUTH_CLIENT_SECRET
TokenSet svc = tokens.clientCredentials("orders-api");        // кэш до expiresAt − 30 с, single-flight
TokenSet onBehalf = tokens.exchange(userAccessToken, "orders-api"); // не кэшируется
TokenSet fresh = tokens.refresh(set.refreshToken());          // refresh ротируется: используйте fresh.refreshToken()
TokenSet byPassword = tokens.password(user, pass, "openid offline_access orders-api"); // только серверные приложения
TokenSet byCode = tokens.authorizationCode(code, redirectUri, codeVerifier);           // PKCE обязателен
tokens.introspect(token).active();
tokens.revoke(token);
```

Ошибки — `TokenException` с `getError()`, `getErrorDescription()`, `getStatus()`; сеть и 5xx → `error = "unavailable"`.
Секреты и токены библиотека не логирует (`TokenSet.toString()` их не содержит).

## Сборка и тесты

Maven не нужен — есть Maven Wrapper (скачивает Maven 3.9 при первом запуске; JDK 11+).

```bash
cd sdk/java
./mvnw -q -B test                       # контрактные тесты против живого стенда
./mvnw -B -Drevision=1.2.3 package      # jar + sources + javadoc c нужной версией (по умолчанию 0.0.0-dev)
```

Тесты читают `tests/sdk-contract/vectors.json` (путь — переменная `SDK_CONTRACT_VECTORS`, по умолчанию
`../../tests/sdk-contract/vectors.json`); векторы генерирует `tests/sdk-contract/make-vectors.py` против
запущенного TSL Auth. Состав: все случаи vectors.json (коды ошибок и поля principal), живые сценарии
(`refresh_rotation`, `introspection_revoked`, `client_credentials_cache`, `jwks_rotation` на локальной заглушке JWKS)
и `middleware` — реальный `HttpServer` с `TslAuthHandler`.

Пример приложения — [`samples/java-api`](../../samples/java-api).
