# Демо Java API на TSL Auth SDK

Маленький API на `com.sun.net.httpserver` (JDK 11+, без фреймворков), защищённый библиотекой
[`ru.tsl.auth:tsl-auth-client`](../../sdk/java):

| Маршрут | Требование |
|---|---|
| `GET /health` | — |
| `GET /api/me` | аутентификация: возвращает subject, роли и разрешения из токена |
| `GET /api/inventory` | разрешение `inventory.read` |
| `POST /api/inventory/adjust?sku=bolt-m6&delta=-5` | разрешение `inventory.write` |

Переменные: `AUTH_ISSUER` (по умолчанию `http://localhost:8080/`), `API_AUDIENCE` (`demo-java-api`), `PORT` (`5105`).

Документация API — как у TSL Auth: руководство http://localhost:5105/docs, справочник Scalar http://localhost:5105/docs/api,
OpenAPI — `/openapi/v1.json` (файлы в `src/main/resources/docs`, см. [integration.md §12](../../docs/integration.md#12-документация-rest-api-модуля-docs-и-docsapi)).

## 1. Регистрация в TSL Auth

`samples/seed-demo.ps1` уже создаёт приложение-API `demo-java-api` с разрешениями `inventory.read`, `inventory.write`
и ролью `storekeeper` («Кладовщик», обе операции); у пользователя `alice` эта роль есть, у `bob` — нет.

```powershell
docker compose up -d           # TSL Auth на http://localhost:8080
.\samples\seed-demo.ps1        # пользователи alice / bob, пароль Demo-Passw0rd!
```

## 2. Сборка и запуск

Maven ставить не нужно — в каталоге лежит Maven Wrapper. SDK берётся из локального репозитория Maven, поэтому сначала
установите его (в закрытом контуре — jar из релиза в ваш Nexus/Artifactory, тогда этот шаг не нужен):

```bash
cd sdk/java && ./mvnw -q -B -DskipTests install && cd ../../samples/java-api
./mvnw -q package
java -jar target/demo-java-api.jar        # зависимости — в target/lib, подхватываются через манифест
```

Windows: `.\mvnw.cmd` вместо `./mvnw`. Версия SDK в `pom.xml` — свойство `revision` (по умолчанию `0.0.0-dev`,
как у локальной сборки; для релизной версии `./mvnw -q -Drevision=1.2.3 package`).

## 3. Токен для вызова

API принимает только токены, у которых `aud` содержит `demo-java-api`. Удобнее всего — персональный токен (PAT):
войдите в TSL Auth как `alice`, откройте `/Account/Tokens`, создайте токен с приложением **demo-java-api**
(см. [integration.md §6](../../docs/integration.md#6-персональные-токены-pat-для-скриптов)) и обменяйте его на JWT:

```bash
JWT=$(curl -s -X POST http://localhost:8080/connect/token \
  -d grant_type=urn:tsl:grant-type:pat -d client_id=tsl-pat -d token=tslpat_... | jq -r .access_token)
```

JWT содержит текущие права владельца по выбранным приложениям; отзыв PAT или отключение пользователя сразу прекращает выдачу.

## 4. Примеры

```bash
curl -s http://localhost:5105/health
# {"status":"ok","audience":"demo-java-api"}

curl -s -i http://localhost:5105/api/me
# HTTP/1.1 401  WWW-Authenticate: Bearer realm="tsl-auth", error="invalid_token", error_description="missing"

curl -s -H "Authorization: Bearer $JWT" http://localhost:5105/api/me
# {"subject":"...","subjectType":"user","username":"alice","roles":["storekeeper"],"permissions":["inventory.read","inventory.write"],"mfa":false}

curl -s -H "Authorization: Bearer $JWT" http://localhost:5105/api/inventory
# {"items":{"bolt-m6":120,"nut-m6":80,"washer-6":300}}

curl -s -X POST -H "Authorization: Bearer $JWT" "http://localhost:5105/api/inventory/adjust?sku=bolt-m6&delta=-5"
# {"sku":"bolt-m6","quantity":115,"by":"alice"}
```

Токен `bob` (PAT без роли в `demo-java-api`) на `/api/inventory` даст `403`:
`{"error":"insufficient_permissions","error_description":"demo-java-api:inventory.read"}` и такой же
`WWW-Authenticate`. Токен другого API (`aud` без `demo-java-api`) — `401` с `error_description="bad_audience"`.

## Как это устроено

Весь код — [`src/main/java/demo/App.java`](src/main/java/demo/App.java): `TslAuthVerifier` создаётся один раз,
`TslAuthHandler.protect(handler, Require.permission(...))` оборачивает обработчики, а principal читается из
`TslAuthHandler.principal(exchange)`. Проверка токена, кэш JWKS, формат ответов 401/403 — в SDK, по
[контракту](../../docs/client-contract.md).
