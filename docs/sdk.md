# Клиентские библиотеки (SDK)

Пять библиотек, чтобы подключить приложение к TSL Auth без ручной работы с JWT: задать адрес сервиса и имя своего
API — и защищать маршруты одной строкой. Все пять ведут себя одинаково: порядок проверок, коды ошибок, формат
ответов 401/403, чтение прав, кэш ключей и ротация refresh описаны в [контракте](client-contract.md) и проверяются
контрактными тестами против живого контейнера на каждый push (`.github/workflows/sdk.yml`).

| Стек | Пакет | Каталог | Подключение |
|---|---|---|---|
| .NET 8/10 (ASP.NET Core) | NuGet `TslAuth.Client` | [`sdk/dotnet`](../sdk/dotnet) | `builder.Services.AddTslAuth();` → `.RequireTslPermission("orders.read")` |
| Node.js ≥ 20 (Express/Connect, `node:http`) и браузер | npm `@tsl/auth-client` (`/browser`) | [`sdk/node`](../sdk/node) | `app.use(tslAuth())` → `tslAuth({ permission: "orders.read" })` |
| Go ≥ 1.22 (`net/http`) | модуль `github.com/akprof2000/tsl-auth/sdk/go` | [`sdk/go`](../sdk/go) | `v.Middleware(tslauth.Require{Permission: "orders.read"})` |
| Python ≥ 3.10 (FastAPI, Flask, любой WSGI) | PyPI `tsl-auth-client` | [`sdk/python`](../sdk/python) | `install(app)` → `require(permission="orders.read")` |
| Java ≥ 11 (Servlet, JDK HttpServer, Spring Boot через фильтр) | Maven `ru.tsl.auth:tsl-auth-client` | [`sdk/java`](../sdk/java) | `new TslAuthFilter(Require.permission("orders.read"))` |

Подробности по каждому — в README каталога. Пример на Java: [`samples/java-api`](../samples/java-api).

## Настройка — одна для всех

SDK читают переменные окружения (полный список — [контракт, §1](client-contract.md#1-конфигурация)):

```bash
TSL_AUTH_ISSUER=https://auth.corp/        # адрес сервиса (как iss в токене)
TSL_AUTH_AUDIENCE=orders-api              # client_id этого API — токен принимается только с таким aud
TSL_AUTH_CLIENT_ID=orders-api             # для клиента токенов: client_credentials, exchange, introspection
TSL_AUTH_CLIENT_SECRET=...                # секрет confidential-клиента
TSL_AUTH_INTROSPECT=false                 # true — дополнительно спрашивать сервис (мгновенный отзыв)
```

Дальше SDK сам находит ключи через `/.well-known/openid-configuration`, кэширует их, перечитывает при ротации
(неизвестный `kid`) и проверяет каждый токен: `RS256` → подпись → `iss` → `exp` → `aud`.

## Что даёт каждая библиотека

- **Проверка токена** — `Verifier`: из строки JWT в **principal** с полями `subject`, `subjectType`, `username`,
  `roles`, `permissions` (уже без префикса `"<audience>:"`), `amr`/`isMfa`, `actor` (цепочка token exchange), `claims`.
- **Защита маршрутов** — middleware / фильтр / dependency с требованиями `permission`, `anyPermission`, `role`,
  `mfa`, `subjectType`. Отказ — `401` (`invalid_token` + код причины) или `403` (`insufficient_permissions`,
  `insufficient_role`, `mfa_required`, `subject_type_not_allowed`) с телом JSON и заголовком `WWW-Authenticate`.
- **Клиент токенов** — `clientCredentials` (кэш до истечения, один запрос при гонке), `exchange` (RFC 8693, вызов
  другого API от имени пользователя), `refresh` (с ротацией), `password`, `authorizationCode`, `introspect`, `revoke`.
- **Браузер** (`@tsl/auth-client/browser`) — вход по authorization code + PKCE, автоматическое продление,
  `fetch` с токеном, выход.

## Пример: API на FastAPI

```python
from fastapi import FastAPI
from tsl_auth_client.fastapi import install, require, Principal

app = FastAPI()
install(app)   # verifier из TSL_AUTH_* и ответы 401/403 по контракту

@app.get("/orders")
def orders(user: Principal = require(permission="orders.read")):
    return {"user": user.username, "permissions": user.permissions}
```

Запуск: `TSL_AUTH_ISSUER=https://auth.corp/ TSL_AUTH_AUDIENCE=orders-api uvicorn app:app`.

## Пример: вызов другого API от имени пользователя (Go)

```go
tc, err := tslauth.NewTokenClient(tslauth.OptionsFromEnv())       // TSL_AUTH_CLIENT_ID / _SECRET
t, err := tc.Exchange(ctx, incomingToken, "billing-api")           // токен для billing-api с act.sub = наш client_id
req.Header.Set("Authorization", "Bearer "+t.AccessToken)
```

## Установка в закрытом контуре

Пакеты не тянут зависимостей из интернета (кроме Jackson у Java) и переносятся вместе с образами:

- в файлах релиза GitHub лежит `tsl-auth-sdk-<версия>.zip` — все пять пакетов и `SHA256SUMS`;
  `scripts/export-images.ps1 -Sdk` собирает тот же набор локально в `dist/sdk`;
- на GitFlic пакеты публикуются в реестр проекта `https://registry.gitflic.ru/project/uklad/tsl-auth/package/-/<nuget|npm|pypi|maven>`
  на каждом прогоне `main` с собственной версией `MAJOR.MINOR.<номер запуска CI>` из `sdk/VERSION` (публикует workflow `SDK`
  на GitHub через `scripts/publish-sdk-gitflic.sh`, секреты `GITFLIC_PKG_USER` / `GITFLIC_PKG_TOKEN`); версии GitFlic и GitHub не синхронизируются;
- локальная установка из файла: `dotnet nuget add source ./dist/sdk/nuget`, `npm install ./dist/sdk/npm/tsl-auth-client-<в>.tgz`,
  `pip install ./dist/sdk/pypi/tsl_auth_client-<в>-py3-none-any.whl`, `mvn install:install-file -Dfile=…jar -DpomFile=…pom`,
  Go — распаковать архив и добавить `replace github.com/akprof2000/tsl-auth/sdk/go => ./vendor-tsl-auth` в `go.mod`.

## Версии

На GitHub версия SDK совпадает с версией сервиса: тег `vX.Y.Z` собирает образ и пять пакетов одной версии (`sdk.yml`).
На GitFlic версии свои: `MAJOR.MINOR` из `sdk/VERSION` плюс номер запуска CI GitHub, образ и пакеты одного запуска имеют одну версию. SDK совместим с сервисом той же MAJOR-версии; правила
изменения контракта — в [релизной политике](release-policy.md).

## Тесты

`tests/sdk-contract/run.ps1` поднимает стенд из исходников, генерирует векторы (`make-vectors.py`: настоящие токены
и их испорченные варианты — чужая подпись, `alg=none`, `HS256`, неизвестный `kid`, чужая аудитория, просроченный по
переведённым часам) и запускает тесты всех пяти SDK; итог — таблица по SDK. Состав проверок — [контракт, §8](client-contract.md#8-контрактные-тесты).
