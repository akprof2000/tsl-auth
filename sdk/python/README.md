# tsl-auth-client — Python SDK для TSL Auth

Клиентская библиотека для API и сервисов на Python 3.10+: проверка access-токенов (RS256 по JWKS), principal с правами,
защита маршрутов для WSGI / FastAPI / Flask и клиент токенов. **Без зависимостей** — только стандартная библиотека
(RSA-подпись проверяется через `pow()` и сравнение PKCS#1 v1.5 за постоянное время), поэтому работает в закрытом контуре.
Поведение — строго по [контракту SDK](../../docs/client-contract.md); формат токена — в [integration.md](../../docs/integration.md).

## Установка

```bash
pip install tsl-auth-client            # ядро: Verifier, Principal, TokenClient, WSGI
pip install "tsl-auth-client[fastapi]" # + dependency для FastAPI
pip install "tsl-auth-client[flask]"   # + декоратор для Flask
```

В закрытом контуре: `pip download tsl-auth-client -d wheels/` снаружи, затем `pip install --no-index -f wheels/ tsl-auth-client`.
Из исходников репозитория: `pip install ./sdk/python`.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `TSL_AUTH_ISSUER` | — (обязательна) | Адрес сервиса, как в `iss` токена (`https://auth.corp/`) |
| `TSL_AUTH_AUDIENCE` | — | `client_id` этого API: токен принимается, только если `aud` его содержит |
| `TSL_AUTH_CLIENT_ID` / `TSL_AUTH_CLIENT_SECRET` | — | Приложение для `TokenClient` и introspection |
| `TSL_AUTH_JWKS_URI` | из discovery | Прямой адрес JWKS (стенды без discovery, тесты) |
| `TSL_AUTH_CLOCK_SKEW_SECONDS` | `30` | Допуск на расхождение часов для `exp`/`nbf` |
| `TSL_AUTH_JWKS_TTL_SECONDS` | `600` | Срок кэша ключей и discovery |
| `TSL_AUTH_JWKS_MIN_REFRESH_SECONDS` | `10` | Не чаще этого перечитывать JWKS по неизвестному `kid` |
| `TSL_AUTH_INTROSPECT` | `false` | После локальной проверки спрашивать `/connect/introspect` (мгновенный отзыв) |
| `TSL_AUTH_HTTP_TIMEOUT_SECONDS` | `10` | Таймаут HTTP-запросов к сервису |

Явные параметры имеют приоритет: `Options.from_env(audience="orders-api")`, либо целиком `Options(issuer=..., audience=...)`.
Часы инжектируются — `Options(now=lambda: ...)` (тестам нужно, и не только).

## Подключение одной строкой

**FastAPI**

```python
from fastapi import FastAPI
from tsl_auth_client import Principal
from tsl_auth_client.fastapi import install, require

app = FastAPI()
install(app)  # настройки из TSL_AUTH_*, discovery, обработчик 401/403 по контракту

@app.get("/orders")
def orders(principal: Principal = require(permission="orders.read")):
    return {"user": principal.username, "orders": []}

@app.post("/orders")
def create(principal: Principal = require(permission="orders.write", mfa=True)):
    ...
```

Principal также доступен как `request.state.auth`. Требования: `permission`, `any_permission=[...]`, `role`, `mfa=True`,
`subject_type="user"|"client"`.

**Flask**

```python
from flask import Flask, g
from tsl_auth_client.flask import protect

app = Flask(__name__)

@app.get("/orders")
@protect(permission="orders.read")
def orders():
    return {"user": g.auth.username}
```

**WSGI без фреймворка** (или любой WSGI-стек)

```python
from tsl_auth_client import TslAuthMiddleware, Verifier, protect
from tsl_auth_client.wsgi import principal_of

verifier = Verifier()                       # из окружения
app = TslAuthMiddleware(app, verifier, require={"permission": "orders.read"}, paths=["/api/"])

@protect(verifier, permission="orders.write")   # или декоратор на отдельный обработчик
def write_orders(environ, start_response):
    principal = principal_of(environ)
    ...
```

Отказы — ровно по контракту (§5): `401` с телом `{"error":"invalid_token","error_description":"<код>"}`,
`403` с `insufficient_permissions` / `insufficient_role` / `mfa_required` / `subject_type_not_allowed`,
заголовок `WWW-Authenticate: Bearer realm="tsl-auth", error="...", error_description="..."`.

## Проверка токена вручную

```python
from tsl_auth_client import Verifier, TslAuthError

verifier = Verifier()  # или Verifier(Options(issuer=..., audience=..., jwks_uri=...))
try:
    p = verifier.verify_authorization(request_headers.get("Authorization"))  # или verifier.verify(jwt)
    p.has_permission("orders.read"); p.has_role("operator"); p.is_mfa; p.actor; p.claims
except TslAuthError as e:
    print(e.code)  # missing | malformed | unsupported_alg | unknown_key | bad_signature | bad_issuer |
                   # expired | not_yet_valid | bad_audience | revoked | introspection_unavailable
```

`Principal`: `subject`, `subject_type`, `username`, `name`, `email`, `roles`, `permissions` (только этого API, без
префикса `<audience>:`), `all_roles`, `all_permissions`, `scopes`, `amr`, `actor`, `expires_at`, `claims`.
`has_permission("orders.read")` принимает только короткую форму.

## Клиент токенов

```python
from tsl_auth_client import TokenClient, TokenError

client = TokenClient()  # TSL_AUTH_ISSUER, TSL_AUTH_CLIENT_ID, TSL_AUTH_CLIENT_SECRET
try:
    svc = client.client_credentials(["orders-api"])      # кэш по scope до expires_at − 30 с, single-flight
    ex = client.exchange(user_access_token, ["orders-api"])  # token exchange, не кэшируется
    ts = client.refresh(refresh_token)                   # ts.refresh_token — новый, старый заменить немедленно
    client.password(username, password, ["openid", "offline_access", "orders-api"])
    client.authorization_code(code, redirect_uri, code_verifier)
    client.introspect(token)["active"]
    client.revoke(token)
except TokenError as e:
    e.error, e.error_description, e.status   # 'unavailable' — сеть или 5xx
```

`TokenSet`: `access_token`, `refresh_token`, `id_token`, `expires_at`, `scope`, `token_type`.

## Тесты

Контрактные тесты (`unittest`, без pytest) идут против живого TSL Auth и `tests/sdk-contract/vectors.json`
(путь — `SDK_CONTRACT_VECTORS`, по умолчанию `../../tests/sdk-contract/vectors.json`):

```bash
cd sdk/python
python -m unittest discover -s tests -v
```

Тесты FastAPI/Flask выполняются, если в окружении есть `fastapi`+`httpx` / `flask`, иначе пропускаются:

```bash
python -m venv .venv && .venv/Scripts/pip install fastapi httpx flask build   # Linux: .venv/bin/pip
.venv/Scripts/python -m unittest discover -s tests -v
```

Весь набор пяти SDK: `tests/sdk-contract/run.ps1`.

## Сборка

```bash
cd sdk/python && python -m build   # dist/tsl_auth_client-*.whl и .tar.gz
```

Версия в `pyproject.toml` — `0.0.0.dev0`; CI подставляет версию тега релиза.
