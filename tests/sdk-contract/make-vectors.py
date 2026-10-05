"""Генератор контрактных векторов для SDK (docs/client-contract.md, §8).

Через Admin API живого TSL Auth создаёт приложение-API sdk-contract-api, клиент sdk-contract-client и двух
пользователей, получает настоящие токены и строит из них испорченные варианты. Результат — vectors.json,
который читают контрактные тесты всех пяти SDK. Только стандартная библиотека.

Переменные: TSL_AUTH_ISSUER (http://localhost:8080), ADMIN_CLIENT_ID (admin-cli), ADMIN_CLIENT_SECRET,
OUT (tests/sdk-contract/vectors.json).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

ISSUER = os.environ.get("TSL_AUTH_ISSUER", "http://localhost:8080/")
BASE = ISSUER.rstrip("/")
ADMIN_ID = os.environ.get("ADMIN_CLIENT_ID", "admin-cli")
ADMIN_SECRET = os.environ.get("ADMIN_CLIENT_SECRET", "sample-admin-cli-secret-2026")
OUT = os.environ.get("OUT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json"))

API = "sdk-contract-api"
CLIENT = "sdk-contract-client"
# Владелец подчинённых клиентов: SDK регистрируют подчинённого со своим ключом и входят по private_key_jwt.
OWNER = "sdk-contract-owner"
OWNER_PREFIX = "sdk-agent-"
# Сервис-робот: работает вместо пользователя по токену подключения, который пользователь выписал ему в «Мои токены».
ROBOT = "sdk-contract-robot"
# Пароли пользователей генерируются на каждый запуск: в репозитории литеральных паролей нет.
PASSWORD = "Sdk-" + secrets.token_urlsafe(12) + "!1"


def http(method, url, form=None, body=None, token=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"error": raw.decode(errors="replace")}


def token(**form):
    status, body = http("POST", f"{BASE}/connect/token", form=form)
    if status != 200:
        sys.exit(f"token {form.get('grant_type')}: {status} {body}")
    return body


admin = token(grant_type="client_credentials", client_id=ADMIN_ID, client_secret=ADMIN_SECRET, scope="tsl-auth-admin")["access_token"]


def api(method, path, body=None, ok=(200, 201, 204)):
    status, data = http(method, f"{BASE}/api/admin{path}", body=body, token=admin)
    if status not in ok:
        sys.exit(f"{method} {path}: {status} {data}")
    return data


def upsert_app(app):
    status, _ = http("GET", f"{BASE}/api/admin/applications/{app['clientId']}", token=admin)
    if status == 200:
        api("PUT", f"/applications/{app['clientId']}", app)
        # Секрет существующего клиента неизвестен — перевыпускаем, чтобы vectors.json всегда содержал рабочий.
        if app["clientType"] == "confidential":
            return api("POST", f"/applications/{app['clientId']}/secret")["clientSecret"]
        return None
    return api("POST", "/applications", app)["clientSecret"]


# --- Приложения ---
upsert_app({"clientId": API, "displayName": "SDK contract API", "clientType": "public", "grantTypes": []})
matrix = api("GET", f"/applications/{API}/matrix")
for p in ("orders.read", "orders.write"):
    if p not in [x["name"] for x in matrix["permissions"]]:
        api("POST", f"/applications/{API}/permissions", {"name": p})
for role, perms in (("viewer", ["orders.read"]), ("operator", ["orders.read", "orders.write"])):
    if role not in [x["name"] for x in matrix["roles"]]:
        api("POST", f"/applications/{API}/roles", {"name": role, "displayName": role, "permissions": perms})
    else:
        api("PUT", f"/applications/{API}/roles/{role}/permissions", perms)

client_secret = upsert_app({
    "clientId": CLIENT, "displayName": "SDK contract client", "clientType": "confidential",
    "grantTypes": ["password", "refresh_token", "client_credentials", "token_exchange"], "scopes": [API]})
# Сервисная роль клиента в API — для ok_client (client_credentials со scope API).
api("PUT", f"/applications/{CLIENT}/service-roles", [{"clientId": API, "role": "operator"}])
# Токены живут час: vectors.json должен пережить прогон тестов пяти SDK (по умолчанию access-токен — 15 минут).
# Срок приложения не может превышать глобальный, поэтому поднимается глобальная настройка тестового стенда.
settings = api("GET", "/settings")
policy = dict(settings.get("tokenPolicy") or {})
if policy.get("accessTokenMinutes", 15) < 60 or policy.get("exchangeTokenMinutes", 15) < 60:
    policy["accessTokenMinutes"] = max(60, policy.get("accessTokenMinutes", 15))
    policy["exchangeTokenMinutes"] = max(60, policy.get("exchangeTokenMinutes", 15))
    api("PUT", "/settings", {**settings, "tokenPolicy": policy})

# --- Владелец подчинённых клиентов (private_key_jwt в SDK) ---
owner_secret = upsert_app({
    "clientId": OWNER, "displayName": "SDK contract owner", "clientType": "confidential",
    "grantTypes": ["client_credentials", "token_exchange"], "selfManagement": True})
owner_matrix = api("GET", f"/applications/{OWNER}/matrix")
if "upload" not in [x["name"] for x in owner_matrix["permissions"]]:
    api("POST", f"/applications/{OWNER}/permissions", {"name": "upload"})
if "uploader" not in [x["name"] for x in owner_matrix["roles"]]:
    api("POST", f"/applications/{OWNER}/roles", {"name": "uploader", "displayName": "uploader", "permissions": ["upload"]})
# requireDelegation=False: контрактные тесты создают подчинённых сервисным токеном владельца (тестовый стенд).
api("PUT", f"/applications/{OWNER}/managed-clients-policy", {
    "prefix": OWNER_PREFIX, "roles": ["uploader"], "authMethods": ["private_key_jwt", "client_secret"],
    "maxClients": 500, "accessTokenLifetime": 5, "requireDelegation": False})

# --- Сервис-робот (токен подключения пользователя) ---
robot_secret = upsert_app({
    "clientId": ROBOT, "displayName": "SDK contract robot", "clientType": "confidential", "grantTypes": ["connection_token"]})

# --- Пользователи ---
for name, role in (("sdk-operator", "operator"), ("sdk-viewer", "viewer")):
    found = api("GET", f"/users?search={name}")
    body = {"userName": name, "email": f"{name}@tsl.local", "displayName": name, "isActive": True,
            "roles": [{"clientId": API, "role": role}]}
    if found["total"] == 0:
        body["password"] = PASSWORD
        api("POST", "/users", body)
    else:
        uid = found["items"][0]["id"]
        api("PUT", f"/users/{uid}", body)
        api("POST", f"/users/{uid}/password", {"password": PASSWORD})

# --- Токены ---
def user_token(name):
    return token(grant_type="password", client_id=CLIENT, client_secret=client_secret, username=name, password=PASSWORD, scope=f"openid {API}")


ok_user = user_token("sdk-operator")["access_token"]
ok_viewer = user_token("sdk-viewer")["access_token"]
ok_client = token(grant_type="client_credentials", client_id=CLIENT, client_secret=client_secret, scope=API)["access_token"]
wrong_aud = token(grant_type="client_credentials", client_id=CLIENT, client_secret=client_secret)["access_token"]
exchanged = token(grant_type="urn:ietf:params:oauth:grant-type:token-exchange", client_id=CLIENT, client_secret=client_secret,
                  subject_token=ok_user, subject_token_type="urn:ietf:params:oauth:token-type:access_token", scope=API)["access_token"]



def connection_token(username, robot):
    """Пользователь выписывает роботу токен подключения так же, как в браузере: вход и форма «Мои токены»."""
    jar = CookieJar()
    web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def page(path, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        with web.open(urllib.request.Request(f"{BASE}{path}", data=data), timeout=20) as r:
            return r.read().decode()

    def antiforgery(html):
        return re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', html).group(1)

    login = page("/Account/Login")
    page("/Account/Login", {"Login": username, "Password": PASSWORD, "__RequestVerificationToken": antiforgery(login)})
    tokens = page("/Account/Tokens")
    created = page("/Account/Tokens?handler=Create", {
        "Name": "sdk-contract", "ClientId": robot, "AllApplications": "true", "ExpiresInDays": "1",
        "__RequestVerificationToken": antiforgery(tokens)})
    found = re.search(r'<code id="pat-secret">([^<]+)</code>', created)
    if not found:
        sys.exit(f"токен подключения для {username} не выпущен: {re.findall(r'class="alert[^"]*">([^<]+)', created)}")
    return found.group(1)


# Прежние токены sdk-operator отзываются: иначе прогоны упрутся в лимит активных токенов пользователя.
operator_id = api("GET", "/users?search=sdk-operator")["items"][0]["id"]
for t in api("GET", f"/users/{operator_id}/tokens"):
    if t["isActive"]:
        api("DELETE", f"/users/{operator_id}/tokens/{t['id']}")
robot_token = connection_token("sdk-operator", ROBOT)

# --- Испорченные варианты ---
def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def parts(t):
    h, p, s = t.split(".")
    return json.loads(b64d(h)), json.loads(b64d(p)), s


def rebuild(header, payload, sig):
    return ".".join([b64e(json.dumps(header, separators=(",", ":")).encode()),
                     b64e(json.dumps(payload, separators=(",", ":")).encode()), sig])


hdr, pl, sig = parts(ok_user)

tampered_payload = dict(pl); tampered_payload["permissions"] = [f"{API}:orders.read", f"{API}:orders.write", f"{API}:admin"]
tampered_issuer = dict(pl); tampered_issuer["iss"] = "https://evil.example/"
alg_none = rebuild({**hdr, "alg": "none"}, pl, "")
no_kid = rebuild({k: v for k, v in hdr.items() if k != "kid"}, pl, sig)
unknown_kid = rebuild({**hdr, "kid": "no-such-key-" + secrets.token_hex(4)}, pl, sig)

# HS256 «атака подменой алгоритма»: подписываем открытым ключом (PEM-подобной строкой n) как HMAC-секретом.
_, disco = http("GET", f"{BASE}/.well-known/openid-configuration")
_, jwks = http("GET", disco["jwks_uri"])
key = next(k for k in jwks["keys"] if k["kid"] == hdr["kid"])
hs_head = b64e(json.dumps({**hdr, "alg": "HS256"}, separators=(",", ":")).encode())
hs_body = b64e(json.dumps(pl, separators=(",", ":")).encode())
hs_sig = b64e(hmac.new(key["n"].encode(), f"{hs_head}.{hs_body}".encode(), hashlib.sha256).digest())
alg_hs256 = f"{hs_head}.{hs_body}.{hs_sig}"

cases = [
    {"name": "ok_user", "token": ok_user, "expect": "ok"},
    {"name": "ok_viewer", "token": ok_viewer, "expect": "ok"},
    {"name": "ok_client", "token": ok_client, "expect": "ok"},
    {"name": "ok_exchanged", "token": exchanged, "expect": "ok"},
    {"name": "wrong_audience", "token": wrong_aud, "expect": "bad_audience"},
    {"name": "tampered_payload", "token": rebuild(hdr, tampered_payload, sig), "expect": "bad_signature"},
    {"name": "tampered_issuer", "token": rebuild(hdr, tampered_issuer, sig), "expect": "bad_signature"},
    {"name": "alg_none", "token": alg_none, "expect": "unsupported_alg"},
    {"name": "alg_hs256", "token": alg_hs256, "expect": "unsupported_alg"},
    {"name": "unknown_kid", "token": unknown_kid, "expect": "unknown_key"},
    {"name": "no_kid", "token": no_kid, "expect": "malformed"},
    {"name": "two_parts", "token": ok_user.rsplit(".", 1)[0], "expect": "malformed"},
    {"name": "garbage", "token": "not.a.jwt", "expect": "malformed"},
    {"name": "empty", "token": "", "expect": "malformed"},
    # Часы SDK: expired — now = exp + 60; not_yet_valid — now = iat - 120 (пропускается, если нет nbf).
    {"name": "expired", "token": ok_user, "expect": "expired", "now": pl["exp"] + 60},
    {"name": "not_yet_valid", "token": ok_user, "expect": "not_yet_valid", "now": pl.get("iat", pl["exp"]) - 120, "skipIfNoNbf": "nbf" not in pl},
    # SDK настроен на другой issuer, JWKS — по прямому адресу.
    {"name": "bad_issuer", "token": ok_user, "expect": "bad_issuer", "issuer": "https://other.example/"},
]

vectors = {
    "issuer": ISSUER, "audience": API, "jwksUri": disco["jwks_uri"],
    "client": {"id": CLIENT, "secret": client_secret},
    "managedOwner": {"id": OWNER, "secret": owner_secret, "prefix": OWNER_PREFIX, "role": "uploader"},
    # Робот обменивает токен подключения sdk-operator (все приложения пользователя) своим секретом.
    "robot": {"id": ROBOT, "secret": robot_secret, "connectionToken": robot_token},
    "users": {"operator": {"username": "sdk-operator", "password": PASSWORD}, "viewer": {"username": "sdk-viewer", "password": PASSWORD}},
    "expected": {
        "ok_user": {"subjectType": "user", "username": "sdk-operator", "permissions": ["orders.read", "orders.write"], "roles": ["operator"]},
        "ok_viewer": {"subjectType": "user", "username": "sdk-viewer", "permissions": ["orders.read"], "roles": ["viewer"]},
        "ok_client": {"subjectType": "client", "subject": CLIENT},
        "ok_exchanged": {"actorSub": CLIENT},
        "robot": {"subjectType": "user", "username": "sdk-operator", "actorSub": ROBOT, "permissions": ["orders.read", "orders.write"]},
    },
    "cases": cases,
}
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(vectors, f, ensure_ascii=False, indent=2)
print(f"vectors: {len(cases)} cases -> {OUT}")
