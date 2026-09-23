"""Демо Python-приложение для TSL Auth (только стандартная библиотека — работает в закрытом контуре).

Что показывает:
  * App API (самоуправление): приложение само заводит своих пользователей и назначает им СВОИ роли
    (client_credentials, scope tsl-auth-app);
  * вход по паролю (password grant) через серверную HTML-форму + refresh-токен;
  * проверку JWT RS256 по JWKS (RSA PKCS#1 v1.5 реализована через pow() — без pip-зависимостей);
  * introspection access-токена (для сервисов, которым нужен мгновенный отзыв).

Переменные: AUTH_ISSUER, CLIENT_ID (demo-python), CLIENT_SECRET, PORT (5104).
"""
import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ISSUER = os.environ.get("AUTH_ISSUER", "http://localhost:8080/")
BASE = ISSUER.rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-python")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
PORT = int(os.environ.get("PORT", "5104"))

SESSIONS: dict[str, dict] = {}  # демо: сессии в памяти процесса
_jwks: dict = {"keys": {}, "at": 0.0}
_app_token: dict = {"token": None, "exp": 0.0}


# ---------- HTTP-клиент ----------
def http(method: str, url: str, form: dict | None = None, body: dict | None = None, token: str | None = None):
    # Возвращает (статус, JSON); ошибки HTTP не бросаются, а возвращаются как ответ — демо показывает их пользователю.
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
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"error": raw.decode(errors="replace")}


def token_request(**form):
    return http("POST", f"{BASE}/connect/token", form={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, **form})


def app_token() -> str:
    """Токен самого приложения для App API (кэшируется до истечения)."""
    # Обновляем заранее, за 30 с до истечения, чтобы токен не протух во время запроса.
    if _app_token["token"] and time.time() < _app_token["exp"] - 30:
        return _app_token["token"]
    status, body = token_request(grant_type="client_credentials", scope="tsl-auth-app")
    if status != 200:
        raise RuntimeError(f"client_credentials: {body}")
    _app_token.update(token=body["access_token"], exp=time.time() + body["expires_in"])
    return body["access_token"]


def app_api(method: str, path: str, body: dict | list | None = None):
    return http(method, f"{BASE}/api/app{path}", body=body, token=app_token())


# ---------- JWT RS256 без сторонних библиотек ----------
def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_key(kid: str):
    # Кэш ключей (n, e): перечитываем JWKS при неизвестном kid (ротация ключей) или раз в 10 минут.
    if kid not in _jwks["keys"] or time.time() - _jwks["at"] > 600:
        _, disco = http("GET", f"{BASE}/.well-known/openid-configuration")
        _, jwks = http("GET", disco["jwks_uri"])
        _jwks["keys"] = {k["kid"]: (int.from_bytes(b64d(k["n"]), "big"), int.from_bytes(b64d(k["e"]), "big"))
                         for k in jwks["keys"] if k["kty"] == "RSA"}
        _jwks["at"] = time.time()
    return _jwks["keys"][kid]


SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")  # DigestInfo для SHA-256


def validate_jwt(token: str, audience: str) -> dict:
    h, p, s = token.split(".")
    header = json.loads(b64d(h))
    if header.get("alg") != "RS256":
        raise ValueError("unsupported alg")
    n, e = jwk_key(header["kid"])
    # RSA-проверка "вручную": signature^e mod n даёт закодированное сообщение (EM) длиной k байт.
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(b64d(s), "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(f"{h}.{p}".encode()).digest()
    # Ожидаемый EM по PKCS#1 v1.5: 00 01 FF..FF 00 DigestInfo(SHA-256) хеш. Сравниваем целиком и за
    # постоянное время — полное сравнение исключает атаки с подделкой подписи через разбор паддинга.
    expected =b"\x00\x01" + b"\xff" * (k - 3 - len(SHA256_PREFIX) - len(digest)) + b"\x00" + SHA256_PREFIX + digest
    if not secrets.compare_digest(em, expected):
        raise ValueError("bad signature")
    claims = json.loads(b64d(p))
    # После подписи — iss (наш сервер), aud (токен выдан для этого приложения), exp (допуск 30 с на расхождение часов).
    aud = claims.get("aud")
    if claims.get("iss") != ISSUER:
        raise ValueError("bad issuer")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("wrong audience")
    if time.time() > claims["exp"] + 30:
        raise ValueError("expired")
    return claims


def as_list(v):
    return v if isinstance(v, list) else [] if v is None else [v]


# ---------- Веб-интерфейс (серверный рендеринг) ----------
PAGE = """<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>Демо Python</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#fff8e6;color:#3a2a00}}
header{{background:#b7791f;color:#fff;padding:14px 20px}}main{{max-width:980px;margin:0 auto;padding:20px}}
.card{{background:#fff;border:1px solid #efd9a8;border-radius:8px;padding:16px;margin-bottom:16px}}
input,select{{padding:6px 8px;margin:2px 4px 2px 0}}button{{padding:6px 12px;border-radius:6px;border:1px solid #b7791f;background:#b7791f;color:#fff;cursor:pointer}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #eee;padding:6px;text-align:left;font-size:14px}}
pre{{background:#fffdf5;border:1px solid #efd9a8;padding:10px;overflow:auto;font-size:12px;max-height:300px}}.msg{{color:#9a3412}}</style>
</head><body><header><b>Демо Python</b> · client_id <code>{client}</code></header><main>{body}</main></body></html>"""


def render_home(session: dict | None, message: str = "") -> str:
    parts = [f'<p class="msg">{html.escape(message)}</p>' if message else ""]

    # 1) Вход пользователя (password grant) и проверка токена
    if session:
        claims = session["claims"]
        parts.append(f"""<div class="card"><b>Вы вошли как {html.escape(str(claims.get('preferred_username')))}</b>
        <p>Разрешения в этом приложении: {html.escape(', '.join(as_list(claims.get('permissions'))) or 'нет')}</p>
        <form method="post" action="/refresh" style="display:inline"><button>Обновить токен (refresh)</button></form>
        <form method="post" action="/introspect" style="display:inline"><button>Introspection</button></form>
        <form method="post" action="/logout" style="display:inline"><button>Выйти</button></form>
        <pre>{html.escape(json.dumps(claims, ensure_ascii=False, indent=2))}</pre></div>""")
    else:
        parts.append("""<div class="card"><b>Вход (password grant)</b><form method="post" action="/login">
        <input name="username" placeholder="логин" required><input name="password" type="password" placeholder="пароль" required>
        <button>Войти</button></form></div>""")

    # 2) Управление своими пользователями через App API
    status, users = app_api("GET", "/users")
    _, matrix = app_api("GET", "/matrix")
    role_names = [r["name"] for r in (matrix or {}).get("roles", [])]
    rows = "".join(
        f"<tr><td>{html.escape(u['userName'])}</td><td>{html.escape(u.get('email') or '')}</td>"
        f"<td>{html.escape(', '.join(u['roles']))}</td><td>{'да' if u['createdByThisApp'] else 'нет'}</td>"
        f"<td><form method='post' action='/users/delete'><input type='hidden' name='id' value='{u['id']}'><button>Удалить/отвязать</button></form></td></tr>"
        for u in (users or []) if status == 200)
    options = "".join(f"<option>{html.escape(r)}</option>" for r in role_names)
    parts.append(f"""<div class="card"><b>Мои пользователи (App API)</b> <span class="msg">HTTP {status}</span>
    <table><tr><th>Логин</th><th>Email</th><th>Роли в этом приложении</th><th>Создан мной</th><th></th></tr>{rows}</table>
    <h4>Создать пользователя</h4><form method="post" action="/users/create">
    <input name="userName" placeholder="логин" required><input name="email" placeholder="email">
    <select name="role"><option value="">без роли</option>{options}</select><button>Создать (временный пароль)</button></form>
    <h4>Роли и матрица приложения</h4><pre>{html.escape(json.dumps(matrix, ensure_ascii=False, indent=2))}</pre></div>""")
    return PAGE.format(client=CLIENT_ID, body="".join(parts))


class Handler(BaseHTTPRequestHandler):
    # Серверная сессия: браузер хранит лишь случайный sid в cookie, токены остаются на сервере (в SESSIONS).
    def session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie["sid"].value if "sid" in cookie else None
        return sid, SESSIONS.get(sid) if sid else None

    def form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}

    def page(self, text: str, status: int = 200, cookie: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(text.encode())

    def redirect(self, message: str = ""):
        self.send_response(303)
        self.send_header("Location", "/?m=" + urllib.parse.quote(message))
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/health"):
            return self.page("ok")
        _, session = self.session()
        msg = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("m", [""])[0]
        try:
            self.page(render_home(session, msg))
        except Exception as e:  # демо: показываем ошибку как есть
            self.page(f"<pre>{html.escape(repr(e))}</pre>", 500)

    def do_POST(self):
        sid, session = self.session()
        f = self.form()
        if self.path == "/login":
            status, body = token_request(grant_type="password", username=f["username"], password=f["password"],
                                         scope="openid profile offline_access")
            if status != 200:
                return self.redirect(f"Ошибка входа: {body.get('error_description', body)}")
            sid = secrets.token_urlsafe(24)
            SESSIONS[sid] = {"tokens": body, "claims": validate_jwt(body["access_token"], CLIENT_ID)}
            # HttpOnly — cookie недоступна из JS (XSS), SameSite=Lax — не отправляется с чужих POST (CSRF).
            self.send_response(303)
            self.send_header("Set-Cookie", f"sid={sid}; HttpOnly; SameSite=Lax; Path=/")
            self.send_header("Location", "/?m=" + urllib.parse.quote("Вход выполнен, подпись JWT проверена по JWKS."))
            return self.end_headers()
        if self.path == "/refresh" and session:
            status, body = token_request(grant_type="refresh_token", refresh_token=session["tokens"]["refresh_token"])
            if status != 200:
                SESSIONS.pop(sid, None)
                return self.redirect(f"Refresh не удался (сессия отозвана?): {body.get('error_description')}")
            session.update(tokens=body, claims=validate_jwt(body["access_token"], CLIENT_ID))
            return self.redirect("Токен обновлён через refresh_token.")
        if self.path == "/introspect" and session:
            # Introspection спрашивает сервер, активен ли токен сейчас: в отличие от локальной
            # проверки JWT, отзыв (logout, блокировка пользователя) виден сразу.
            _, body = http("POST", f"{BASE}/connect/introspect", form={
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "token": session["tokens"]["access_token"]})
            return self.redirect(f"Introspection: active={body.get('active')}")
        if self.path == "/logout":
            if session:
                # Отзываем refresh-токен (RFC 7009), чтобы его нельзя было использовать после выхода.
                http("POST", f"{BASE}/connect/revoke", form={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                                                               "token": session["tokens"].get("refresh_token", "")})
            SESSIONS.pop(sid, None)
            return self.redirect("Вы вышли (refresh-токен отозван).")
        if self.path == "/users/create":
            status, body = app_api("POST", "/users", {"userName": f["userName"], "email": f.get("email") or None,
                                                      "roles": [f["role"]] if f.get("role") else []})
            if status != 201:
                return self.redirect(f"Ошибка: {body.get('detail', body)}")
            return self.redirect(f"Создан {body['user']['userName']}, временный пароль: {body['temporaryPassword']}")
        if self.path == "/users/delete":
            status, body = app_api("DELETE", f"/users/{f['id']}")
            return self.redirect(f"Удаление: HTTP {status} {body}")
        self.redirect("Неизвестное действие")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"python-app on :{PORT} (client_id={CLIENT_ID}, iss={ISSUER})", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()
