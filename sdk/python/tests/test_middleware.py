"""Middleware (docs/client-contract.md §5, §8 п. 3): реальный WSGI-сервер на свободном порту."""
import json
import threading
import unittest
import urllib.error
import urllib.request
from wsgiref.simple_server import WSGIServer, make_server

from _support import case, load_vectors

from tsl_auth_client import Options, TslAuthMiddleware, Verifier, protect
from tsl_auth_client.wsgi import principal_of


class _QuietServer(WSGIServer):
    def handle_error(self, request, client_address):
        pass


def build_app(verifier: Verifier):
    def json_response(start_response, status: str, payload: dict):
        body = json.dumps(payload).encode()
        start_response(status, [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]

    @protect(verifier)
    def me(environ, start_response):
        return json_response(start_response, "200 OK", {"username": principal_of(environ).username})

    @protect(verifier, permission="orders.read")
    def orders(environ, start_response):
        return json_response(start_response, "200 OK", {"orders": []})

    @protect(verifier, permission="orders.write")
    def orders_write(environ, start_response):
        return json_response(start_response, "200 OK", {"written": True})

    @protect(verifier, role="operator", mfa=True)
    def admin(environ, start_response):
        return json_response(start_response, "200 OK", {})

    @protect(verifier, subject_type="client")
    def service(environ, start_response):
        return json_response(start_response, "200 OK", {})

    routes = {"/me": me, "/orders": orders, "/orders/write": orders_write, "/admin": admin, "/service": service}

    def app(environ, start_response):
        handler = routes.get(environ.get("PATH_INFO", ""))
        if handler is None:
            return json_response(start_response, "404 Not Found", {"error": "not_found"})
        return handler(environ, start_response)

    return app


class MiddlewareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()
        cls.verifier = Verifier(Options(issuer=cls.v["issuer"], audience=cls.v["audience"], jwks_uri=cls.v["jwksUri"]))
        cls.server = make_server("127.0.0.1", 0, build_app(cls.verifier), server_class=_QuietServer)
        cls.server.RequestHandlerClass.log_message = lambda *a, **k: None
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path: str, token: str | None = None, header: str | None = None):
        req = urllib.request.Request(self.base + path)
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        if header is not None:
            req.add_header("Authorization", header)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers), json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), json.loads(e.read())

    def token(self, name: str) -> str:
        return case(self.v, name)["token"]

    def test_missing_token(self):
        status, headers, body = self.get("/me")
        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "invalid_token", "error_description": "missing"})
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="tsl-auth", error="invalid_token", error_description="missing"')
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        # Пустой Bearer — тоже missing.
        status, _, body = self.get("/me", header="Bearer ")
        self.assertEqual((status, body["error_description"]), (401, "missing"))

    def test_broken_tokens(self):
        for name in ("garbage", "tampered_payload", "alg_none", "unknown_kid", "wrong_audience"):
            with self.subTest(case=name):
                status, headers, body = self.get("/me", self.token(name))
                self.assertEqual(status, 401)
                self.assertEqual(body["error"], "invalid_token")
                self.assertEqual(body["error_description"], case(self.v, name)["expect"])
                self.assertIn(f'error_description="{case(self.v, name)["expect"]}"', headers["WWW-Authenticate"])

    def test_forbidden_permission(self):
        status, headers, body = self.get("/orders/write", self.token("ok_viewer"))
        self.assertEqual(status, 403)
        self.assertEqual(body, {"error": "insufficient_permissions", "error_description": f"{self.v['audience']}:orders.write"})
        self.assertEqual(headers["WWW-Authenticate"],
                         f'Bearer realm="tsl-auth", error="insufficient_permissions", error_description="{self.v["audience"]}:orders.write"')

    def test_ok(self):
        status, _, body = self.get("/me", self.token("ok_user"))
        self.assertEqual((status, body), (200, {"username": self.v["expected"]["ok_user"]["username"]}))
        self.assertEqual(self.get("/orders", self.token("ok_viewer"))[0], 200)
        self.assertEqual(self.get("/orders/write", self.token("ok_user"))[0], 200)

    def test_role_mfa_subject_type(self):
        status, headers, body = self.get("/admin", self.token("ok_viewer"))
        self.assertEqual((status, body["error"]), (403, "insufficient_role"))
        self.assertIn('error="insufficient_role"', headers["WWW-Authenticate"])
        status, _, body = self.get("/admin", self.token("ok_user"))  # роль есть, MFA нет
        self.assertEqual((status, body["error"]), (403, "mfa_required"))
        status, _, body = self.get("/service", self.token("ok_user"))
        self.assertEqual((status, body), (403, {"error": "subject_type_not_allowed", "error_description": "client"}))
        self.assertEqual(self.get("/service", self.token("ok_client"))[0], 200)

    def test_middleware_class_with_paths(self):
        calls = []

        def inner(environ, start_response):
            calls.append(principal_of(environ))
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        app = TslAuthMiddleware(inner, self.verifier, require={"permission": "orders.read"}, paths=["/api/"])
        captured = {}

        def start_response(status, headers):
            captured["status"], captured["headers"] = status, dict(headers)

        body = b"".join(app({"PATH_INFO": "/public"}, start_response))
        self.assertEqual((captured["status"], body), ("200 OK", b"ok"))
        self.assertIsNone(calls[-1])
        app({"PATH_INFO": "/api/x"}, start_response)
        self.assertEqual(captured["status"], "401 Unauthorized")
        body = b"".join(app({"PATH_INFO": "/api/x", "HTTP_AUTHORIZATION": f"Bearer {self.token('ok_viewer')}"}, start_response))
        self.assertEqual((captured["status"], body), ("200 OK", b"ok"))
        self.assertEqual(calls[-1].username, "sdk-viewer")


if __name__ == "__main__":
    unittest.main()
