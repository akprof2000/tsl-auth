"""FastAPI dependency (если fastapi установлен; иначе тест пропускается)."""
import unittest

from _support import case, load_vectors

from tsl_auth_client import Options, Principal, Verifier

try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:  # httpx тоже нужен для TestClient
    HAS_FASTAPI = False


@unittest.skipUnless(HAS_FASTAPI, "fastapi/httpx не установлены")
class FastApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi import FastAPI, Request
        from tsl_auth_client.fastapi import install, require

        cls.v = load_vectors()
        app = FastAPI()
        install(app, Verifier(Options(issuer=cls.v["issuer"], audience=cls.v["audience"], jwks_uri=cls.v["jwksUri"])))

        @app.get("/me")
        def me(request: Request, principal: Principal = require()):
            assert request.state.auth is principal
            return {"username": principal.username}

        @app.get("/orders")
        def orders(principal: Principal = require(permission="orders.read")):
            return {"orders": []}

        @app.get("/orders/write")
        def orders_write(principal: Principal = require(permission="orders.write")):
            return {"written": True}

        @app.get("/any")
        def any_perm(principal: Principal = require(any_permission=["orders.write", "orders.admin"])):
            return {}

        cls.client = TestClient(app)

    def token(self, name):
        return {"Authorization": "Bearer " + case(self.v, name)["token"]}

    def test_missing(self):
        r = self.client.get("/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json(), {"error": "invalid_token", "error_description": "missing"})
        self.assertEqual(r.headers["www-authenticate"], 'Bearer realm="tsl-auth", error="invalid_token", error_description="missing"')
        self.assertTrue(r.headers["content-type"].startswith("application/json"))

    def test_bad_token(self):
        r = self.client.get("/me", headers=self.token("tampered_payload"))
        self.assertEqual((r.status_code, r.json()["error_description"]), (401, "bad_signature"))

    def test_forbidden(self):
        r = self.client.get("/orders/write", headers=self.token("ok_viewer"))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json(), {"error": "insufficient_permissions", "error_description": f"{self.v['audience']}:orders.write"})
        self.assertIn('error="insufficient_permissions"', r.headers["www-authenticate"])
        r = self.client.get("/any", headers=self.token("ok_viewer"))
        self.assertEqual(r.status_code, 403)

    def test_ok(self):
        r = self.client.get("/me", headers=self.token("ok_user"))
        self.assertEqual((r.status_code, r.json()), (200, {"username": "sdk-operator"}))
        self.assertEqual(self.client.get("/orders", headers=self.token("ok_viewer")).status_code, 200)
        self.assertEqual(self.client.get("/orders/write", headers=self.token("ok_user")).status_code, 200)
        self.assertEqual(self.client.get("/any", headers=self.token("ok_user")).status_code, 200)


if __name__ == "__main__":
    unittest.main()
