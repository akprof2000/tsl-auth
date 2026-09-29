"""Flask-декоратор (если flask установлен; иначе тест пропускается)."""
import unittest

from _support import case, load_vectors

from tsl_auth_client import Options, Verifier

try:
    import flask  # noqa: F401
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


@unittest.skipUnless(HAS_FLASK, "flask не установлен")
class FlaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from flask import Flask, g
        from tsl_auth_client.flask import protect

        cls.v = load_vectors()
        verifier = Verifier(Options(issuer=cls.v["issuer"], audience=cls.v["audience"], jwks_uri=cls.v["jwksUri"]))
        app = Flask("t")

        @app.get("/me")
        @protect(verifier=verifier)
        def me():
            return {"username": g.auth.username}

        @app.get("/orders/write")
        @protect(permission="orders.write", verifier=verifier)
        def write():
            return {"written": True}

        cls.client = app.test_client()

    def token(self, name):
        return {"Authorization": "Bearer " + case(self.v, name)["token"]}

    def test_flows(self):
        r = self.client.get("/me")
        self.assertEqual((r.status_code, r.get_json()), (401, {"error": "invalid_token", "error_description": "missing"}))
        self.assertEqual(r.headers["WWW-Authenticate"], 'Bearer realm="tsl-auth", error="invalid_token", error_description="missing"')
        r = self.client.get("/orders/write", headers=self.token("ok_viewer"))
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "insufficient_permissions"))
        r = self.client.get("/me", headers=self.token("ok_user"))
        self.assertEqual((r.status_code, r.get_json()), (200, {"username": "sdk-operator"}))


if __name__ == "__main__":
    unittest.main()
