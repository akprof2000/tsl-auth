"""Живые сценарии против стенда (docs/client-contract.md §8, п. 3), кроме middleware (test_middleware.py)."""
import json
import time
import unittest
import urllib.request

from _support import JwksStub, case, load_vectors

from tsl_auth_client import Options, TokenClient, TokenError, TslAuthError, Verifier


class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()

    def options(self, **kw) -> Options:
        v = self.v
        base = dict(issuer=v["issuer"], audience=v["audience"], client_id=v["client"]["id"], client_secret=v["client"]["secret"])
        base.update(kw)
        return Options(**base)

    def user_tokens(self, who="operator", scopes=("openid", "offline_access", None)):
        u = self.v["users"][who]
        scope = [s for s in scopes if s] + [self.v["audience"]]
        return TokenClient(self.options()).password(u["username"], u["password"], scope)

    def test_refresh_rotation(self):
        client = TokenClient(self.options())
        first = self.user_tokens()
        self.assertTrue(first.refresh_token, "password grant с offline_access должен вернуть refresh_token")
        second = client.refresh(first.refresh_token)
        self.assertTrue(second.refresh_token)
        self.assertNotEqual(second.refresh_token, first.refresh_token, "ротация: новый refresh_token")
        third = client.refresh(second.refresh_token)  # новый работает повторно
        self.assertTrue(third.access_token)
        client.revoke(third.refresh_token)
        with self.assertRaises(TokenError) as ctx:
            client.refresh(third.refresh_token)
        self.assertEqual(ctx.exception.error, "invalid_grant")
        self.assertEqual(ctx.exception.status, 400)

    def test_introspection_revoked(self):
        tokens = self.user_tokens()
        client = TokenClient(self.options())
        verifier = Verifier(self.options(introspect=True))
        self.assertEqual(verifier.verify(tokens.access_token).username, self.v["users"]["operator"]["username"])
        self.assertTrue(client.introspect(tokens.access_token)["active"])
        client.revoke(tokens.access_token)
        with self.assertRaises(TslAuthError) as ctx:
            verifier.verify(tokens.access_token)
        self.assertEqual(ctx.exception.code, "revoked")
        # Без introspection локальная проверка по-прежнему проходит — отзыв виден только через introspect.
        self.assertTrue(Verifier(self.options()).verify(tokens.access_token))

    def test_connection_token_robot(self):
        """§6 токен подключения: робот своим секретом получает JWT с правами пользователя и act = робот; клиент без потока connection_token — unauthorized_client."""
        robot = self.v.get("robot")
        if not robot:
            self.skipTest("в vectors.json нет robot — обновите make-vectors.py")
        expected = self.v["expected"]["robot"]
        client = TokenClient(self.options(client_id=robot["id"], client_secret=robot["secret"]))
        tokens = client.connection_token(robot["connectionToken"])
        self.assertIs(tokens, client.connection_token(robot["connectionToken"]), "повторный вызов — из кэша")
        self.assertFalse(tokens.refresh_token)
        p = Verifier(self.options()).verify(tokens.access_token)
        self.assertEqual(p.subject_type, expected["subjectType"])
        self.assertEqual(p.username, expected["username"])
        self.assertEqual((p.actor or {}).get("sub"), expected["actorSub"])
        for perm in expected["permissions"]:
            self.assertTrue(p.has_permission(perm), perm)
        with self.assertRaises(TokenError) as ctx:
            TokenClient(self.options()).connection_token(robot["connectionToken"])
        self.assertEqual(ctx.exception.error, "unauthorized_client")

    def test_client_credentials_cache(self):
        clock = {"now": time.time()}
        client = TokenClient(self.options(now=lambda: clock["now"]))
        a = client.client_credentials([self.v["audience"]])
        b = client.client_credentials([self.v["audience"]])
        self.assertEqual(a.access_token, b.access_token, "повторный вызов — из кэша")
        self.assertIsNot(a, client.client_credentials(), "другой scope — другой кэш")
        clock["now"] = a.expires_at
        c = client.client_credentials([self.v["audience"]])
        self.assertNotEqual(a.access_token, c.access_token, "после истечения — новый токен")

    def test_client_credentials_error_does_not_poison_cache(self):
        good = TokenClient(self.options())
        bad = TokenClient(self.options(client_secret="wrong-secret"))
        with self.assertRaises(TokenError) as ctx:
            bad.client_credentials([self.v["audience"]])
        self.assertEqual(ctx.exception.error, "invalid_client")
        self.assertTrue(good.client_credentials([self.v["audience"]]).access_token)

    def test_token_error_unavailable(self):
        client = TokenClient(self.options(issuer="http://127.0.0.1:9/", http_timeout=2))
        with self.assertRaises(TokenError) as ctx:
            client.client_credentials()
        self.assertEqual(ctx.exception.error, "unavailable")

    def test_jwks_rotation(self):
        with urllib.request.urlopen(self.v["jwksUri"], timeout=10) as r:
            real = json.load(r)
        token = case(self.v, "ok_user")["token"]
        with JwksStub({"keys": []}) as stub:
            verifier = Verifier(self.options(jwks_uri=stub.url, jwks_min_refresh=1))
            with self.assertRaises(TslAuthError) as ctx:
                verifier.verify(token)
            self.assertEqual(ctx.exception.code, "unknown_key")
            self.assertEqual(stub.hits, 1, "первая загрузка")
            stub.document = real
            with self.assertRaises(TslAuthError) as ctx:
                verifier.verify(token)  # ещё не прошёл min_refresh — перечитывания нет
            self.assertEqual(ctx.exception.code, "unknown_key")
            self.assertEqual(stub.hits, 1, "лимит частоты перечитывания")
            time.sleep(1.1)
            self.assertEqual(verifier.verify(token).username, "sdk-operator")
            self.assertEqual(stub.hits, 2, "ротация: одно перечитывание")
            verifier.verify(token)
            self.assertEqual(stub.hits, 2, "известный kid — без обращений")

    def test_jwks_ignores_bad_keys(self):
        from tsl_auth_client.jwks import parse_jwks
        keys = parse_jwks({"keys": [
            {"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "kid": "ec", "x": "AA", "y": "AA"},
            {"kty": "RSA", "kid": "broken", "n": "%%%", "e": "AQAB"},
            {"kty": "RSA", "kid": "nokey"},
        ]})
        self.assertEqual(list(keys), ["a"])


if __name__ == "__main__":
    unittest.main()
