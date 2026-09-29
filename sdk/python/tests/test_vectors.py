"""Контрактные векторы (docs/client-contract.md §8, п. 2): каждый случай — ровно тот код, что в expect."""
import unittest

from _support import load_vectors

from tsl_auth_client import Options, TslAuthError, Verifier


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()

    def make_verifier(self, **kw) -> Verifier:
        base = dict(issuer=self.v["issuer"], audience=self.v["audience"], jwks_uri=self.v["jwksUri"])
        base.update(kw)
        return Verifier(Options(**base))

    def run_case(self, c: dict):
        kw = {}
        if "now" in c:
            kw["now"] = lambda: float(c["now"])
        if "issuer" in c:
            kw["issuer"] = c["issuer"]
        verifier = self.make_verifier(**kw)
        if c["expect"] == "ok":
            return verifier.verify(c["token"])
        with self.assertRaises(TslAuthError) as ctx:
            verifier.verify(c["token"])
        self.assertEqual(ctx.exception.code, c["expect"], f"{c['name']}: {ctx.exception}")
        return None

    def test_all_cases(self):
        for c in self.v["cases"]:
            with self.subTest(case=c["name"]):
                if c.get("skipIfNoNbf"):
                    continue  # в токене нет nbf — случай по контракту пропускается
                self.run_case(c)

    def test_not_yet_valid_skipped_when_no_nbf(self):
        c = next(x for x in self.v["cases"] if x["name"] == "not_yet_valid")
        if c.get("skipIfNoNbf"):
            self.skipTest("в токене нет nbf")
        self.run_case(c)

    def test_principal_fields(self):
        exp = self.v["expected"]
        by_name = {c["name"]: c for c in self.v["cases"]}

        user = self.run_case(by_name["ok_user"])
        self.assertEqual(user.subject_type, exp["ok_user"]["subjectType"])
        self.assertEqual(user.username, exp["ok_user"]["username"])
        self.assertEqual(sorted(user.permissions), sorted(exp["ok_user"]["permissions"]))
        self.assertEqual(sorted(user.roles), sorted(exp["ok_user"]["roles"]))
        self.assertTrue(user.has_permission("orders.write"))
        self.assertFalse(user.has_permission(f"{self.v['audience']}:orders.write"), "полная форма не принимается")
        self.assertTrue(user.has_role("operator"))
        self.assertFalse(user.is_mfa)
        self.assertIsNone(user.actor)
        self.assertEqual(user.claims["sub"], user.subject)
        self.assertIn(self.v["audience"], user.claims["aud"])

        viewer = self.run_case(by_name["ok_viewer"])
        self.assertEqual(viewer.permissions, exp["ok_viewer"]["permissions"])
        self.assertFalse(viewer.has_permission("orders.write"))

        client = self.run_case(by_name["ok_client"])
        self.assertEqual(client.subject_type, exp["ok_client"]["subjectType"])
        self.assertEqual(client.subject, exp["ok_client"]["subject"])
        self.assertIsNone(client.username)

        exchanged = self.run_case(by_name["ok_exchanged"])
        self.assertIsNotNone(exchanged.actor)
        self.assertEqual(exchanged.actor["sub"], exp["ok_exchanged"]["actorSub"])

    def test_empty_authorization_is_missing(self):
        verifier = self.make_verifier()
        for header in (None, "", "Bearer", "Bearer   ", "Basic abc"):
            with self.assertRaises(TslAuthError) as ctx:
                verifier.verify_authorization(header)
            self.assertEqual(ctx.exception.code, "missing")

    def test_bearer_case_insensitive(self):
        verifier = self.make_verifier()
        token = next(c for c in self.v["cases"] if c["name"] == "ok_user")["token"]
        self.assertEqual(verifier.verify_authorization(f"bearer {token}").username, "sdk-operator")
        self.assertEqual(verifier.verify_authorization(f"BEARER {token}").username, "sdk-operator")

    def test_options_from_env(self):
        env = {"TSL_AUTH_ISSUER": "https://auth.corp/", "TSL_AUTH_AUDIENCE": "api", "TSL_AUTH_INTROSPECT": "True",
               "TSL_AUTH_CLOCK_SKEW_SECONDS": "5", "TSL_AUTH_JWKS_TTL_SECONDS": "", "TSL_AUTH_JWKS_URI": "https://x/jwks"}
        o = Options.from_env(env, audience="other")
        self.assertEqual(o.issuer_normalized, "https://auth.corp")
        self.assertEqual(o.audience, "other")  # явный параметр важнее окружения
        self.assertTrue(o.introspect)
        self.assertEqual(o.clock_skew, 5)
        self.assertEqual(o.jwks_ttl, 600)
        self.assertEqual(o.jwks_uri, "https://x/jwks")


if __name__ == "__main__":
    unittest.main()
