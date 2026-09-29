// Контрактные векторы (§8.2): для каждого случая — ровно тот код, что в expect; для ok_* — поля principal.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVerifier, TslAuthError } from "../src/index.js";
import { decodePayload, loadVectors } from "./helpers.js";

const v = loadVectors();
const base = { issuer: v.issuer, audience: v.audience, jwksUri: v.jwksUri };

async function run(verifier, token) {
  try {
    return { principal: await verifier.verify(token), code: "ok" };
  } catch (e) {
    assert.ok(e instanceof TslAuthError, `ожидалась TslAuthError, получено ${e?.constructor?.name}: ${e?.message}`);
    return { code: e.code };
  }
}

describe("vectors.json", () => {
  const shared = createVerifier(base);

  for (const c of v.cases) {
    it(`${c.name} → ${c.expect}`, async (t) => {
      if (c.name === "not_yet_valid" && c.skipIfNoNbf) return t.skip("в токене нет nbf");
      let verifier = shared;
      if (c.now !== undefined || c.issuer) verifier = createVerifier({ ...base, issuer: c.issuer ?? v.issuer, now: c.now });
      const { code, principal } = await run(verifier, c.token);
      assert.equal(code, c.expect);

      const exp = v.expected[c.name];
      if (!exp) return;
      if (exp.subjectType) assert.equal(principal.subjectType, exp.subjectType);
      if (exp.username) assert.equal(principal.username, exp.username);
      if (exp.subject) assert.equal(principal.subject, exp.subject);
      if (exp.permissions) assert.deepEqual([...principal.permissions].sort(), [...exp.permissions].sort());
      if (exp.roles) assert.deepEqual([...principal.roles].sort(), [...exp.roles].sort());
      if (exp.actorSub) assert.equal(principal.actor?.sub, exp.actorSub);
    });
  }

  it("ok_viewer: hasPermission(orders.write) = false, полная форма не принимается", async () => {
    const p = await shared.verify(v.cases.find((c) => c.name === "ok_viewer").token);
    assert.equal(p.hasPermission("orders.read"), true);
    assert.equal(p.hasPermission("orders.write"), false);
    assert.equal(p.hasPermission(`${v.audience}:orders.read`), false);
    assert.equal(p.hasRole("viewer"), true);
    assert.ok(p.allPermissions.includes(`${v.audience}:orders.read`));
  });

  it("ok_client: username отсутствует, claims — сырой payload", async () => {
    const token = v.cases.find((c) => c.name === "ok_client").token;
    const p = await shared.verify(token);
    assert.equal(p.username, undefined);
    assert.deepEqual(p.claims, decodePayload(token));
    assert.ok(p.expiresAt instanceof Date);
    assert.equal(p.actor, null);
  });

  it("issuer без завершающего / эквивалентен", async () => {
    const verifier = createVerifier({ ...base, issuer: v.issuer.replace(/\/+$/, "") });
    const p = await verifier.verify(v.cases.find((c) => c.name === "ok_user").token);
    assert.equal(p.username, v.expected.ok_user.username);
  });

  it("now как функция, возвращающая Date", async () => {
    const token = v.cases.find((c) => c.name === "ok_user").token;
    const exp = decodePayload(token).exp;
    const verifier = createVerifier({ ...base, now: () => new Date((exp + 60) * 1000) });
    const { code } = await run(verifier, token);
    assert.equal(code, "expired");
  });

  it("verifyAuthorization: без заголовка — missing, Bearer без учёта регистра", async () => {
    await assert.rejects(shared.verifyAuthorization(undefined), (e) => e.code === "missing");
    const token = v.cases.find((c) => c.name === "ok_user").token;
    const p = await shared.verifyAuthorization(`bearer ${token}`);
    assert.equal(p.username, v.expected.ok_user.username);
  });
});
