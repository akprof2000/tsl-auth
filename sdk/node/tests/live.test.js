// Живые сценарии (§8.3) против запущенного TSL Auth из vectors.json: refresh_rotation, introspection_revoked,
// client_credentials_cache, jwks_rotation. Свои токены получаем password grant — векторные не трогаем.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createTokenClient, createVerifier, TokenError } from "../src/index.js";
import { decodePayload, json, listen, loadVectors, sleep } from "./helpers.js";

const v = loadVectors();
const clientOpts = { issuer: v.issuer, clientId: v.client.id, clientSecret: v.client.secret };
const userScope = `openid offline_access ${v.audience}`;

describe("live", () => {
  const tokens = createTokenClient(clientOpts);

  it("refresh_rotation: новый refresh отличается и работает; после revoke — invalid_grant", async () => {
    const first = await tokens.password(v.users.operator.username, v.users.operator.password, userScope);
    assert.ok(first.accessToken);
    assert.ok(first.refreshToken, "password grant должен вернуть refresh_token (scope offline_access)");
    assert.ok(first.expiresAt instanceof Date && first.expiresAt.getTime() > Date.now());

    const second = await tokens.refresh(first.refreshToken);
    assert.ok(second.refreshToken);
    assert.notEqual(second.refreshToken, first.refreshToken, "refresh-токен должен ротироваться");

    const third = await tokens.refresh(second.refreshToken);
    assert.ok(third.accessToken);

    await tokens.revoke(third.refreshToken);
    await assert.rejects(tokens.refresh(third.refreshToken), (e) => e instanceof TokenError && e.error === "invalid_grant" && e.status === 400);
  });

  it("password с неверным паролем — TokenError invalid_grant", async () => {
    await assert.rejects(tokens.password(v.users.viewer.username, "definitely-wrong-" + Date.now(), userScope), (e) => e instanceof TokenError && e.error === "invalid_grant");
  });

  it("introspection_revoked: токен проходит, после revoke(access) — revoked", async () => {
    const verifier = createVerifier({ ...clientOpts, audience: v.audience, introspect: true });
    const set = await tokens.password(v.users.viewer.username, v.users.viewer.password, userScope);
    const p = await verifier.verify(set.accessToken);
    assert.equal(p.username, v.users.viewer.username);

    const intro = await tokens.introspect(set.accessToken);
    assert.equal(intro.active, true);

    await tokens.revoke(set.accessToken);
    await assert.rejects(verifier.verify(set.accessToken), (e) => e.code === "revoked");
    // Без introspection локальная проверка по-прежнему проходит: отзыв виден только через introspect.
    const local = createVerifier({ issuer: v.issuer, audience: v.audience, jwksUri: v.jwksUri });
    assert.equal((await local.verify(set.accessToken)).username, v.users.viewer.username);
  });

  it("client_credentials_cache: два вызова — один токен, после перевода часов на exp — новый; параллельные — один запрос", async () => {
    let clock = Date.now() / 1000;
    let calls = 0;
    const counting = (url, init) => {
      if (String(url).includes("/connect/token")) calls++;
      return fetch(url, init);
    };
    const client = createTokenClient({ ...clientOpts, now: () => clock, fetch: counting });

    const [a, b, c] = await Promise.all([client.clientCredentials(v.audience), client.clientCredentials(v.audience), client.clientCredentials(v.audience)]);
    assert.equal(calls, 1, "параллельные вызовы делают один запрос");
    assert.equal(a.accessToken, b.accessToken);
    assert.equal(b.accessToken, c.accessToken);

    const again = await client.clientCredentials(v.audience);
    assert.equal(again.accessToken, a.accessToken);
    assert.equal(calls, 1);

    clock = a.expiresAt.getTime() / 1000; // «протух»
    const fresh = await client.clientCredentials(v.audience);
    assert.notEqual(fresh.accessToken, a.accessToken);
    assert.equal(calls, 2);
    assert.equal(decodePayload(fresh.accessToken).subject_type, "client");
  });

  describe("jwks_rotation", () => {
    let stub;
    let realKeys;
    let empty = true;
    let hits = 0;

    before(async () => {
      realKeys = await json(await fetch(v.jwksUri));
      stub = await listen((req, res) => {
        hits++;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(empty ? { keys: [] } : realKeys));
      });
    });
    after(() => stub?.close());

    it("пустой набор → unknown_key; повтор в пределах minRefresh не перечитывает; после ротации — ok", async () => {
      const token = v.cases.find((c) => c.name === "ok_user").token;
      const verifier = createVerifier({ issuer: v.issuer, audience: v.audience, jwksUri: `${stub.url}/jwks`, jwksMinRefresh: 1 });

      await assert.rejects(verifier.verify(token), (e) => e.code === "unknown_key");
      assert.equal(hits, 1);
      await assert.rejects(verifier.verify(token), (e) => e.code === "unknown_key");
      assert.equal(hits, 1, "лимит частоты: повторное перечитывание не раньше minRefresh");

      empty = false;
      await sleep(1100);
      const p = await verifier.verify(token);
      assert.equal(p.username, v.expected.ok_user.username);
      assert.equal(hits, 2);

      // Ключ в кэше: дальше обращений нет.
      await verifier.verify(token);
      assert.equal(hits, 2);
    });

    it("параллельные проверки при пустом кэше — одна загрузка (single-flight)", async () => {
      const token = v.cases.find((c) => c.name === "ok_user").token;
      const before = hits;
      const verifier = createVerifier({ issuer: v.issuer, audience: v.audience, jwksUri: `${stub.url}/jwks` });
      await Promise.all(Array.from({ length: 5 }, () => verifier.verify(token)));
      assert.equal(hits - before, 1);
    });
  });

  it("jwks_unavailable: недоступный JWKS без старого набора", async () => {
    const dead = await listen((req, res) => {
      res.writeHead(500);
      res.end();
    });
    try {
      const verifier = createVerifier({ issuer: v.issuer, audience: v.audience, jwksUri: `${dead.url}/jwks` });
      await assert.rejects(verifier.verify(v.cases.find((c) => c.name === "ok_user").token), (e) => e.code === "jwks_unavailable");
    } finally {
      await dead.close();
    }
  });

  it("TokenError unavailable при недоступном сервисе", async () => {
    const dead = await listen((req, res) => {
      res.writeHead(503);
      res.end();
    });
    try {
      const client = createTokenClient({ issuer: dead.url, clientId: "x" });
      await assert.rejects(client.clientCredentials("s"), (e) => e instanceof TokenError && e.error === "unavailable");
    } finally {
      await dead.close();
    }
  });
});
