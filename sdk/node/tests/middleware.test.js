// Middleware (§5, §8.3 middleware): реальный node:http-сервер на свободном порту с /me, /orders, /orders/write.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { tslAuth } from "../src/index.js";
import { json, listen, loadVectors } from "./helpers.js";

const v = loadVectors();
const token = (name) => v.cases.find((c) => c.name === name).token;
const expectWwwAuth = (res, error, description) =>
  assert.equal(res.headers.get("www-authenticate"), `Bearer realm="tsl-auth", error="${error}", error_description="${description}"`);

describe("middleware на node:http", () => {
  let server;
  const auth = tslAuth({ issuer: v.issuer, audience: v.audience, jwksUri: v.jwksUri });
  const routes = {
    "/me": auth.protect((req, res) => {
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ username: req.auth.username }));
    }),
    "/orders": auth.protect((req, res) => res.end(JSON.stringify({ orders: [1, 2] })), { permission: "orders.read" }),
    "/orders/write": auth.protect((req, res) => res.end(JSON.stringify({ ok: true })), { permission: "orders.write" }),
    "/any": auth.protect((req, res) => res.end("{}"), { anyPermission: ["orders.write", "nope"] }),
    "/role": auth.protect((req, res) => res.end("{}"), { role: "operator" }),
    "/mfa": auth.protect((req, res) => res.end("{}"), { mfa: true }),
    "/clients-only": auth.protect((req, res) => res.end("{}"), { subjectType: "client" }),
  };

  before(async () => {
    server = await listen((req, res) => {
      const route = routes[new URL(req.url, "http://x").pathname];
      if (!route) {
        res.writeHead(404);
        return res.end();
      }
      route(req, res);
    });
  });
  after(() => server.close());

  const get = (path, t) => fetch(`${server.url}${path}`, { headers: t === undefined ? {} : { Authorization: `Bearer ${t}` } });

  it("без токена — 401 missing", async () => {
    const res = await get("/me");
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("content-type"), "application/json; charset=utf-8");
    expectWwwAuth(res, "invalid_token", "missing");
    assert.deepEqual(await json(res), { error: "invalid_token", error_description: "missing" });
  });

  it("пустой Bearer — 401 missing", async () => {
    const res = await fetch(`${server.url}/me`, { headers: { Authorization: "Bearer " } });
    assert.equal(res.status, 401);
    assert.deepEqual(await json(res), { error: "invalid_token", error_description: "missing" });
  });

  it("испорченный токен — 401 с кодом §2", async () => {
    for (const [name, code] of [
      ["garbage", "malformed"],
      ["tampered_payload", "bad_signature"],
      ["alg_none", "unsupported_alg"],
      ["wrong_audience", "bad_audience"],
    ]) {
      const res = await get("/me", token(name));
      assert.equal(res.status, 401, name);
      expectWwwAuth(res, "invalid_token", code);
      assert.deepEqual(await json(res), { error: "invalid_token", error_description: code });
    }
  });

  it("ok_user — 200 и username", async () => {
    const res = await get("/me", token("ok_user"));
    assert.equal(res.status, 200);
    assert.deepEqual(await json(res), { username: v.expected.ok_user.username });
    assert.equal((await get("/orders/write", token("ok_user"))).status, 200);
    assert.equal((await get("/orders", token("ok_viewer"))).status, 200);
  });

  it("ok_viewer на /orders/write — 403 insufficient_permissions", async () => {
    const res = await get("/orders/write", token("ok_viewer"));
    assert.equal(res.status, 403);
    expectWwwAuth(res, "insufficient_permissions", `${v.audience}:orders.write`);
    assert.deepEqual(await json(res), { error: "insufficient_permissions", error_description: `${v.audience}:orders.write` });
  });

  it("anyPermission, role, mfa, subjectType", async () => {
    assert.equal((await get("/any", token("ok_user"))).status, 200);
    let res = await get("/any", token("ok_viewer"));
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error, "insufficient_permissions");

    assert.equal((await get("/role", token("ok_user"))).status, 200);
    res = await get("/role", token("ok_viewer"));
    assert.equal(res.status, 403);
    expectWwwAuth(res, "insufficient_role", `${v.audience}:operator`);

    res = await get("/mfa", token("ok_user"));
    assert.equal(res.status, 403);
    assert.deepEqual(await json(res), { error: "mfa_required", error_description: "mfa" });

    assert.equal((await get("/clients-only", token("ok_client"))).status, 200);
    res = await get("/clients-only", token("ok_user"));
    assert.equal(res.status, 403);
    assert.deepEqual(await json(res), { error: "subject_type_not_allowed", error_description: "client" });
  });

  it("как Express/Connect: (req, res, next) — next вызывается при успехе, req.auth заполнен", async () => {
    const mw = tslAuth({ issuer: v.issuer, audience: v.audience, jwksUri: v.jwksUri, permission: "orders.read" });
    const req = { headers: { authorization: `Bearer ${token("ok_viewer")}` } };
    let nextCalled = 0;
    await mw(req, fakeRes(), function next() {
      nextCalled++;
    });
    assert.equal(nextCalled, 1);
    assert.equal(req.auth.username, v.expected.ok_viewer.username);

    const denied = { headers: { authorization: `Bearer ${token("ok_viewer")}` } };
    const res = fakeRes();
    await mw.require({ permission: "orders.write" })(denied, res, () => nextCalled++);
    assert.equal(nextCalled, 1);
    assert.equal(res.statusCode, 403);
    assert.equal(JSON.parse(res.body).error, "insufficient_permissions");
  });
});

function fakeRes() {
  return {
    statusCode: 200,
    headers: {},
    body: "",
    setHeader(k, val) {
      this.headers[k.toLowerCase()] = val;
    },
    end(b) {
      this.body = b ?? "";
    },
  };
}
