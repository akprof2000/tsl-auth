// Браузерный клиент (§7) в Node: подмена sessionStorage, location, history и fetch; crypto — WebCrypto Node.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { beforeEach, describe, it } from "node:test";
import { BrowserAuthError, createBrowserClient, decodeClaims } from "../src/browser.js";

const ISSUER = "https://auth.test/";
const DISCOVERY = {
  authorization_endpoint: "https://auth.test/connect/authorize",
  token_endpoint: "https://auth.test/connect/token",
  end_session_endpoint: "https://auth.test/connect/logout",
};

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const fakeJwt = (payload) => `${b64url(JSON.stringify({ alg: "RS256", kid: "k" }))}.${b64url(JSON.stringify(payload))}.sig`;

/** Окружение браузера: хранилище, адресная строка, история и fetch-заглушка с журналом запросов. */
function browserEnv() {
  const map = new Map();
  const storage = {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, val) => map.set(k, String(val)),
    removeItem: (k) => map.delete(k),
    clear: () => map.clear(),
    get size() {
      return map.size;
    },
  };
  const location = {
    origin: "https://app.test",
    pathname: "/",
    search: "",
    hash: "",
    href: "https://app.test/",
    assign(url) {
      this.href = url;
    },
  };
  const history = { replaced: [], replaceState: (s, t, url) => history.replaced.push(url) };
  const requests = [];
  let tokenResponse = () => ({ status: 200, body: {} });
  let tokenDelay = 0;
  const fetchStub = async (url, init = {}) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) {
      requests.push({ url: u, kind: "discovery" });
      return new Response(JSON.stringify(DISCOVERY), { status: 200 });
    }
    if (u === DISCOVERY.token_endpoint) {
      const form = Object.fromEntries(new URLSearchParams(init.body));
      requests.push({ url: u, kind: "token", form });
      if (tokenDelay) await new Promise((r) => setTimeout(r, tokenDelay));
      const { status, body } = tokenResponse(form);
      return new Response(JSON.stringify(body), { status });
    }
    requests.push({ url: u, kind: "api", headers: Object.fromEntries(new Headers(init.headers ?? {})) });
    return new Response("{}", { status: 200 });
  };
  for (const [name, value] of [
    ["sessionStorage", storage],
    ["location", location],
    ["history", history],
    ["fetch", fetchStub],
  ]) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
  return {
    storage,
    location,
    history,
    requests,
    tokenRequests: () => requests.filter((r) => r.kind === "token"),
    setTokenResponse: (fn) => (tokenResponse = fn),
    setTokenDelay: (ms) => (tokenDelay = ms),
  };
}

describe("browser client", () => {
  let env;
  let now = 1_800_000_000;
  const client = () => createBrowserClient({ issuer: ISSUER, clientId: "spa", scope: "openid offline_access api", now: () => now });

  beforeEach(() => {
    env = browserEnv();
    now = 1_800_000_000;
  });

  it("login: PKCE S256 от verifier, state ≥16 байт, всё в sessionStorage, redirect на authorization_endpoint", async () => {
    const url = new URL(await client().login());
    assert.equal(env.location.href, url.href);
    assert.equal(`${url.origin}${url.pathname}`, DISCOVERY.authorization_endpoint);
    const pkce = JSON.parse(env.storage.getItem("tsl-auth:pkce"));
    assert.match(pkce.verifier, /^[A-Za-z0-9_-]{43,128}$/);
    assert.ok(Buffer.from(pkce.state, "base64url").length >= 16);
    const expected = createHash("sha256").update(pkce.verifier).digest("base64url");
    assert.equal(url.searchParams.get("code_challenge"), expected);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("state"), pkce.state);
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("client_id"), "spa");
    assert.equal(url.searchParams.get("redirect_uri"), "https://app.test/callback");
    assert.equal(url.searchParams.get("scope"), "openid offline_access api");
  });

  it("handleCallback: обмен кода с verifier, pkce удалён до обмена, адресная строка очищена, токены сохранены", async () => {
    const c = client();
    await c.login();
    const { verifier, state } = JSON.parse(env.storage.getItem("tsl-auth:pkce"));
    env.location.pathname = "/callback";
    env.location.search = `?code=the-code&state=${state}`;
    let pkceAtExchange;
    env.setTokenResponse(() => {
      pkceAtExchange = env.storage.getItem("tsl-auth:pkce");
      return { status: 200, body: { access_token: fakeJwt({ preferred_username: "ivan", exp: now + 900 }), refresh_token: "r1", id_token: "id1", expires_in: 900 } };
    });

    const body = await c.handleCallback();
    assert.equal(body.refresh_token, "r1");
    const [req] = env.tokenRequests();
    assert.deepEqual(req.form, { client_id: "spa", grant_type: "authorization_code", code: "the-code", redirect_uri: "https://app.test/callback", code_verifier: verifier });
    assert.equal(pkceAtExchange, null, "pkce удаляется до обмена");
    assert.deepEqual(env.history.replaced, ["/callback"]);
    assert.equal(env.storage.getItem("tsl-auth:refresh_token"), "r1");
    assert.equal(env.storage.getItem("tsl-auth:id_token"), "id1");
    assert.equal(c.isLoggedIn(), true);
    assert.equal(c.getClaims().preferred_username, "ivan");
    assert.equal(await c.getAccessToken(), body.access_token);
  });

  it("handleCallback: state_mismatch — обмен не выполняется", async () => {
    const c = client();
    await c.login();
    env.location.search = "?code=the-code&state=wrong";
    await assert.rejects(c.handleCallback(), (e) => e instanceof BrowserAuthError && e.code === "state_mismatch");
    assert.equal(env.tokenRequests().length, 0);
    assert.equal(env.storage.getItem("tsl-auth:pkce"), null);
    assert.equal(c.isLoggedIn(), false);
  });

  it("handleCallback: одноразовость pkce — повторный заход с тем же state не проходит", async () => {
    const c = client();
    await c.login();
    const { state } = JSON.parse(env.storage.getItem("tsl-auth:pkce"));
    env.location.search = `?code=c1&state=${state}`;
    env.setTokenResponse(() => ({ status: 200, body: { access_token: "a1", expires_in: 900 } }));
    await c.handleCallback();
    await assert.rejects(c.handleCallback(), (e) => e.code === "state_mismatch");
    assert.equal(env.tokenRequests().length, 1);
  });

  it("handleCallback: ошибка от сервера авторизации", async () => {
    const c = client();
    await c.login();
    env.location.search = "?error=access_denied&error_description=nope";
    await assert.rejects(c.handleCallback(), (e) => e.code === "access_denied");
    assert.equal(env.tokenRequests().length, 0);
  });

  it("getAccessToken: скорое истечение → refresh с ротацией, новая пара сохранена немедленно", async () => {
    const c = client();
    env.storage.setItem("tsl-auth:access_token", "a1");
    env.storage.setItem("tsl-auth:refresh_token", "r1");
    env.storage.setItem("tsl-auth:expires_at", String(now + 10));
    env.setTokenResponse(() => ({ status: 200, body: { access_token: "a2", refresh_token: "r2", expires_in: 900 } }));

    assert.equal(await c.getAccessToken(), "a2");
    const [req] = env.tokenRequests();
    assert.deepEqual(req.form, { client_id: "spa", grant_type: "refresh_token", refresh_token: "r1" });
    assert.equal(env.storage.getItem("tsl-auth:refresh_token"), "r2");
    assert.equal(env.storage.getItem("tsl-auth:access_token"), "a2");
    assert.equal(env.storage.getItem("tsl-auth:expires_at"), String(now + 900));
    // Свежий токен отдаётся из хранилища без запросов.
    assert.equal(await c.getAccessToken(), "a2");
    assert.equal(env.tokenRequests().length, 1);
  });

  it("getAccessToken: single-flight — параллельные вызовы делают один refresh", async () => {
    const c = client();
    env.storage.setItem("tsl-auth:access_token", "a1");
    env.storage.setItem("tsl-auth:refresh_token", "r1");
    env.storage.setItem("tsl-auth:expires_at", String(now + 5));
    env.setTokenDelay(20);
    env.setTokenResponse(() => ({ status: 200, body: { access_token: "a2", refresh_token: "r2", expires_in: 900 } }));
    const results = await Promise.all([c.getAccessToken(), c.getAccessToken(), c.getAccessToken()]);
    assert.deepEqual(results, ["a2", "a2", "a2"]);
    assert.equal(env.tokenRequests().length, 1);
  });

  it("getAccessToken: отказ refresh очищает сессию и возвращает null", async () => {
    const c = client();
    env.storage.setItem("tsl-auth:access_token", "a1");
    env.storage.setItem("tsl-auth:refresh_token", "r1");
    env.storage.setItem("tsl-auth:expires_at", String(now - 1));
    env.setTokenResponse(() => ({ status: 400, body: { error: "invalid_grant" } }));
    assert.equal(await c.getAccessToken(), null);
    assert.equal(env.storage.size, 0);
    assert.equal(c.isLoggedIn(), false);
    assert.equal(await c.getAccessToken(), null);
  });

  it("getAccessToken: без refresh — токен пока действует, потом null; без сессии — null", async () => {
    const c = client();
    assert.equal(await c.getAccessToken(), null);
    env.storage.setItem("tsl-auth:access_token", "a1");
    env.storage.setItem("tsl-auth:expires_at", String(now + 10));
    assert.equal(await c.getAccessToken(), "a1");
    now += 20;
    assert.equal(await c.getAccessToken(), null);
    assert.equal(c.isLoggedIn(), false);
  });

  it("fetch добавляет Authorization: Bearer и сохраняет остальные заголовки", async () => {
    const c = client();
    env.storage.setItem("tsl-auth:access_token", "a1");
    env.storage.setItem("tsl-auth:expires_at", String(now + 900));
    await c.fetch("https://api.test/orders", { headers: { "X-Trace": "1" } });
    const req = env.requests.find((r) => r.kind === "api");
    assert.equal(req.headers.authorization, "Bearer a1");
    assert.equal(req.headers["x-trace"], "1");
  });

  it("logout: очистка хранилища и переход на end_session_endpoint с id_token_hint", async () => {
    const c = client();
    env.storage.setItem("tsl-auth:access_token", "a1");
    env.storage.setItem("tsl-auth:id_token", "id1");
    const url = new URL(await c.logout());
    assert.equal(`${url.origin}${url.pathname}`, DISCOVERY.end_session_endpoint);
    assert.equal(url.searchParams.get("id_token_hint"), "id1");
    assert.equal(url.searchParams.get("post_logout_redirect_uri"), "https://app.test/");
    assert.equal(env.storage.size, 0);
    assert.equal(env.location.href, url.href);
  });

  it("discovery кэшируется в памяти", async () => {
    const c = client();
    await c.login();
    await c.login();
    assert.equal(env.requests.filter((r) => r.kind === "discovery").length, 1);
  });

  it("decodeClaims: только декодирование, без проверки подписи; мусор → null", () => {
    assert.deepEqual(decodeClaims(fakeJwt({ sub: "1", role: ["x"] })), { sub: "1", role: ["x"] });
    assert.equal(decodeClaims("garbage"), null);
  });
});
