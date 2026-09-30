// Нагрузочный тест подчинённых клиентов (k6): N подчинённых с ключами ES256 получают токены по private_key_jwt.
// Запуск: tests/load/run-managed-load.ps1. Постановка: 200 агентов, токен каждому раз в 5 минут; здесь сценарий
// «сжат» — те же 200 агентов за CYCLE_SECONDS секунд (по умолчанию 20 с, то есть ~10 запросов/с) на DURATION.
// Подготовка 200 подчинённых идёт под лимитом 30 изменений в минуту на владельца (setup ждёт окна) — около 7 минут.
//   BASE_URL, CLIENT_ID/CLIENT_SECRET — сервис и клиент Admin API (admin-cli); CLIENTS — число подчинённых (200);
//   CYCLE_SECONDS — за сколько секунд все подчинённые получают по токену; DURATION — длительность.
// Ключи создаются в setup() через WebCrypto (crypto.subtle), assertion подписывается в каждом VU.
import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate } from "k6/metrics";
import exec from "k6/execution";
import encoding from "k6/encoding";

const BASE = __ENV.BASE_URL || "http://host.docker.internal:8080";
const CLIENTS = Number(__ENV.CLIENTS || 200);
const CYCLE = Number(__ENV.CYCLE_SECONDS || 20);
const DURATION = __ENV.DURATION || "60s";
const OWNER = __ENV.OWNER || "load-agents-owner";
const PREFIX = "load-agent-";
const form = { headers: { "Content-Type": "application/x-www-form-urlencoded" } };
// 429 (лимит изменений) и 404/409 в подготовке — ожидаемые ответы, не ошибки http_req_failed.
const json = (token) => ({
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  responseCallback: http.expectedStatuses(200, 201, 204, 404, 409, 429),
});

const keyTokenLatency = new Trend("token_private_key_jwt_ms", true);
const errors = new Rate("errors");

export const options = {
  // Подготовка 200 подчинённых под лимитом изменений (30/мин) занимает несколько минут — больше стандартных 60 с.
  setupTimeout: "15m",
  scenarios: {
    // Постоянная интенсивность: все подчинённые по кругу, CLIENTS запросов за CYCLE секунд.
    private_key_jwt: {
      executor: "constant-arrival-rate", exec: "keyToken", rate: CLIENTS, timeUnit: `${CYCLE}s`,
      duration: DURATION, preAllocatedVUs: 20, maxVUs: 100,
    },
  },
  thresholds: {
    errors: ["rate<0.01"],
    token_private_key_jwt_ms: ["p(95)<500"],
    http_req_failed: ["rate<0.01"],
  },
};

function body(obj) {
  return Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

// base64url без «=» (в k6 нет btoa/atob — используется модуль k6/encoding).
const b64url = (bytes) => encoding.b64encode(bytes instanceof ArrayBuffer ? bytes : new Uint8Array(bytes).buffer, "rawurl");

const utf8 = (s) => new TextEncoder().encode(s);

// Координаты JWK P-256 должны быть ровно по 32 байта (RFC 7518); WebCrypto k6 отдаёт их без ведущих нулей.
function pad32(b64u) {
  const raw = new Uint8Array(encoding.b64decode(b64u, "rawurl"));
  const bytes = new Uint8Array(32);
  bytes.set(raw, 32 - raw.length);
  return b64url(bytes);
}

/// Подготовка: владелец с политикой (requireDelegation=false — сервисный токен), CLIENTS подчинённых с ключами.
export async function setup() {
  const admin = http.post(`${BASE}/connect/token`, body({
    grant_type: "client_credentials", client_id: __ENV.CLIENT_ID, client_secret: __ENV.CLIENT_SECRET, scope: "tsl-auth-admin" }), form).json("access_token");
  const api = (method, path, payload) => {
    const r = http.request(method, `${BASE}/api/admin${path}`, payload ? JSON.stringify(payload) : null, json(admin));
    if (r.status >= 400 && r.status !== 404 && r.status !== 409) throw new Error(`${method} ${path}: ${r.status} ${r.body}`);
    return r;
  };
  let ownerSecret;
  const existing = api("GET", `/applications/${OWNER}`);
  if (existing.status === 404) {
    ownerSecret = api("POST", "/applications", {
      clientId: OWNER, displayName: "Нагрузка: владелец агентов", clientType: "confidential",
      grantTypes: ["client_credentials"], selfManagement: true }).json("clientSecret");
  } else {
    ownerSecret = api("POST", `/applications/${OWNER}/secret`).json("clientSecret");
  }
  api("POST", `/applications/${OWNER}/permissions`, { name: "upload" });
  api("POST", `/applications/${OWNER}/roles`, { name: "uploader", permissions: ["upload"] });
  api("PUT", `/applications/${OWNER}/managed-clients-policy`, {
    prefix: PREFIX, roles: ["uploader"], authMethods: ["private_key_jwt"], maxClients: Math.max(CLIENTS, 200) * 2,
    accessTokenLifetime: 5, requireDelegation: false });

  const ownerToken = http.post(`${BASE}/connect/token`, body({
    grant_type: "client_credentials", client_id: OWNER, client_secret: ownerSecret, scope: "tsl-auth-app" }), form).json("access_token");
  // Прошлые прогоны: удаляем старых подчинённых, чтобы не упереться в предел (тоже с учётом лимита изменений).
  for (const c of http.get(`${BASE}/api/app/clients`, json(ownerToken)).json()) {
    let d = http.del(`${BASE}/api/app/clients/${c.clientId}`, null, json(ownerToken));
    if (d.status === 429) { sleep(61); d = http.del(`${BASE}/api/app/clients/${c.clientId}`, null, json(ownerToken)); }
  }

  const clients = [];
  for (let i = 0; i < CLIENTS; i++) {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
    let r;
    for (let attempt = 0; attempt < 5; attempt++) {
      r = http.post(`${BASE}/api/app/clients`, JSON.stringify({
        clientIdSuffix: `${String(i).padStart(3, "0")}`, displayName: `Агент ${i}`, roles: ["uploader"],
        jwks: { keys: [{ kty: pub.kty, crv: pub.crv, x: pad32(pub.x), y: pad32(pub.y) }] } }), json(ownerToken));
      // Предел изменений подчинённых — 30 в минуту на владельца: 200 агентов заводятся за несколько минут, как и в жизни.
      if (r.status !== 429) break;
      sleep(61);
    }
    if (r.status !== 201) throw new Error(`создание подчинённого ${i}: ${r.status} ${r.body}`);
    clients.push({ clientId: r.json("client.clientId"), kid: r.json("client.keys.0.kid"), jwk: priv });
  }
  const issuer = http.get(`${BASE}/.well-known/openid-configuration`).json("issuer");
  return { owner: OWNER, issuer, clients };
}

/// Assertion RFC 7523: ES256, typ client-authentication+jwt, aud = issuer, jti случайный, срок 60 с.
async function assertion(c, data) {
  const key = await crypto.subtle.importKey("jwk", c.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(utf8(JSON.stringify({ alg: "ES256", typ: "client-authentication+jwt", kid: c.kid })));
  const payload = b64url(utf8(JSON.stringify({
    iss: c.clientId, sub: c.clientId, aud: data.issuer, jti: crypto.randomUUID(), iat: now, nbf: now, exp: now + 60 })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(`${header}.${payload}`));
  return `${header}.${payload}.${b64url(sig)}`;
}

export async function keyToken(data) {
  const c = data.clients[exec.scenario.iterationInTest % data.clients.length];
  const r = http.post(`${BASE}/connect/token`, body({
    grant_type: "client_credentials", client_id: c.clientId, scope: data.owner,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await assertion(c, data) }), form);
  keyTokenLatency.add(r.timings.duration);
  const ok = check(r, { "private_key_jwt 200": (x) => x.status === 200, "role in token": (x) => x.json("access_token") !== undefined });
  errors.add(!ok);
}
