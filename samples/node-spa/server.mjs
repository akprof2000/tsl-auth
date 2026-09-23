// Демо Node.js: раздаёт SPA (public client, PKCE в браузере) и сам является API ресурса demo-node-api.
// Без npm-зависимостей: JWT (RS256) проверяется встроенным crypto по JWKS сервиса авторизации.
//
// Переменные: AUTH_ISSUER, API_AUDIENCE (demo-node-api), SPA_CLIENT_ID (demo-node-spa), GO_API_URL, PORT.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { createPublicKey, verify } from "node:crypto";
import { extname, join } from "node:path";

const issuer = process.env.AUTH_ISSUER ?? "http://localhost:8080/";
const audience = process.env.API_AUDIENCE ?? "demo-node-api";
const port = Number(process.env.PORT ?? 5102);
const spaConfig = {
  issuer,
  clientId: process.env.SPA_CLIENT_ID ?? "demo-node-spa",
  scope: "openid profile email roles offline_access demo-node-api demo-go-api",
  goApi: process.env.GO_API_URL ?? "http://localhost:5103",
};

// ---------- JWKS / JWT ----------
let jwks = { keys: new Map(), fetched: 0 };

// Кэш ключей: перечитываем JWKS (через discovery) при неизвестном kid — ротация ключей — или раз в 10 минут.
async function keyFor(kid) {
  if (!jwks.keys.has(kid) || Date.now() - jwks.fetched > 10 * 60_000) {
    const discovery = await (await fetch(new URL(".well-known/openid-configuration", issuer))).json();
    const set = await (await fetch(discovery.jwks_uri)).json();
    jwks = { keys: new Map(set.keys.map((k) => [k.kid, createPublicKey({ key: k, format: "jwk" })])), fetched: Date.now() };
  }
  const key = jwks.keys.get(kid);
  if (!key) throw new Error(`unknown kid ${kid}`);
  return key;
}

const b64json = (s) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
// Claim может прийти строкой (одно значение) или массивом — приводим к массиву.
const list = (v) => (Array.isArray(v) ? v : v == null ? [] : [v]);

// Локальная проверка access-токена: подпись RS256 по JWKS, затем iss, aud и exp (с допуском 30 с на расхождение часов).
async function validate(token) {
  const [h, p, s] = token.split(".");
  if (!s) throw new Error("malformed token");
  const header = b64json(h);
  // Только RS256 — защита от подмены алгоритма (alg=none и т.п.).
  if (header.alg !== "RS256") throw new Error("unsupported alg");
  const ok = verify("RSA-SHA256", Buffer.from(`${h}.${p}`), await keyFor(header.kid), Buffer.from(s, "base64url"));
  if (!ok) throw new Error("bad signature");
  const claims = b64json(p);
  if (claims.iss !== issuer) throw new Error(`bad issuer ${claims.iss}`);
  if (!list(claims.aud).includes(audience)) throw new Error("token is not for this API (aud)");
  if (Date.now() / 1000 > claims.exp + 30) throw new Error("token expired");
  return claims;
}

// ---------- API ----------
const send = (res, status, body, type = "application/json; charset=utf-8") => {
  res.writeHead(status, { "Content-Type": type });
  res.end(type.startsWith("application/json") ? JSON.stringify(body) : body);
};

// Обёртка защищённого эндпоинта: 401 — нет/невалидный токен, 403 — нет разрешения "<audience>:<permission>" из матрицы доступа.
async function api(req, res, permission, handler) {
  const token = (req.headers.authorization ?? "").replace(/^Bearer /, "");
  let claims;
  try {
    claims = await validate(token);
  } catch (e) {
    return send(res, 401, { error: e.message });
  }
  if (permission && !list(claims.permissions).includes(`${audience}:${permission}`))
    return send(res, 403, { error: `permission required: ${audience}:${permission}` });
  return send(res, 200, handler(claims));
}

// act — claim token exchange (RFC 8693): если запрос пришёл через Go API, в act.sub указан сервис-посредник.
const routes = {
  "GET /api/me": (req, res) =>
    api(req, res, null, (c) => ({ service: "node-api", user: c.preferred_username, permissions: list(c.permissions), act: c.act ?? null })),
  "GET /api/orders": (req, res) =>
    api(req, res, "orders.read", (c) => ({
      service: "node-api",
      user: c.preferred_username,
      calledVia: c.act?.sub ?? "напрямую",
      orders: [{ id: 101, total: 1500 }, { id: 102, total: 320 }],
    })),
  // Конфигурация SPA отдаётся скриптом, чтобы не пересобирать фронтенд под каждое окружение.
  "GET /config.js": (req, res) => send(res, 200, `window.APP_CONFIG = ${JSON.stringify(spaConfig)};`, "text/javascript"),
  "GET /health": (req, res) => send(res, 200, { ok: true }),
};

const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css" };

createServer(async (req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  const route = routes[`${req.method} ${path}`];
  if (route) return route(req, res);
  // SPA: статика, всё остальное (в т.ч. /callback) — index.html
  // Удаление ".." — простая защита от выхода за пределы каталога public (path traversal).
  const file = path === "/" || !extname(path) ? "index.html" : path.slice(1).replace(/\.\./g, "");
  try {
    send(res, 200, await readFile(join(import.meta.dirname, "public", file)), types[extname(file)] ?? "application/octet-stream");
  } catch {
    send(res, 404, { error: "not found" });
  }
}).listen(port, () => console.log(`node-spa + node-api on :${port} (aud=${audience}, iss=${issuer})`));
