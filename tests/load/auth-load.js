// Нагрузочный тест TSL Auth (k6). Запуск: tests/load/run-load.ps1
//   BASE_URL      — адрес сервиса (по умолчанию http://host.docker.internal:8080)
//   CLIENT_ID/SECRET — confidential-клиент с client_credentials (admin-cli)
//   USERS/PASSWORD/PUBLIC_CLIENT — пул пользователей (через запятую, один пароль) и public-клиент с password grant;
//                    USER — один пользователь, если пул не задан
//   DURATION, VUS — длительность и число виртуальных пользователей на сценарий
import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate } from "k6/metrics";

const BASE = __ENV.BASE_URL || "http://host.docker.internal:8080";
const DURATION = __ENV.DURATION || "60s";
const VUS = Number(__ENV.VUS || 20);
const form = { headers: { "Content-Type": "application/x-www-form-urlencoded" } };
// Каждый VU входит своим пользователем из пула: при одном пользователе на всех тест мерил бы конкуренцию
// за одну учётную запись (блокировки строк, счётчик неудачных входов, тысячи сессий у одного человека),
// а не поведение сервиса под нагрузкой от разных людей.
const USERS = (__ENV.USERS || __ENV.USER || "alice").split(",").map((u) => u.trim()).filter(Boolean);
const userOf = () => USERS[(__VU - 1) % USERS.length];

const tokenLatency = new Trend("token_client_credentials_ms", true);
const loginLatency = new Trend("token_password_ms", true);
const refreshLatency = new Trend("token_refresh_ms", true);
const errors = new Rate("errors");

export const options = {
  scenarios: {
    client_credentials: { executor: "constant-vus", exec: "clientCredentials", vus: VUS, duration: DURATION },
    password_login:     { executor: "constant-vus", exec: "passwordLogin", vus: Math.max(1, Math.floor(VUS / 4)), duration: DURATION },
    refresh:            { executor: "constant-vus", exec: "refresh", vus: Math.max(1, Math.floor(VUS / 2)), duration: DURATION },
    jwks:               { executor: "constant-vus", exec: "jwks", vus: Math.max(1, Math.floor(VUS / 4)), duration: DURATION },
    admin_read:         { executor: "constant-vus", exec: "adminRead", vus: Math.max(1, Math.floor(VUS / 4)), duration: DURATION },
  },
  thresholds: {
    errors: ["rate<0.01"],                          // < 1% ошибок
    token_client_credentials_ms: ["p(95)<500"],
    token_refresh_ms: ["p(95)<700"],
    token_password_ms: ["p(95)<2000"],              // PBKDF2 (100k итераций) намеренно «тяжёлый»
    http_req_failed: ["rate<0.01"],
  },
};

function body(obj) {
  return Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

function token(params) {
  return http.post(`${BASE}/connect/token`, body(params), form);
}

function adminToken() {
  const r = token({ grant_type: "client_credentials", client_id: __ENV.CLIENT_ID, client_secret: __ENV.CLIENT_SECRET, scope: "tsl-auth-admin" });
  return r.json("access_token");
}

export function setup() {
  const login = token({ grant_type: "password", client_id: __ENV.PUBLIC_CLIENT, username: USERS[0], password: __ENV.PASSWORD,
    scope: "openid" });
  check(login, { "setup login ok": (r) => r.status === 200 });
  return { admin: adminToken() };
}

export function clientCredentials() {
  const r = token({ grant_type: "client_credentials", client_id: __ENV.CLIENT_ID, client_secret: __ENV.CLIENT_SECRET, scope: "tsl-auth-admin" });
  tokenLatency.add(r.timings.duration);
  errors.add(!check(r, { "cc 200": (x) => x.status === 200 && !!x.json("access_token") }));
}

// Без offline_access: каждый вход иначе оставлял бы в БД новую refresh-сессию до истечения её срока.
export function passwordLogin() {
  const r = token({ grant_type: "password", client_id: __ENV.PUBLIC_CLIENT, username: userOf(), password: __ENV.PASSWORD,
    scope: "openid" });
  loginLatency.add(r.timings.duration);
  errors.add(!check(r, { "login 200": (x) => x.status === 200 }));
  sleep(0.2);
}

// Каждый VU ведёт свою «сессию»: вход один раз, дальше цепочка refresh (ротация токенов).
let refreshToken = null;
export function refresh() {
  if (!refreshToken) {
    const l = token({ grant_type: "password", client_id: __ENV.PUBLIC_CLIENT, username: userOf(), password: __ENV.PASSWORD,
      scope: "openid offline_access" });
    refreshToken = l.json("refresh_token");
    return;
  }
  const r = token({ grant_type: "refresh_token", client_id: __ENV.PUBLIC_CLIENT, refresh_token: refreshToken });
  refreshLatency.add(r.timings.duration);
  const ok = check(r, { "refresh 200": (x) => x.status === 200 && !!x.json("refresh_token") });
  errors.add(!ok);
  refreshToken = ok ? r.json("refresh_token") : null;
}

export function jwks() {
  const r = http.get(`${BASE}/.well-known/jwks`);
  errors.add(!check(r, { "jwks 200": (x) => x.status === 200 }));
}

export function adminRead(data) {
  const r = http.get(`${BASE}/api/admin/applications`, { headers: { Authorization: `Bearer ${data.admin}` } });
  errors.add(!check(r, { "admin 200": (x) => x.status === 200 }));
}
