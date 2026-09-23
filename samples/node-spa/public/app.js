// SPA без библиотек: OAuth 2.0 authorization code + PKCE (RFC 7636), refresh token, вызовы API.
const cfg = window.APP_CONFIG;
const base = cfg.issuer.replace(/\/$/, "");
const redirectUri = `${location.origin}/callback`;
const $ = (id) => document.getElementById(id);
// Токены живут в sessionStorage: очищаются при закрытии вкладки и не уходят на сервер автоматически (в отличие от cookie).
const store = sessionStorage;

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
// Декодирует payload JWT только для отображения — подпись здесь НЕ проверяется (это задача API).
const claims = (t) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
const show = (v) => ($("out").textContent = typeof v === "string" ? v : JSON.stringify(v, null, 2));

function render() {
  const t = store.getItem("access_token");
  $("claims").textContent = t ? JSON.stringify(claims(t), null, 2) : "—";
  $("who").textContent = t ? `вошёл: ${claims(t).preferred_username}` : "не выполнен вход";
}

// PKCE: случайный code_verifier остаётся в браузере, на сервер уходит только его SHA-256 (code_challenge).
// При обмене кода на токен предъявляется verifier — перехваченный код без него бесполезен.
// state — защита от CSRF: сверяется при возврате на /callback.
async function login() {
  const verifier = random(48), state = random(16);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  store.setItem("pkce", JSON.stringify({ verifier, state }));
  location.href = `${base}/connect/authorize?` + new URLSearchParams({
    client_id: cfg.clientId, response_type: "code", redirect_uri: redirectUri, scope: cfg.scope,
    state, code_challenge: challenge, code_challenge_method: "S256",
  });
}

// Запрос к token endpoint. SPA — public client: client_secret нет, защита обеспечивается PKCE.
async function token(params) {
  const res = await fetch(`${base}/connect/token`, { method: "POST", body: new URLSearchParams({ client_id: cfg.clientId, ...params }) });
  const body = await res.json();
  if (!res.ok) throw new Error(`${body.error}: ${body.error_description}`);
  store.setItem("access_token", body.access_token);
  if (body.refresh_token) store.setItem("refresh_token", body.refresh_token);
  if (body.id_token) store.setItem("id_token", body.id_token);
  render();
  return body;
}

async function handleCallback() {
  const q = new URLSearchParams(location.search);
  const saved = JSON.parse(store.getItem("pkce") ?? "{}");
  // Убираем code/state из адресной строки, чтобы код не остался в истории браузера.
  history.replaceState(null, "", "/");
  if (q.get("error")) return show(`Ошибка входа: ${q.get("error")} ${q.get("error_description") ?? ""}`);
  if (q.get("state") !== saved.state) return show("state не совпадает — возможная CSRF-атака");
  const body = await token({ grant_type: "authorization_code", code: q.get("code"), redirect_uri: redirectUri, code_verifier: saved.verifier });
  show({ ok: "вход выполнен", expires_in: body.expires_in, has_refresh_token: !!body.refresh_token });
}

async function callApi(url) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${store.getItem("access_token")}` } });
  show({ status: res.status, body: await res.json().catch(() => null) });
}

$("login").onclick = login;
$("refresh").onclick = () => token({ grant_type: "refresh_token", refresh_token: store.getItem("refresh_token") })
  .then((b) => show({ ok: "токен обновлён", expires_in: b.expires_in })).catch((e) => show(e.message));
$("node").onclick = () => callApi("/api/orders");
$("go").onclick = () => callApi(`${cfg.goApi}/api/reports`);
$("chain").onclick = () => callApi(`${cfg.goApi}/api/chain`);
// RP-initiated logout: id_token_hint подсказывает серверу, чью сессию завершить, затем возврат на post_logout_redirect_uri.
$("logout").onclick = () => {
  const idToken = store.getItem("id_token");
  store.clear();
  location.href = `${base}/connect/logout?` + new URLSearchParams({ id_token_hint: idToken ?? "", post_logout_redirect_uri: `${location.origin}/` });
};

render();
if (location.pathname === "/callback") handleCallback().catch((e) => show(e.message));
