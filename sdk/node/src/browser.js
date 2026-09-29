// @tsl/auth-client/browser — клиент для SPA (§7 контракта): authorization code + PKCE S256, refresh с ротацией,
// хранение в sessionStorage, fetch с автоподстановкой Bearer, RP-initiated logout. Без зависимостей.
//
// Глобальные объекты (sessionStorage, location, history, crypto, fetch) читаются при каждом вызове через
// globalThis — так модуль тестируется в Node с подменой глобалов.

const PREFIX = "tsl-auth:";
const REFRESH_AHEAD_SECONDS = 30;

const g = () => globalThis;
const store = () => g().sessionStorage;

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (n) => b64url(g().crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (text) => b64url(await g().crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

/**
 * Декодирует payload JWT БЕЗ проверки подписи: только для отображения имени, ролей и т. п. в интерфейсе.
 * Право доступа решает API, проверяя подпись на сервере; в браузере доверять этим данным нельзя.
 */
export function decodeClaims(token) {
  try {
    const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part), (c) => c.charCodeAt(0))));
  } catch {
    return null;
  }
}

export class BrowserAuthError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = "BrowserAuthError";
    this.code = code;
  }
}

export function createBrowserClient({ issuer, clientId, scope = "openid", redirectUri, postLogoutRedirectUri, now } = {}) {
  if (!issuer || !clientId) throw new TypeError("createBrowserClient: нужны issuer и clientId");
  const base = issuer.replace(/\/+$/, "");
  const clock = now ?? (() => Date.now() / 1000);
  const redirect = () => redirectUri ?? `${g().location.origin}/callback`;
  const postLogout = () => postLogoutRedirectUri ?? `${g().location.origin}/`;

  let discoveryPromise = null;
  let refreshing = null; // single-flight refresh

  const discovery = () =>
    (discoveryPromise ??= g()
      .fetch(`${base}/.well-known/openid-configuration`)
      .then((r) => {
        if (!r.ok) throw new BrowserAuthError("discovery_failed", `discovery: HTTP ${r.status}`);
        return r.json();
      })
      .catch((e) => {
        discoveryPromise = null; // не кэшируем неудачу
        throw e;
      }));

  const read = (k) => store().getItem(PREFIX + k);
  const write = (k, v) => (v == null ? store().removeItem(PREFIX + k) : store().setItem(PREFIX + k, v));

  function saveTokens(body) {
    write("access_token", body.access_token);
    if (body.refresh_token) write("refresh_token", body.refresh_token); // ротация: новый заменяет старый немедленно
    if (body.id_token) write("id_token", body.id_token);
    const expiresIn = Number(body.expires_in);
    write("expires_at", Number.isFinite(expiresIn) ? String(Math.floor(clock() + expiresIn)) : null);
  }

  function clearSession() {
    for (const k of ["access_token", "refresh_token", "id_token", "expires_at", "pkce"]) write(k, null);
  }

  /** Запрос к token endpoint. SPA — public client: секрета нет, защита — PKCE. */
  async function tokenRequest(params) {
    const url = (await discovery()).token_endpoint;
    const res = await g().fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: clientId, ...params }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new BrowserAuthError(body.error ?? "token_error", body.error_description ?? `HTTP ${res.status}`);
    saveTokens(body);
    return body;
  }

  function expiresAt() {
    const v = Number(read("expires_at"));
    if (Number.isFinite(v) && v > 0) return v;
    const claims = read("access_token") ? decodeClaims(read("access_token")) : null;
    return typeof claims?.exp === "number" ? claims.exp : 0;
  }

  return {
    /** Начало входа: verifier и state в sessionStorage, redirect на authorization_endpoint. */
    async login({ extraParams } = {}) {
      const verifier = random(48); // 64 символа base64url (в пределах 43–128 по RFC 7636)
      const state = random(16);
      const challenge = await sha256(verifier);
      write("pkce", JSON.stringify({ verifier, state }));
      const authz = (await discovery()).authorization_endpoint;
      const url =
        `${authz}?` +
        new URLSearchParams({
          client_id: clientId,
          response_type: "code",
          redirect_uri: redirect(),
          scope,
          state,
          code_challenge: challenge,
          code_challenge_method: "S256",
          ...(extraParams ?? {}),
        });
      g().location.assign(url);
      return url;
    },

    /** Обработка возврата с сервера авторизации: state, одноразовость PKCE, очистка адресной строки, обмен кода. */
    async handleCallback() {
      const q = new URLSearchParams(g().location.search);
      const saved = JSON.parse(read("pkce") ?? "null");
      // verifier и state одноразовые: удаляем ДО обмена, чтобы повторный заход на callback не запустил обмен ещё раз.
      write("pkce", null);
      // Убираем code/state из адресной строки, чтобы код не остался в истории браузера.
      const clean = g().location.pathname + (g().location.hash ?? "");
      g().history.replaceState(null, "", clean);
      if (q.get("error")) throw new BrowserAuthError(q.get("error"), q.get("error_description") ?? "");
      if (!saved || !saved.state || q.get("state") !== saved.state) throw new BrowserAuthError("state_mismatch", "state не совпадает — обмен не выполнен");
      const code = q.get("code");
      if (!code) throw new BrowserAuthError("missing_code", "в ответе нет code");
      return tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirect(), code_verifier: saved.verifier });
    },

    /** Access-токен; если истекает менее чем через 30 с и есть refresh — обновляет (single-flight). При отказе — null и сессия очищена. */
    async getAccessToken() {
      const token = read("access_token");
      if (!token) return null;
      if (expiresAt() - clock() > REFRESH_AHEAD_SECONDS) return token;
      const refreshToken = read("refresh_token");
      if (!refreshToken) return expiresAt() > clock() ? token : null;
      if (!refreshing) {
        refreshing = tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken })
          .then((b) => b.access_token)
          .catch(() => {
            clearSession();
            return null;
          })
          .finally(() => {
            refreshing = null;
          });
      }
      return refreshing;
    },

    /** fetch с заголовком Authorization: Bearer (с автообновлением токена). */
    async fetch(url, init = {}) {
      const token = await this.getAccessToken();
      const headers = new Headers(init.headers ?? {});
      if (token) headers.set("Authorization", `Bearer ${token}`);
      return g().fetch(url, { ...init, headers });
    },

    /** Очистка хранилища и переход на end_session_endpoint. */
    async logout() {
      const idToken = read("id_token");
      clearSession();
      const end = (await discovery()).end_session_endpoint;
      const params = new URLSearchParams({ post_logout_redirect_uri: postLogout() });
      if (idToken) params.set("id_token_hint", idToken);
      const url = `${end}?${params}`;
      g().location.assign(url);
      return url;
    },

    /** Claims access-токена без проверки подписи (см. decodeClaims) или null. */
    getClaims() {
      const t = read("access_token");
      return t ? decodeClaims(t) : null;
    },

    /** Есть access-токен, который ещё действует или может быть обновлён. */
    isLoggedIn() {
      if (!read("access_token")) return false;
      return expiresAt() > clock() || !!read("refresh_token");
    },

    getIdToken: () => read("id_token"),
    clear: clearSession,
  };
}
