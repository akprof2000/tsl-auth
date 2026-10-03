// Клиент токенов (§6 контракта): все grant'ы, introspect, revoke; кэш client_credentials с single-flight.
import { fetchWithTimeout, resolveConfig } from "./config.js";
import { createDiscovery } from "./discovery.js";
import { TokenError } from "./errors.js";

/** Обмен токена подключения (PAT, выписанного пользователем этому сервису) на JWT пользователя. */
export const CONNECTION_TOKEN_GRANT = "urn:tsl:grant-type:pat";

const scopeString = (scopes) => (Array.isArray(scopes) ? scopes.join(" ") : scopes ?? "");

export function createTokenClient(options = {}) {
  const cfg = resolveConfig(options);
  const discovery =
    options.discovery ?? createDiscovery({ issuer: cfg.issuer, ttl: cfg.jwksTtl, httpTimeout: cfg.httpTimeout, fetch: cfg.fetch, now: cfg.now });
  const ccCache = new Map(); // scope → { tokenSet, inflight }

  /** POST формой; `client_id` всегда в теле, `client_secret` — если задан. */
  async function post(endpointName, params) {
    if (!cfg.clientId) throw new TokenError("invalid_client", "не задан clientId (параметр или TSL_AUTH_CLIENT_ID)", 0);
    const body = new URLSearchParams({ client_id: cfg.clientId });
    if (cfg.clientSecret) body.set("client_secret", cfg.clientSecret);
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") body.set(k, String(v));

    let url;
    let res;
    try {
      url = await discovery.endpoint(endpointName);
      res = await fetchWithTimeout(
        cfg.fetch,
        url,
        { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body },
        cfg.httpTimeout,
      );
    } catch (e) {
      throw new TokenError("unavailable", `сервис авторизации недоступен: ${e?.message ?? e}`, 0);
    }
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (res.status >= 500) throw new TokenError("unavailable", `HTTP ${res.status}`, res.status);
    if (!res.ok) throw new TokenError(json?.error ?? "invalid_request", json?.error_description ?? `HTTP ${res.status}`, res.status);
    return json ?? {};
  }

  /** Ответ token endpoint → TokenSet; expiresAt вычисляется в момент получения. */
  function toTokenSet(raw) {
    const expiresIn = Number(raw.expires_in);
    return Object.freeze({
      accessToken: raw.access_token,
      refreshToken: raw.refresh_token ?? undefined,
      idToken: raw.id_token ?? undefined,
      expiresAt: Number.isFinite(expiresIn) ? new Date((cfg.now() + expiresIn) * 1000) : undefined,
      scope: raw.scope ?? undefined,
      tokenType: raw.token_type ?? "Bearer",
      raw,
    });
  }

  const grant = async (params) => toTokenSet(await post("token_endpoint", params));

  /** Кэш до `expiresAt − 30 с` по ключу; параллельные вызовы с одним ключом делают один запрос. */
  function cached(key, params) {
    const entry = ccCache.get(key) ?? {};
    const fresh = entry.tokenSet && entry.tokenSet.expiresAt && entry.tokenSet.expiresAt.getTime() / 1000 - 30 > cfg.now();
    if (fresh) return Promise.resolve(entry.tokenSet);
    if (!entry.inflight) {
      entry.inflight = grant(params)
        .then((ts) => {
          entry.tokenSet = ts;
          return ts;
        })
        .finally(() => {
          entry.inflight = null;
        });
      ccCache.set(key, entry);
    }
    return entry.inflight; // ошибка запроса кэш не портит: старый tokenSet остаётся в entry
  }

  return {
    /** Сервисный токен; кэш по scope до `expiresAt − 30 с`, параллельные вызовы делают один запрос. */
    clientCredentials(scopes) {
      const scope = scopeString(scopes);
      return cached(scope ?? "", { grant_type: "client_credentials", scope });
    },
    /**
     * Робот: JWT пользователя по его токену подключения (`tslpat_…`, выписан в «Мои токены» этому сервису).
     * Сервис входит своим client_id и секретом; в JWT — права пользователя и claim `act` с этим сервисом.
     * Кэшируется по токену до `expiresAt − 30 с`, как сервисный токен.
     */
    connectionToken(connectionToken) {
      if (!connectionToken) return Promise.reject(new TypeError("пустой токен подключения"));
      return cached(`pat:${connectionToken}`, { grant_type: CONNECTION_TOKEN_GRANT, token: connectionToken });
    },
    /** RFC 8693 token exchange; не кэшируется. */
    exchange: (subjectToken, scopes) =>
      grant({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: subjectToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        scope: scopeString(scopes),
      }),
    refresh: (refreshToken, scopes) => grant({ grant_type: "refresh_token", refresh_token: refreshToken, scope: scopeString(scopes) }),
    /** Только серверные приложения. */
    password: (username, password, scopes) => grant({ grant_type: "password", username, password, scope: scopeString(scopes) }),
    authorizationCode: (code, redirectUri, codeVerifier) =>
      grant({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: codeVerifier }),
    /** RFC 7662; результат — объект ответа (`active` и claims). */
    introspect: (token) => post("introspection_endpoint", { token }),
    /** RFC 7009; успех — 200 (пустое тело). */
    async revoke(token) {
      await post("revocation_endpoint", { token });
    },
    /** Сбросить кэш client_credentials (например, после смены секрета). */
    clearCache() {
      ccCache.clear();
    },
  };
}
