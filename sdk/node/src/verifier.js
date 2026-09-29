// Проверка access-токена (§2 контракта): порядок шагов и коды ошибок — строго по таблице.
import { verify as rsaVerify } from "node:crypto";
import { normalizeIssuer, resolveConfig } from "./config.js";
import { createDiscovery } from "./discovery.js";
import { TslAuthError } from "./errors.js";
import { createJwksCache } from "./jwks.js";
import { createPrincipal, toList } from "./principal.js";
import { createTokenClient } from "./token-client.js";

const B64URL = /^[A-Za-z0-9_-]*$/;

/** base64url → JSON-объект или null. */
function decodeJson(part) {
  if (!part || !B64URL.test(part)) return null;
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/** Извлекает токен из `Authorization: Bearer <jwt>` (регистр слова Bearer не важен); пустой → undefined. */
export function bearerFromHeader(header) {
  if (typeof header !== "string") return undefined;
  const m = /^\s*Bearer\s+(.+?)\s*$/i.exec(header);
  return m ? m[1] : undefined;
}

export function createVerifier(options = {}) {
  const cfg = resolveConfig(options);
  const issuer = normalizeIssuer(cfg.issuer);
  const discovery =
    options.discovery ?? createDiscovery({ issuer: cfg.issuer, ttl: cfg.jwksTtl, httpTimeout: cfg.httpTimeout, fetch: cfg.fetch, now: cfg.now });
  const jwks =
    options.jwks ??
    createJwksCache({
      jwksUri: cfg.jwksUri,
      discovery,
      ttl: cfg.jwksTtl,
      minRefresh: cfg.jwksMinRefresh,
      httpTimeout: cfg.httpTimeout,
      fetch: cfg.fetch,
      now: cfg.now,
    });
  // Клиент для introspection создаётся лениво: нужен только при TSL_AUTH_INTROSPECT=true.
  let tokenClient = options.tokenClient ?? null;
  const introspector = () => (tokenClient ??= createTokenClient({ ...options, discovery }));

  async function verify(token) {
    // 1. Токен передан и не пуст.
    if (token === undefined || token === null) throw new TslAuthError("missing", "токен не передан");
    if (typeof token !== "string" || token.trim() === "") throw new TslAuthError("malformed", "пустой токен");
    // 2. Три части, заголовок и payload — JSON в base64url.
    const parts = token.split(".");
    if (parts.length !== 3) throw new TslAuthError("malformed", "ожидались три части JWT");
    const [h, p, s] = parts;
    const header = decodeJson(h);
    const payload = decodeJson(p);
    if (!header || !payload || !B64URL.test(s)) throw new TslAuthError("malformed", "заголовок или payload не декодируются");
    // 3. Только RS256 — до любых обращений к ключам.
    if (header.alg !== "RS256") throw new TslAuthError("unsupported_alg", "поддерживается только RS256");
    // 4. kid обязателен.
    if (typeof header.kid !== "string" || header.kid === "") throw new TslAuthError("malformed", "в заголовке нет kid");
    // 5. Ключ из кэша JWKS.
    let key;
    try {
      key = await jwks.getKey(header.kid);
    } catch (e) {
      throw new TslAuthError("jwks_unavailable", `не удалось загрузить JWKS: ${e?.message ?? e}`);
    }
    if (!key) throw new TslAuthError("unknown_key", "ключ с таким kid не найден");
    // 6. Подпись RSASSA-PKCS1-v1_5 / SHA-256.
    let ok = false;
    try {
      ok = rsaVerify("RSA-SHA256", Buffer.from(`${h}.${p}`), key, Buffer.from(s, "base64url"));
    } catch {
      ok = false;
    }
    if (!ok) throw new TslAuthError("bad_signature", "подпись неверна");
    // 7. iss.
    if (normalizeIssuer(payload.iss) !== issuer) throw new TslAuthError("bad_issuer", "iss не совпадает с настроенным issuer");
    // 8. exp / nbf с допуском.
    const now = cfg.now();
    if (typeof payload.exp !== "number" || now > payload.exp + cfg.clockSkew) throw new TslAuthError("expired", "токен истёк");
    if (typeof payload.nbf === "number" && now < payload.nbf - cfg.clockSkew) throw new TslAuthError("not_yet_valid", "токен ещё не действует");
    // 9. aud содержит audience.
    if (!cfg.audience || !toList(payload.aud).includes(cfg.audience)) throw new TslAuthError("bad_audience", "токен выдан не для этого API");
    // 10. Introspection (мгновенный отзыв).
    if (cfg.introspect) {
      let result;
      try {
        result = await introspector().introspect(token);
      } catch (e) {
        throw new TslAuthError("introspection_unavailable", `introspection недоступен: ${e?.message ?? e}`);
      }
      if (result?.active !== true) throw new TslAuthError("revoked", "токен отозван");
    }
    return createPrincipal(payload, cfg.audience);
  }

  return {
    verify,
    /** Проверка по значению заголовка Authorization: отсутствие → `missing`. */
    verifyAuthorization(header) {
      const token = bearerFromHeader(header);
      if (token === undefined) return Promise.reject(new TslAuthError("missing", "нет заголовка Authorization: Bearer"));
      return verify(token);
    },
    get audience() {
      return cfg.audience;
    },
    get jwks() {
      return jwks;
    },
  };
}
