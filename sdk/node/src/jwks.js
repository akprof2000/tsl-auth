// Кэш ключей JWKS (§3 контракта): ленивая загрузка, TTL, перечитывание по неизвестному kid не чаще
// JWKS_MIN_REFRESH, single-flight, старый набор при ошибке сети, только RSA/sig с корректными n/e.
import { createPublicKey } from "node:crypto";
import { fetchWithTimeout } from "./config.js";

export function createJwksCache({ jwksUri, discovery, ttl = 600, minRefresh = 10, httpTimeout = 10, fetch, now = () => Date.now() / 1000 }) {
  let keys = null; // Map<kid, KeyObject>
  let fetchedAt = -Infinity; // момент последней успешной загрузки
  let attemptedAt = -Infinity; // момент последней попытки (успешной или нет) — для лимита частоты
  let inflight = null;
  let fetchCount = 0;

  async function resolveUri() {
    if (jwksUri) return jwksUri;
    if (!discovery) throw new Error("JWKS: не задан ни jwksUri, ни discovery");
    return discovery.endpoint("jwks_uri");
  }

  function parse(set) {
    const map = new Map();
    for (const k of Array.isArray(set?.keys) ? set.keys : []) {
      // Принимаем только RSA для подписи; битые n/e пропускаем, не роняя весь набор.
      if (!k || k.kty !== "RSA" || (k.use && k.use !== "sig") || typeof k.kid !== "string") continue;
      try {
        map.set(k.kid, createPublicKey({ key: { kty: "RSA", n: k.n, e: k.e }, format: "jwk" }));
      } catch {
        /* некорректный ключ — пропускаем */
      }
    }
    return map;
  }

  async function load() {
    attemptedAt = now();
    fetchCount++;
    const uri = await resolveUri();
    const res = await fetchWithTimeout(fetch, uri, { headers: { Accept: "application/json" } }, httpTimeout);
    if (!res.ok) throw new Error(`JWKS ${uri}: HTTP ${res.status}`);
    keys = parse(await res.json());
    fetchedAt = now();
  }

  /** Перечитывание: одновременные вызовы ждут один запрос. Ошибка сети глотается, если старый набор есть. */
  async function refresh() {
    if (!inflight) {
      inflight = load().finally(() => {
        inflight = null;
      });
    }
    try {
      await inflight;
    } catch (e) {
      if (!keys) throw e;
    }
  }

  return {
    /** Ключ по kid или undefined (после попытки перечитать с учётом лимита частоты). */
    async getKey(kid) {
      if (!keys || now() - fetchedAt >= ttl) await refresh();
      if (keys.has(kid)) return keys.get(kid);
      if (now() - attemptedAt >= minRefresh) {
        await refresh();
        return keys.get(kid);
      }
      return undefined;
    },
    /** Число обращений к JWKS (для тестов и метрик). */
    get fetchCount() {
      return fetchCount;
    },
  };
}
