// Discovery (`/.well-known/openid-configuration`) с кэшем в памяти на JWKS_TTL и single-flight.
import { fetchWithTimeout, normalizeIssuer } from "./config.js";

export function createDiscovery({ issuer, ttl = 600, httpTimeout = 10, fetch, now = () => Date.now() / 1000 }) {
  const url = `${normalizeIssuer(issuer)}/.well-known/openid-configuration`;
  let cached = null;
  let fetchedAt = -Infinity;
  let inflight = null;

  async function load() {
    const res = await fetchWithTimeout(fetch, url, { headers: { Accept: "application/json" } }, httpTimeout);
    if (!res.ok) throw new Error(`discovery ${url}: HTTP ${res.status}`);
    const doc = await res.json();
    if (!doc || typeof doc !== "object") throw new Error(`discovery ${url}: не JSON-объект`);
    cached = doc;
    fetchedAt = now();
    return doc;
  }

  return {
    /** Документ discovery; при протухшем кэше и ошибке сети возвращает старый документ. */
    async get() {
      if (cached && now() - fetchedAt < ttl) return cached;
      if (!inflight) {
        inflight = load().finally(() => {
          inflight = null;
        });
      }
      try {
        return await inflight;
      } catch (e) {
        if (cached) return cached;
        throw e;
      }
    },
    /** Адрес эндпоинта по имени (`token_endpoint` и т. п.). */
    async endpoint(name) {
      const doc = await this.get();
      const value = doc[name];
      if (!value) throw new Error(`discovery: в документе нет ${name}`);
      return value;
    },
  };
}
