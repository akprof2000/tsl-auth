// Настройки из переменных окружения (§1 контракта). Явные параметры имеют приоритет.

const env = (name) => (typeof process !== "undefined" && process.env ? process.env[name] : undefined);

const num = (value, fallback) => {
  if (value === undefined || value === null || value === "") return fallback;
  const n = Number(value);
  if (!Number.isFinite(n)) throw new TypeError(`TSL Auth: ожидалось число, получено "${value}"`);
  return n;
};

const bool = (value, fallback) => {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
};

/** Убирает завершающий `/`: `https://auth.corp` ≡ `https://auth.corp/`. */
export const normalizeIssuer = (iss) => (typeof iss === "string" ? iss.replace(/\/+$/, "") : iss);

/** Сливает явные параметры с окружением и значениями по умолчанию. */
export function resolveConfig(options = {}) {
  const cfg = {
    issuer: options.issuer ?? env("TSL_AUTH_ISSUER"),
    audience: options.audience ?? env("TSL_AUTH_AUDIENCE"),
    clientId: options.clientId ?? env("TSL_AUTH_CLIENT_ID"),
    clientSecret: options.clientSecret ?? env("TSL_AUTH_CLIENT_SECRET"),
    jwksUri: options.jwksUri ?? env("TSL_AUTH_JWKS_URI"),
    clockSkew: num(options.clockSkew ?? env("TSL_AUTH_CLOCK_SKEW_SECONDS"), 30),
    jwksTtl: num(options.jwksTtl ?? env("TSL_AUTH_JWKS_TTL_SECONDS"), 600),
    jwksMinRefresh: num(options.jwksMinRefresh ?? env("TSL_AUTH_JWKS_MIN_REFRESH_SECONDS"), 10),
    introspect: bool(options.introspect ?? env("TSL_AUTH_INTROSPECT"), false),
    httpTimeout: num(options.httpTimeout ?? env("TSL_AUTH_HTTP_TIMEOUT_SECONDS"), 10),
    fetch: options.fetch ?? globalThis.fetch,
    now: makeClock(options.now),
  };
  if (!cfg.issuer) throw new TypeError("TSL Auth: не задан issuer (параметр issuer или TSL_AUTH_ISSUER)");
  if (typeof cfg.fetch !== "function") throw new TypeError("TSL Auth: недоступен fetch (нужен Node 18+ или параметр fetch)");
  return cfg;
}

/** Часы: опция `now` — функция, возвращающая Date или число секунд; результат — функция «секунды unix». */
export function makeClock(now) {
  if (now === undefined || now === null) return () => Date.now() / 1000;
  const read = typeof now === "function" ? now : () => now;
  return () => {
    const v = read();
    if (v instanceof Date) return v.getTime() / 1000;
    if (typeof v === "number") return v;
    throw new TypeError("TSL Auth: now() должна возвращать Date или число секунд");
  };
}

/** fetch с таймаутом (секунды) и без передачи чего-либо лишнего. */
export function fetchWithTimeout(fetchFn, url, init, timeoutSeconds) {
  const signal = timeoutSeconds > 0 && typeof AbortSignal?.timeout === "function" ? AbortSignal.timeout(timeoutSeconds * 1000) : undefined;
  return fetchFn(url, { ...init, signal });
}
