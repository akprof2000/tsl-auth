// Middleware (§5 контракта): `(req, res, next)` для Express/Connect и обёртка `protect` для чистого node:http.
// Ответы 401/403 — JSON и WWW-Authenticate по RFC 6750; из токена в ответ не попадает ничего, кроме кода.
import { TslAuthError } from "./errors.js";
import { bearerFromHeader, createVerifier } from "./verifier.js";

const REQUIREMENT_KEYS = ["permission", "anyPermission", "role", "mfa", "subjectType"];

const quote = (s) => `"${String(s).replace(/["\\]/g, "")}"`;

function reject(res, status, error, description) {
  const body = JSON.stringify({ error, error_description: description });
  res.statusCode = status;
  res.setHeader("WWW-Authenticate", `Bearer realm="tsl-auth", error=${quote(error)}, error_description=${quote(description)}`);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.end(body);
}

/** Проверяет требования к principal; возвращает `{ error, description }` или null. */
export function checkRequirements(principal, req, audience) {
  const aud = audience ?? "";
  if (req.permission !== undefined && !principal.hasPermission(req.permission))
    return { error: "insufficient_permissions", description: `${aud}:${req.permission}` };
  if (Array.isArray(req.anyPermission) && req.anyPermission.length > 0 && !principal.hasAnyPermission(req.anyPermission))
    return { error: "insufficient_permissions", description: req.anyPermission.map((p) => `${aud}:${p}`).join(" ") };
  if (req.role !== undefined && !principal.hasRole(req.role)) return { error: "insufficient_role", description: `${aud}:${req.role}` };
  if (req.mfa === true && !principal.isMfa) return { error: "mfa_required", description: "mfa" };
  if (req.subjectType !== undefined && principal.subjectType !== req.subjectType)
    return { error: "subject_type_not_allowed", description: req.subjectType };
  return null;
}

const pick = (o) => Object.fromEntries(REQUIREMENT_KEYS.filter((k) => o[k] !== undefined).map((k) => [k, o[k]]));

/**
 * `tslAuth(options)` → middleware. options: параметры createVerifier (или готовый `verifier`) плюс требования
 * `permission`, `anyPermission`, `role`, `mfa`, `subjectType`. Principal — в `req.auth`.
 * `.require(requirements)` — тот же verifier, другие требования; `.protect(handler, requirements)` — для node:http.
 */
export function tslAuth(options = {}) {
  const verifier = options.verifier ?? createVerifier(options);
  const onError = typeof options.onError === "function" ? options.onError : null;

  const build = (requirements) => {
    const middleware = async (req, res, next) => {
      const token = bearerFromHeader(req.headers?.authorization);
      let principal;
      try {
        if (token === undefined) throw new TslAuthError("missing", "нет заголовка Authorization: Bearer");
        principal = await verifier.verify(token);
      } catch (e) {
        const code = e instanceof TslAuthError ? e.code : "invalid_token";
        onError?.(e, req);
        return reject(res, 401, "invalid_token", code);
      }
      req.auth = principal;
      const denied = checkRequirements(principal, requirements, verifier.audience);
      if (denied) return reject(res, 403, denied.error, denied.description);
      if (typeof next === "function") {
        try {
          await next();
        } catch (e) {
          // Express передаёт ошибку дальше через next(err); в node:http пробрасываем.
          if (next.length > 0) return next(e);
          throw e;
        }
      }
    };
    middleware.require = (more) => build({ ...requirements, ...pick(more ?? {}) });
    middleware.protect = (handler, more) => {
      const mw = more ? middleware.require(more) : middleware;
      return (req, res) => mw(req, res, () => handler(req, res));
    };
    middleware.verifier = verifier;
    return middleware;
  };

  return build(pick(options));
}
