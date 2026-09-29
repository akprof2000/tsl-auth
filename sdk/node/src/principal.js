// Principal (§4 контракта): нормализованный взгляд на claims access-токена для одного API (audience).

/** Claim-список может прийти строкой или массивом; отсутствующий — пустой список. */
export const toList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : typeof v === "string" ? [v] : []);

/** Оставляет значения вида `<audience>:<x>` с обрезанным префиксом. */
const forAudience = (values, audience) => {
  const prefix = `${audience}:`;
  return values.filter((v) => v.startsWith(prefix)).map((v) => v.slice(prefix.length));
};

/** Цепочка token exchange `act` → `{ sub, act? }` или null. */
const actor = (act) => {
  if (!act || typeof act !== "object" || typeof act.sub !== "string") return null;
  const nested = actor(act.act);
  return nested ? { sub: act.sub, act: nested } : { sub: act.sub };
};

export function createPrincipal(claims, audience) {
  const allRoles = toList(claims.role);
  const allPermissions = toList(claims.permissions);
  const roles = audience ? forAudience(allRoles, audience) : [];
  const permissions = audience ? forAudience(allPermissions, audience) : [];
  const amr = toList(claims.amr);
  const principal = {
    subject: typeof claims.sub === "string" ? claims.sub : undefined,
    subjectType: typeof claims.subject_type === "string" ? claims.subject_type : undefined,
    username: typeof claims.preferred_username === "string" ? claims.preferred_username : undefined,
    name: typeof claims.name === "string" ? claims.name : undefined,
    email: typeof claims.email === "string" ? claims.email : undefined,
    roles,
    permissions,
    allRoles,
    allPermissions,
    scopes: typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : toList(claims.scope),
    amr,
    isMfa: amr.includes("mfa"),
    actor: actor(claims.act),
    expiresAt: typeof claims.exp === "number" ? new Date(claims.exp * 1000) : undefined,
    claims,
    /** Только короткая форма (`orders.read`); полная (`api:orders.read`) намеренно не принимается. */
    hasPermission: (p) => permissions.includes(p),
    hasAnyPermission: (list) => list.some((p) => permissions.includes(p)),
    hasRole: (r) => roles.includes(r),
  };
  return Object.freeze(principal);
}
