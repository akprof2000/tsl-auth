// Типы @tsl/auth-client (вход Node.js). Соответствуют docs/client-contract.md.

/** Код ошибки проверки токена (§2). */
export type VerifyErrorCode =
  | "missing"
  | "malformed"
  | "unsupported_alg"
  | "unknown_key"
  | "bad_signature"
  | "bad_issuer"
  | "expired"
  | "not_yet_valid"
  | "bad_audience"
  | "revoked"
  | "introspection_unavailable"
  | "jwks_unavailable";

export class TslAuthError extends Error {
  constructor(code: VerifyErrorCode | string, message?: string);
  readonly code: VerifyErrorCode | string;
}

export class TokenError extends Error {
  constructor(error: string, errorDescription?: string, status?: number);
  /** Код OAuth 2.0 (`invalid_grant`, `invalid_client`, …) или `unavailable` для сети/5xx. */
  readonly error: string;
  readonly errorDescription: string;
  /** HTTP-статус ответа; 0, если ответа не было. */
  readonly status: number;
}

/** Часы: функция, возвращающая Date или число секунд unix; либо константа в секундах. */
export type Clock = (() => Date | number) | number;

export interface CommonOptions {
  /** Адрес сервиса, как в `iss` токена (или TSL_AUTH_ISSUER). */
  issuer?: string;
  /** Прямой адрес JWKS вместо discovery (или TSL_AUTH_JWKS_URI). */
  jwksUri?: string;
  /** client_id приложения (или TSL_AUTH_CLIENT_ID). */
  clientId?: string;
  /** Секрет confidential-клиента (или TSL_AUTH_CLIENT_SECRET). */
  clientSecret?: string;
  /** Допуск на расхождение часов, с (30). */
  clockSkew?: number;
  /** Срок кэша ключей и discovery, с (600). */
  jwksTtl?: number;
  /** Минимальный интервал перечитывания JWKS по неизвестному kid, с (10). */
  jwksMinRefresh?: number;
  /** Таймаут HTTP-запросов, с (10). */
  httpTimeout?: number;
  /** Инжектируемые часы. */
  now?: Clock;
  /** Своя реализация fetch (по умолчанию глобальная). */
  fetch?: typeof fetch;
}

export interface VerifierOptions extends CommonOptions {
  /** client_id этого API (или TSL_AUTH_AUDIENCE). */
  audience?: string;
  /** После локальной проверки спрашивать introspection_endpoint (или TSL_AUTH_INTROSPECT). */
  introspect?: boolean;
  /** Готовый клиент токенов для introspection. */
  tokenClient?: TokenClient;
  discovery?: Discovery;
  jwks?: JwksCache;
}

export interface Actor {
  sub: string;
  act?: Actor;
}

/** Principal (§4). */
export interface Principal {
  readonly subject?: string;
  readonly subjectType?: "user" | "client" | string;
  readonly username?: string;
  readonly name?: string;
  readonly email?: string;
  /** Роли этого API без префикса `<audience>:`. */
  readonly roles: string[];
  /** Разрешения этого API без префикса `<audience>:`. */
  readonly permissions: string[];
  readonly allRoles: string[];
  readonly allPermissions: string[];
  readonly scopes: string[];
  readonly amr: string[];
  readonly isMfa: boolean;
  readonly actor: Actor | null;
  readonly expiresAt?: Date;
  readonly claims: Record<string, unknown>;
  hasPermission(permission: string): boolean;
  hasAnyPermission(permissions: string[]): boolean;
  hasRole(role: string): boolean;
}

export interface JwksCache {
  getKey(kid: string): Promise<import("node:crypto").KeyObject | undefined>;
  readonly fetchCount: number;
}

export interface Discovery {
  get(): Promise<Record<string, any>>;
  endpoint(name: string): Promise<string>;
}

export interface Verifier {
  /** Проверка access-токена; отказ — TslAuthError с `code`. */
  verify(token: string): Promise<Principal>;
  /** Проверка по значению заголовка Authorization; отсутствие — `missing`. */
  verifyAuthorization(header: string | undefined): Promise<Principal>;
  readonly audience: string | undefined;
  readonly jwks: JwksCache;
}

export function createVerifier(options?: VerifierOptions): Verifier;
export function bearerFromHeader(header: string | undefined): string | undefined;
export function createPrincipal(claims: Record<string, unknown>, audience?: string): Principal;
export function createJwksCache(options: {
  jwksUri?: string;
  discovery?: Discovery;
  ttl?: number;
  minRefresh?: number;
  httpTimeout?: number;
  fetch: typeof fetch;
  now?: () => number;
}): JwksCache;
export function createDiscovery(options: { issuer: string; ttl?: number; httpTimeout?: number; fetch: typeof fetch; now?: () => number }): Discovery;
export function resolveConfig(options?: VerifierOptions): Record<string, unknown>;

/** Требования к principal (§5). */
export interface Requirements {
  permission?: string;
  anyPermission?: string[];
  role?: string;
  mfa?: boolean;
  subjectType?: "user" | "client" | string;
}

export interface MiddlewareOptions extends VerifierOptions, Requirements {
  /** Готовый verifier вместо параметров. */
  verifier?: Verifier;
  /** Вызывается при отказе 401 (для журналирования; токен не передаётся). */
  onError?: (error: Error, req: unknown) => void;
}

export type AuthenticatedRequest = import("node:http").IncomingMessage & { auth: Principal };

export interface Middleware {
  (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse, next?: (err?: unknown) => unknown): Promise<void>;
  /** Тот же verifier, дополнительные требования. */
  require(requirements: Requirements): Middleware;
  /** Обёртка для node:http: `(req, res) => …`, обработчик вызывается только при успехе. */
  protect<Req extends import("node:http").IncomingMessage, Res extends import("node:http").ServerResponse>(
    handler: (req: Req & { auth: Principal }, res: Res) => unknown,
    requirements?: Requirements,
  ): (req: Req, res: Res) => Promise<void>;
  readonly verifier: Verifier;
}

export function tslAuth(options?: MiddlewareOptions): Middleware;
export function checkRequirements(
  principal: Principal,
  requirements: Requirements,
  audience?: string,
): { error: string; description: string } | null;

/** Ответ token endpoint (§6). */
export interface TokenSet {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  /** Вычислен из expires_in в момент получения. */
  readonly expiresAt?: Date;
  readonly scope?: string;
  readonly tokenType: string;
  readonly raw: Record<string, unknown>;
}

export type Scopes = string | string[] | undefined;

export interface TokenClient {
  clientCredentials(scopes?: Scopes): Promise<TokenSet>;
  exchange(subjectToken: string, scopes?: Scopes): Promise<TokenSet>;
  refresh(refreshToken: string, scopes?: Scopes): Promise<TokenSet>;
  password(username: string, password: string, scopes?: Scopes): Promise<TokenSet>;
  authorizationCode(code: string, redirectUri: string, codeVerifier: string): Promise<TokenSet>;
  introspect(token: string): Promise<{ active: boolean; [claim: string]: unknown }>;
  revoke(token: string): Promise<void>;
  clearCache(): void;
}

export interface TokenClientOptions extends CommonOptions {
  discovery?: Discovery;
}

export function createTokenClient(options?: TokenClientOptions): TokenClient;
