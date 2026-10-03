// @tsl/auth-client — вход для Node.js: verifier, middleware, клиент токенов.
export { TslAuthError, TokenError } from "./errors.js";
export { createVerifier, bearerFromHeader } from "./verifier.js";
export { tslAuth, checkRequirements } from "./middleware.js";
export { createTokenClient, CONNECTION_TOKEN_GRANT } from "./token-client.js";
export { createPrincipal } from "./principal.js";
export { createJwksCache } from "./jwks.js";
export { createDiscovery } from "./discovery.js";
export { resolveConfig } from "./config.js";
