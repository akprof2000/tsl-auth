// Типы @tsl/auth-client/browser (§7 контракта).

export class BrowserAuthError extends Error {
  constructor(code: string, message?: string);
  /** `state_mismatch`, `missing_code`, `discovery_failed` или код ошибки OAuth 2.0 из ответа сервера. */
  readonly code: string;
}

export interface BrowserClientOptions {
  /** Адрес сервиса авторизации, например `https://auth.corp/`. */
  issuer: string;
  /** client_id public-клиента (SPA). */
  clientId: string;
  /** Scope через пробел (по умолчанию `openid`). */
  scope?: string;
  /** По умолчанию `${location.origin}/callback`. */
  redirectUri?: string;
  /** По умолчанию `${location.origin}/`. */
  postLogoutRedirectUri?: string;
  /** Часы (секунды unix) — для тестов. */
  now?: () => number;
}

export interface BrowserClient {
  /** Создаёт PKCE-пару и state, сохраняет в sessionStorage и ведёт на authorization_endpoint. Возвращает URL перехода. */
  login(options?: { extraParams?: Record<string, string> }): Promise<string>;
  /** Проверяет state, удаляет PKCE до обмена, чистит адресную строку и меняет code на токены. */
  handleCallback(): Promise<Record<string, unknown>>;
  /** Access-токен из хранилища; при скором истечении обновляет по refresh (single-flight); null, если сессии нет. */
  getAccessToken(): Promise<string | null>;
  /** fetch с `Authorization: Bearer` и автообновлением. */
  fetch(url: string | URL, init?: RequestInit): Promise<Response>;
  /** Очищает хранилище и ведёт на end_session_endpoint. Возвращает URL перехода. */
  logout(): Promise<string>;
  /**
   * Claims access-токена БЕЗ проверки подписи — только для интерфейса.
   * Доверять этим данным для решений о доступе нельзя: их проверяет API на сервере.
   */
  getClaims(): Record<string, unknown> | null;
  isLoggedIn(): boolean;
  getIdToken(): string | null;
  /** Очистить сессию без перехода на сервер. */
  clear(): void;
}

export function createBrowserClient(options: BrowserClientOptions): BrowserClient;
/** Декодирование payload JWT без проверки подписи; null при ошибке. */
export function decodeClaims(token: string): Record<string, unknown> | null;
