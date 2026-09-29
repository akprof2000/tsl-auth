// Типизированные ошибки SDK (docs/client-contract.md §2, §6).

/** Ошибка проверки access-токена: `code` — код из §2 контракта, текст описания не является частью контракта. */
export class TslAuthError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = "TslAuthError";
    this.code = code;
  }
}

/** Ошибка клиента токенов: `error` — код OAuth 2.0 (или `unavailable` для сети/5xx), `status` — HTTP-статус (0, если ответа не было). */
export class TokenError extends Error {
  constructor(error, errorDescription, status = 0) {
    super(errorDescription ? `${error}: ${errorDescription}` : error);
    this.name = "TokenError";
    this.error = error;
    this.errorDescription = errorDescription ?? "";
    this.status = status;
  }
}
