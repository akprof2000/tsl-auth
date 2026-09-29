package ru.tsl.auth.client;

/** Ошибка проверки токена. {@link #getCode()} — код из §2 контракта (missing, malformed, unsupported_alg, ...). */
public class TslAuthException extends RuntimeException {
    private final String code;

    public TslAuthException(String code, String message) {
        super(message);
        this.code = code;
    }

    public TslAuthException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
