package ru.tsl.auth.client;

/** Ошибка клиента токенов (§6): 4xx с JSON error — как есть; сеть и 5xx — error = unavailable. */
public class TokenException extends RuntimeException {
    private final String error;
    private final String errorDescription;
    private final int status;

    public TokenException(String error, String errorDescription, int status) {
        this(error, errorDescription, status, null);
    }

    public TokenException(String error, String errorDescription, int status, Throwable cause) {
        super(error + (errorDescription != null ? ": " + errorDescription : ""), cause);
        this.error = error;
        this.errorDescription = errorDescription;
        this.status = status;
    }

    public String getError() { return error; }
    public String getErrorDescription() { return errorDescription; }
    /** HTTP-статус ответа; 0 — сетевая ошибка. */
    public int getStatus() { return status; }
}
