package ru.tsl.auth.client;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Ответ 401/403 по RFC 6750 (§5): статус, заголовок WWW-Authenticate и тело JSON. */
public final class Challenge {
    public static final String ATTRIBUTE = "tslauth.principal";
    public static final String CONTENT_TYPE = "application/json; charset=utf-8";

    private final int status;
    private final String wwwAuthenticate;
    private final String body;

    private Challenge(int status, String error, String description) {
        this.status = status;
        this.wwwAuthenticate = "Bearer realm=\"tsl-auth\", error=\"" + error + "\", error_description=\"" + escape(description) + "\"";
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("error", error);
        json.put("error_description", description);
        this.body = Json.write(json);
    }

    /** 401: error=invalid_token, error_description=код §2. */
    public static Challenge unauthorized(String code) {
        return new Challenge(401, "invalid_token", code);
    }

    public static Challenge unauthorized(TslAuthException e) {
        return unauthorized(e.getCode());
    }

    /** 403: код и описание из {@link Require.Denial}. */
    public static Challenge forbidden(Require.Denial denial) {
        return new Challenge(403, denial.code(), denial.description());
    }

    public int status() { return status; }
    public String wwwAuthenticate() { return wwwAuthenticate; }
    public String body() { return body; }
    public byte[] bodyBytes() { return body.getBytes(StandardCharsets.UTF_8); }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
