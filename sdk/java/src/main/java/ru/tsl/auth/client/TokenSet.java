package ru.tsl.auth.client;

import java.time.Instant;
import java.util.Map;

/** Ответ token endpoint (§6). expiresAt вычислен из expires_in в момент получения. */
public final class TokenSet {
    private final String accessToken;
    private final String refreshToken;
    private final String idToken;
    private final Instant expiresAt;
    private final String scope;
    private final String tokenType;

    public TokenSet(String accessToken, String refreshToken, String idToken, Instant expiresAt, String scope, String tokenType) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
        this.expiresAt = expiresAt;
        this.scope = scope;
        this.tokenType = tokenType;
    }

    static TokenSet from(Map<String, Object> body, Instant now) {
        Object expiresIn = body.get("expires_in");
        Instant expiresAt = expiresIn instanceof Number ? now.plusSeconds(((Number) expiresIn).longValue()) : null;
        return new TokenSet(str(body.get("access_token")), str(body.get("refresh_token")), str(body.get("id_token")),
                expiresAt, str(body.get("scope")), str(body.get("token_type")));
    }

    private static String str(Object v) {
        return v == null ? null : v.toString();
    }

    public String accessToken() { return accessToken; }
    /** null, если сервер не выдал refresh-токен. */
    public String refreshToken() { return refreshToken; }
    public String idToken() { return idToken; }
    public Instant expiresAt() { return expiresAt; }
    public String scope() { return scope; }
    public String tokenType() { return tokenType; }

    @Override
    public String toString() {
        // Токены в журналы не попадают.
        return "TokenSet{expiresAt=" + expiresAt + ", scope=" + scope + "}";
    }
}
