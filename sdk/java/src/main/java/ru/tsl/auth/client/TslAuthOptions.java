package ru.tsl.auth.client;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Настройки SDK (§1 контракта). Собираются билдером или из переменных окружения TSL_AUTH_*;
 * явные параметры имеют приоритет над окружением.
 */
public final class TslAuthOptions {
    private final String issuer;
    private final String audience;
    private final String clientId;
    private final String clientSecret;
    private final String jwksUri;
    private final Duration clockSkew;
    private final Duration jwksTtl;
    private final Duration jwksMinRefresh;
    private final boolean introspect;
    private final Duration httpTimeout;
    private final Clock clock;
    private final HttpClient httpClient;

    private TslAuthOptions(Builder b) {
        if (b.issuer == null || b.issuer.isBlank()) {
            throw new IllegalArgumentException("TSL_AUTH_ISSUER (issuer) обязателен");
        }
        this.issuer = b.issuer;
        this.audience = b.audience;
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.jwksUri = b.jwksUri;
        this.clockSkew = b.clockSkew;
        this.jwksTtl = b.jwksTtl;
        this.jwksMinRefresh = b.jwksMinRefresh;
        this.introspect = b.introspect;
        this.httpTimeout = b.httpTimeout;
        this.clock = b.clock;
        this.httpClient = b.httpClient != null ? b.httpClient
                : HttpClient.newBuilder().connectTimeout(b.httpTimeout).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Настройки из переменных окружения TSL_AUTH_* (§1). */
    public static Builder fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    public static Builder fromEnvironment(Map<String, String> env) {
        Builder b = new Builder();
        b.issuer = env.get("TSL_AUTH_ISSUER");
        b.audience = blankToNull(env.get("TSL_AUTH_AUDIENCE"));
        b.clientId = blankToNull(env.get("TSL_AUTH_CLIENT_ID"));
        b.clientSecret = blankToNull(env.get("TSL_AUTH_CLIENT_SECRET"));
        b.jwksUri = blankToNull(env.get("TSL_AUTH_JWKS_URI"));
        b.clockSkew = seconds(env, "TSL_AUTH_CLOCK_SKEW_SECONDS", b.clockSkew);
        b.jwksTtl = seconds(env, "TSL_AUTH_JWKS_TTL_SECONDS", b.jwksTtl);
        b.jwksMinRefresh = seconds(env, "TSL_AUTH_JWKS_MIN_REFRESH_SECONDS", b.jwksMinRefresh);
        b.httpTimeout = seconds(env, "TSL_AUTH_HTTP_TIMEOUT_SECONDS", b.httpTimeout);
        String intro = env.get("TSL_AUTH_INTROSPECT");
        b.introspect = intro != null && (intro.equalsIgnoreCase("true") || intro.trim().equals("1"));
        return b;
    }

    private static Duration seconds(Map<String, String> env, String name, Duration def) {
        String v = env.get(name);
        if (v == null || v.isBlank()) return def;
        return Duration.ofSeconds(Long.parseLong(v.trim()));
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }

    /** issuer без завершающего слэша — для сравнения с iss и сборки адресов. */
    public String issuerNormalized() {
        return stripSlash(issuer);
    }

    static String stripSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    public String issuer() { return issuer; }
    public String audience() { return audience; }
    public String clientId() { return clientId; }
    public String clientSecret() { return clientSecret; }
    public String jwksUri() { return jwksUri; }
    public Duration clockSkew() { return clockSkew; }
    public Duration jwksTtl() { return jwksTtl; }
    public Duration jwksMinRefresh() { return jwksMinRefresh; }
    public boolean introspect() { return introspect; }
    public Duration httpTimeout() { return httpTimeout; }
    public Clock clock() { return clock; }
    public HttpClient httpClient() { return httpClient; }

    public static final class Builder {
        private String issuer;
        private String audience;
        private String clientId;
        private String clientSecret;
        private String jwksUri;
        private Duration clockSkew = Duration.ofSeconds(30);
        private Duration jwksTtl = Duration.ofSeconds(600);
        private Duration jwksMinRefresh = Duration.ofSeconds(10);
        private boolean introspect;
        private Duration httpTimeout = Duration.ofSeconds(10);
        private Clock clock = Clock.systemUTC();
        private HttpClient httpClient;

        public Builder issuer(String v) { this.issuer = v; return this; }
        public Builder audience(String v) { this.audience = v; return this; }
        public Builder clientId(String v) { this.clientId = v; return this; }
        public Builder clientSecret(String v) { this.clientSecret = v; return this; }
        public Builder jwksUri(String v) { this.jwksUri = v; return this; }
        public Builder clockSkew(Duration v) { this.clockSkew = Objects.requireNonNull(v); return this; }
        public Builder jwksTtl(Duration v) { this.jwksTtl = Objects.requireNonNull(v); return this; }
        public Builder jwksMinRefresh(Duration v) { this.jwksMinRefresh = Objects.requireNonNull(v); return this; }
        public Builder introspect(boolean v) { this.introspect = v; return this; }
        public Builder httpTimeout(Duration v) { this.httpTimeout = Objects.requireNonNull(v); return this; }
        /** Часы для проверки exp/nbf и кэшей — подменяются в тестах. */
        public Builder clock(Clock v) { this.clock = Objects.requireNonNull(v); return this; }
        public Builder httpClient(HttpClient v) { this.httpClient = v; return this; }

        public TslAuthOptions build() {
            return new TslAuthOptions(this);
        }
    }
}
