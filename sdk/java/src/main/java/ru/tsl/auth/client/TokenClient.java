package ru.tsl.auth.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/**
 * Клиент token endpoint (§6): client_credentials с кэшем и single-flight, exchange, refresh, password,
 * authorization_code, introspect, revoke. client_id всегда в теле, client_secret — если задан.
 */
public final class TokenClient {
    /** Ответ /connect/introspect. */
    public static final class Introspection {
        private final boolean active;
        private final Map<String, Object> claims;

        Introspection(Map<String, Object> claims) {
            this.claims = Collections.unmodifiableMap(claims);
            this.active = Boolean.TRUE.equals(claims.get("active"));
        }

        public boolean active() { return active; }
        public Map<String, Object> claims() { return claims; }
    }

    private static final Duration CACHE_MARGIN = Duration.ofSeconds(30);

    private final TslAuthOptions options;
    private final Discovery discovery;
    private final Object cacheLock = new Object();
    private final Map<String, TokenSet> serviceTokens = new HashMap<>();

    public TokenClient(TslAuthOptions options) {
        this(options, new Discovery(options));
    }

    public TokenClient(TslAuthOptions options, Discovery discovery) {
        this.options = options;
        this.discovery = discovery;
    }

    public static TokenClient fromEnvironment() {
        return new TokenClient(TslAuthOptions.fromEnvironment().build());
    }

    /** Сервисный токен; кэшируется по scope до expiresAt − 30 с, параллельные вызовы делают один запрос. */
    public TokenSet clientCredentials(String... scopes) {
        String scope = joinScopes(scopes);
        Instant now = options.clock().instant();
        synchronized (cacheLock) {
            TokenSet cached = serviceTokens.get(scope);
            if (cached != null && cached.expiresAt() != null && now.isBefore(cached.expiresAt().minus(CACHE_MARGIN))) {
                return cached;
            }
            Map<String, String> form = form("client_credentials");
            if (!scope.isEmpty()) form.put("scope", scope);
            TokenSet fresh = token(form); // ошибка запроса кэш не портит
            serviceTokens.put(scope, fresh);
            return fresh;
        }
    }

    /** Token exchange (RFC 8693) — не кэшируется, токен привязан к пользователю. */
    public TokenSet exchange(String subjectToken, String... scopes) {
        Map<String, String> form = form("urn:ietf:params:oauth:grant-type:token-exchange");
        form.put("subject_token", subjectToken);
        form.put("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        String scope = joinScopes(scopes);
        if (!scope.isEmpty()) form.put("scope", scope);
        return token(form);
    }

    /** Обновление; ответ содержит новый refresh_token — старый использовать нельзя. */
    public TokenSet refresh(String refreshToken, String... scopes) {
        Map<String, String> form = form("refresh_token");
        form.put("refresh_token", refreshToken);
        String scope = joinScopes(scopes);
        if (!scope.isEmpty()) form.put("scope", scope);
        return token(form);
    }

    /** Только для серверных приложений. */
    public TokenSet password(String username, String password, String... scopes) {
        Map<String, String> form = form("password");
        form.put("username", username);
        form.put("password", password);
        String scope = joinScopes(scopes);
        if (!scope.isEmpty()) form.put("scope", scope);
        return token(form);
    }

    /** Обмен кода авторизации; PKCE обязателен. */
    public TokenSet authorizationCode(String code, String redirectUri, String codeVerifier) {
        Map<String, String> form = form("authorization_code");
        form.put("code", code);
        form.put("redirect_uri", redirectUri);
        form.put("code_verifier", codeVerifier);
        return token(form);
    }

    public Introspection introspect(String token) {
        Map<String, String> form = clientForm();
        form.put("token", token);
        String endpoint = endpoint(d -> d.introspectionEndpoint, "introspection_endpoint");
        return new Introspection(post(endpoint, form));
    }

    /** Отзыв токена; успех — 200. */
    public void revoke(String token) {
        Map<String, String> form = clientForm();
        form.put("token", token);
        String endpoint = endpoint(d -> d.revocationEndpoint, "revocation_endpoint");
        post(endpoint, form);
    }

    // ---------- внутреннее ----------

    private interface EndpointSelector {
        String select(Discovery.Document d);
    }

    private String endpoint(EndpointSelector selector, String name) {
        try {
            String url = selector.select(discovery.get());
            if (url == null) throw new TokenException("unavailable", "discovery не содержит " + name, 0);
            return url;
        } catch (IOException e) {
            throw new TokenException("unavailable", "discovery недоступен: " + e.getMessage(), 0, e);
        }
    }

    private Map<String, String> clientForm() {
        Map<String, String> form = new LinkedHashMap<>();
        if (options.clientId() == null) throw new TokenException("invalid_client", "TSL_AUTH_CLIENT_ID не задан", 0);
        form.put("client_id", options.clientId());
        if (options.clientSecret() != null) form.put("client_secret", options.clientSecret());
        return form;
    }

    private Map<String, String> form(String grantType) {
        Map<String, String> form = clientForm();
        form.put("grant_type", grantType);
        return form;
    }

    private TokenSet token(Map<String, String> form) {
        Instant now = options.clock().instant();
        String endpoint = endpoint(d -> d.tokenEndpoint, "token_endpoint");
        return TokenSet.from(post(endpoint, form), now);
    }

    private Map<String, Object> post(String url, Map<String, String> form) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (body.length() > 0) body.append('&');
            body.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(options.httpTimeout())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> resp;
        try {
            resp = options.httpClient().send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new TokenException("unavailable", e.getMessage(), 0, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenException("unavailable", "прервано", 0, e);
        }
        int status = resp.statusCode();
        Map<String, Object> json = null;
        if (resp.body() != null && !resp.body().isBlank()) {
            try {
                json = Json.parseObject(resp.body());
            } catch (IOException ignored) {
                // не JSON — ниже обработается по статусу
            }
        }
        if (status >= 200 && status < 300) {
            return json != null ? json : Collections.emptyMap();
        }
        if (status >= 400 && status < 500 && json != null && json.get("error") != null) {
            Object desc = json.get("error_description");
            throw new TokenException(json.get("error").toString(), desc == null ? null : desc.toString(), status);
        }
        throw new TokenException("unavailable", "HTTP " + status, status);
    }

    /** Нормализованный scope — ключ кэша не зависит от порядка. */
    private static String joinScopes(String... scopes) {
        TreeSet<String> set = new TreeSet<>();
        if (scopes != null) {
            for (String s : scopes) {
                if (s == null) continue;
                for (String part : s.split(" ")) if (!part.isEmpty()) set.add(part);
            }
        }
        return String.join(" ", set);
    }
}
