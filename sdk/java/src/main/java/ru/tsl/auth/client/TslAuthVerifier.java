package ru.tsl.auth.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Проверка access-токена по §2–§3 контракта: порядок шагов и коды ошибок фиксированы. */
public final class TslAuthVerifier {
    private final TslAuthOptions options;
    private final Discovery discovery;
    private final JwksCache jwks;
    private final TokenClient tokenClient;

    public TslAuthVerifier(TslAuthOptions options) {
        this.options = options;
        this.discovery = new Discovery(options);
        this.jwks = new JwksCache(options, discovery);
        this.tokenClient = new TokenClient(options, discovery);
    }

    /** Verifier из переменных окружения TSL_AUTH_*. */
    public static TslAuthVerifier fromEnvironment() {
        return new TslAuthVerifier(TslAuthOptions.fromEnvironment().build());
    }

    public TslAuthOptions options() { return options; }
    public Discovery discovery() { return discovery; }
    public JwksCache jwksCache() { return jwks; }

    /**
     * Извлекает токен из заголовка Authorization (схема Bearer без учёта регистра).
     * @return токен или null, если заголовка нет, схема иная или токен пуст (код missing)
     */
    public static String extractBearer(String authorization) {
        if (authorization == null) return null;
        String h = authorization.trim();
        if (h.length() < 7 || !h.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        String token = h.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    /** Проверяет заголовок Authorization: отсутствие токена — missing, далее как {@link #verify(String)}. */
    public Principal verifyAuthorization(String authorization) {
        String token = extractBearer(authorization);
        if (token == null) throw new TslAuthException("missing", "Токен не передан");
        return verify(token);
    }

    /** Проверяет JWT; при неудаче — {@link TslAuthException} с кодом из §2. */
    public Principal verify(String token) {
        if (token == null || token.isEmpty()) throw new TslAuthException("malformed", "Пустой токен");
        // 2. Три части, заголовок и payload — JSON в base64url
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) throw new TslAuthException("malformed", "Ожидались три части токена");
        Map<String, Object> header;
        Map<String, Object> payload;
        try {
            header = Json.parseObject(Base64.getUrlDecoder().decode(parts[0]));
            payload = Json.parseObject(Base64.getUrlDecoder().decode(parts[1]));
        } catch (IOException | IllegalArgumentException e) {
            throw new TslAuthException("malformed", "Заголовок или payload не разбирается", e);
        }
        // 3. Только RS256 — до любых обращений к ключам
        if (!"RS256".equals(header.get("alg"))) {
            throw new TslAuthException("unsupported_alg", "Алгоритм не поддерживается");
        }
        // 4. kid
        Object kid = header.get("kid");
        if (!(kid instanceof String) || ((String) kid).isEmpty()) {
            throw new TslAuthException("malformed", "В заголовке нет kid");
        }
        // 5. Ключ из кэша JWKS
        RSAPublicKey key;
        try {
            key = jwks.getKey((String) kid);
        } catch (IOException e) {
            throw new TslAuthException("jwks_unavailable", "Не удалось загрузить ключи подписи", e);
        }
        if (key == null) throw new TslAuthException("unknown_key", "Ключ подписи не найден");
        // 6. Подпись RSASSA-PKCS1-v1_5 / SHA-256
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(key);
            sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!sig.verify(Base64.getUrlDecoder().decode(parts[2]))) {
                throw new TslAuthException("bad_signature", "Подпись неверна");
            }
        } catch (TslAuthException e) {
            throw e;
        } catch (Exception e) {
            throw new TslAuthException("bad_signature", "Подпись не проверяется", e);
        }
        // 7. iss
        Object iss = payload.get("iss");
        if (!(iss instanceof String) || !TslAuthOptions.stripSlash((String) iss).equals(options.issuerNormalized())) {
            throw new TslAuthException("bad_issuer", "Издатель токена не совпадает");
        }
        // 8. exp / nbf с допуском
        long now = options.clock().instant().getEpochSecond();
        long skew = options.clockSkew().getSeconds();
        Object exp = payload.get("exp");
        if (!(exp instanceof Number) || now > ((Number) exp).longValue() + skew) {
            throw new TslAuthException("expired", "Срок токена истёк");
        }
        Object nbf = payload.get("nbf");
        if (nbf instanceof Number && now < ((Number) nbf).longValue() - skew) {
            throw new TslAuthException("not_yet_valid", "Токен ещё не действует");
        }
        // 9. aud содержит audience
        if (options.audience() != null) {
            List<String> aud = Principal.asList(payload.get("aud"));
            if (!aud.contains(options.audience())) {
                throw new TslAuthException("bad_audience", "Токен выдан не для этого API");
            }
        }
        // 10. Интроспекция (мгновенный отзыв)
        if (options.introspect()) {
            TokenClient.Introspection result;
            try {
                result = tokenClient.introspect(token);
            } catch (TokenException e) {
                throw new TslAuthException("introspection_unavailable", "Интроспекция недоступна", e);
            }
            if (!result.active()) throw new TslAuthException("revoked", "Токен отозван");
        }
        return new Principal(payload, options.audience());
    }

    /** Текущее время по часам SDK (для тестов и кэшей). */
    Instant now() {
        return options.clock().instant();
    }
}
