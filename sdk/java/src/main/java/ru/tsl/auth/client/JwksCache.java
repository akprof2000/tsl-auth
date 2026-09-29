package ru.tsl.auth.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Кэш ключей подписи (§3): ленивая загрузка, TTL, перечитывание по неизвестному kid не чаще jwksMinRefresh,
 * single-flight (перечитывает один поток, остальные ждут), старый набор при ошибке сети.
 */
public final class JwksCache {
    private static final class Snapshot {
        final Map<String, RSAPublicKey> keys;
        final Instant fetchedAt;

        Snapshot(Map<String, RSAPublicKey> keys, Instant fetchedAt) {
            this.keys = keys;
            this.fetchedAt = fetchedAt;
        }
    }

    private final TslAuthOptions options;
    private final Discovery discovery;
    private final Object lock = new Object();
    private volatile Snapshot snapshot;
    private Instant lastAttempt;

    public JwksCache(TslAuthOptions options, Discovery discovery) {
        this.options = options;
        this.discovery = discovery;
    }

    /** Ключ по kid или null, если его нет даже после перечитывания. */
    public RSAPublicKey getKey(String kid) throws IOException {
        Instant now = options.clock().instant();
        Snapshot s = snapshot;
        if (s == null || !s.fetchedAt.plus(options.jwksTtl()).isAfter(now)) {
            s = refresh(s, now, true);
        }
        RSAPublicKey key = s.keys.get(kid);
        if (key != null) return key;
        // Неизвестный kid: возможно, ротация ключей — перечитываем, но не чаще jwksMinRefresh.
        s = refresh(s, now, false);
        return s.keys.get(kid);
    }

    /**
     * Перечитывает JWKS под замком. Если другой поток уже обновил кэш после снимка seen — берём его результат.
     * required=true (кэш пуст или протух): ошибка сети роняет проверку только при отсутствии старого набора.
     * required=false (неизвестный kid): действует лимит частоты, ошибки сети игнорируются.
     */
    private Snapshot refresh(Snapshot seen, Instant now, boolean required) throws IOException {
        synchronized (lock) {
            Snapshot current = snapshot;
            if (current != null && current != seen) {
                return current; // single-flight: соседний поток уже перечитал
            }
            if (!required && lastAttempt != null && now.isBefore(lastAttempt.plus(options.jwksMinRefresh()))) {
                return current != null ? current : new Snapshot(Collections.emptyMap(), now);
            }
            lastAttempt = now;
            try {
                current = new Snapshot(fetch(), now);
                snapshot = current;
                return current;
            } catch (IOException e) {
                if (current != null) return current;
                if (required) throw e;
                return new Snapshot(Collections.emptyMap(), now);
            }
        }
    }

    private String jwksUri() throws IOException {
        if (options.jwksUri() != null) return options.jwksUri();
        String uri = discovery.get().jwksUri;
        if (uri == null) throw new IOException("discovery не содержит jwks_uri");
        return uri;
    }

    private Map<String, RSAPublicKey> fetch() throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(jwksUri())).timeout(options.httpTimeout()).GET().build();
        HttpResponse<byte[]> resp;
        try {
            resp = options.httpClient().send(req, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("jwks: прервано", e);
        }
        if (resp.statusCode() != 200) throw new IOException("jwks: HTTP " + resp.statusCode());
        return parse(Json.parseObject(resp.body()));
    }

    /** Только kty=RSA с use отсутствующим или sig; ключи с некорректными n/e пропускаются. */
    static Map<String, RSAPublicKey> parse(Map<String, Object> jwks) {
        Map<String, RSAPublicKey> result = new HashMap<>();
        Object keys = jwks.get("keys");
        if (!(keys instanceof List)) return result;
        for (Object o : (List<?>) keys) {
            if (!(o instanceof Map)) continue;
            Map<?, ?> k = (Map<?, ?>) o;
            if (!"RSA".equals(k.get("kty"))) continue;
            Object use = k.get("use");
            if (use != null && !"sig".equals(use)) continue;
            Object kid = k.get("kid");
            if (!(kid instanceof String) || !(k.get("n") instanceof String) || !(k.get("e") instanceof String)) continue;
            try {
                BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode((String) k.get("n")));
                BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode((String) k.get("e")));
                if (n.signum() <= 0 || e.signum() <= 0) continue;
                RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
                result.put((String) kid, key);
            } catch (Exception ignored) {
                // некорректный ключ пропускаем, остальной набор используется
            }
        }
        return result;
    }
}
