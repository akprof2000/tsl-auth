package ru.tsl.auth.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Map;

/** Документ /.well-known/openid-configuration с кэшем на срок jwksTtl (§1). */
public final class Discovery {
    /** Адреса из discovery; null, если сервис не объявил конечную точку. */
    public static final class Document {
        public final String jwksUri;
        public final String tokenEndpoint;
        public final String introspectionEndpoint;
        public final String revocationEndpoint;
        public final String authorizationEndpoint;
        public final String endSessionEndpoint;

        Document(Map<String, Object> m) {
            jwksUri = str(m, "jwks_uri");
            tokenEndpoint = str(m, "token_endpoint");
            introspectionEndpoint = str(m, "introspection_endpoint");
            revocationEndpoint = str(m, "revocation_endpoint");
            authorizationEndpoint = str(m, "authorization_endpoint");
            endSessionEndpoint = str(m, "end_session_endpoint");
        }

        private static String str(Map<String, Object> m, String k) {
            Object v = m.get(k);
            return v == null ? null : v.toString();
        }
    }

    private final TslAuthOptions options;
    private final Object lock = new Object();
    private Document cached;
    private Instant fetchedAt;

    public Discovery(TslAuthOptions options) {
        this.options = options;
    }

    /** Документ discovery; загружается лениво, перечитывается по истечении jwksTtl. */
    public Document get() throws IOException {
        synchronized (lock) {
            Instant now = options.clock().instant();
            if (cached != null && fetchedAt.plus(options.jwksTtl()).isAfter(now)) {
                return cached;
            }
            try {
                cached = fetch();
                fetchedAt = now;
            } catch (IOException e) {
                if (cached == null) throw e;
                // Старый документ пригоден, пока не удастся перечитать.
            }
            return cached;
        }
    }

    private Document fetch() throws IOException {
        URI uri = URI.create(options.issuerNormalized() + "/.well-known/openid-configuration");
        HttpRequest req = HttpRequest.newBuilder(uri).timeout(options.httpTimeout()).GET().build();
        try {
            HttpResponse<byte[]> resp = options.httpClient().send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200) {
                throw new IOException("discovery: HTTP " + resp.statusCode());
            }
            return new Document(Json.parseObject(resp.body()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("discovery: прервано", e);
        }
    }
}
