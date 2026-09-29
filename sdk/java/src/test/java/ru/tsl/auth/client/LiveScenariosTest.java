package ru.tsl.auth.client;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** §8 п. 3: живые сценарии против стенда из vectors.json. */
class LiveScenariosTest {
    private static final String SCOPE = "openid offline_access " + Vectors.AUDIENCE;

    @Test
    void refresh_rotation() {
        TokenClient client = new TokenClient(Vectors.options().build());
        TokenSet first = client.password(Vectors.user("operator").get("username").asText(),
                Vectors.user("operator").get("password").asText(), SCOPE);
        assertNotNull(first.refreshToken());
        TokenSet second = client.refresh(first.refreshToken());
        assertNotNull(second.refreshToken());
        assertNotEquals(first.refreshToken(), second.refreshToken(), "refresh-токен ротируется");
        TokenSet third = client.refresh(second.refreshToken());
        assertNotNull(third.accessToken(), "новый refresh работает повторно");
        client.revoke(third.refreshToken());
        TokenException e = assertThrows(TokenException.class, () -> client.refresh(third.refreshToken()));
        assertEquals("invalid_grant", e.getError());
        assertEquals(400, e.getStatus());
    }

    @Test
    void introspection_revoked() {
        TokenClient client = new TokenClient(Vectors.options().build());
        TokenSet set = client.password(Vectors.user("viewer").get("username").asText(),
                Vectors.user("viewer").get("password").asText(), SCOPE);
        TslAuthVerifier verifier = new TslAuthVerifier(Vectors.options().introspect(true).build());
        Principal p = verifier.verify(set.accessToken());
        assertEquals("sdk-viewer", p.username());
        client.revoke(set.accessToken());
        TslAuthException e = assertThrows(TslAuthException.class, () -> verifier.verify(set.accessToken()));
        assertEquals("revoked", e.getCode());
    }

    @Test
    void client_credentials_cache() {
        Vectors.MutableClock clock = new Vectors.MutableClock(Instant.now());
        TokenClient client = new TokenClient(Vectors.options().clock(clock).build());
        TokenSet a = client.clientCredentials(Vectors.AUDIENCE);
        TokenSet b = client.clientCredentials(Vectors.AUDIENCE);
        assertSame(a, b, "второй вызов — из кэша");
        clock.set(a.expiresAt());
        TokenSet c = client.clientCredentials(Vectors.AUDIENCE);
        assertNotEquals(a.accessToken(), c.accessToken(), "после exp — новый токен");
    }

    @Test
    void jwks_rotation() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        AtomicBoolean real = new AtomicBoolean(false);
        byte[] realJwks = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(Vectors.JWKS_URI)).build(),
                HttpResponse.BodyHandlers.ofByteArray()).body();
        HttpServer stub = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        stub.createContext("/jwks", ex -> {
            hits.incrementAndGet();
            byte[] body = real.get() ? realJwks : "{\"keys\":[]}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream out = ex.getResponseBody()) { out.write(body); }
        });
        stub.start();
        try {
            Vectors.MutableClock clock = new Vectors.MutableClock(Instant.now());
            TslAuthVerifier verifier = new TslAuthVerifier(Vectors.options().clock(clock)
                    .jwksUri("http://127.0.0.1:" + stub.getAddress().getPort() + "/jwks")
                    .jwksMinRefresh(Duration.ofSeconds(1)).build());
            String token = Vectors.token("ok_user");

            TslAuthException e = assertThrows(TslAuthException.class, () -> verifier.verify(token));
            assertEquals("unknown_key", e.getCode());
            // Первая проверка: загрузка + одно перечитывание по неизвестному kid; лимит частоты в ту же секунду.
            int afterFirst = hits.get();
            assertEquals(1, afterFirst, "перечитывание по kid не чаще jwksMinRefresh");

            real.set(true);
            e = assertThrows(TslAuthException.class, () -> verifier.verify(token));
            assertEquals("unknown_key", e.getCode(), "до истечения jwksMinRefresh перечитывания нет");
            assertEquals(afterFirst, hits.get());

            clock.set(clock.instant().plusSeconds(2));
            Principal p = verifier.verify(token);
            assertEquals("sdk-operator", p.username());
            assertEquals(afterFirst + 1, hits.get(), "ровно одно перечитывание после jwksMinRefresh");
        } finally {
            stub.stop(0);
        }
    }
}
