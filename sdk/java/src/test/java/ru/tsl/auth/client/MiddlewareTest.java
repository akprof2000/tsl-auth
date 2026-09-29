package ru.tsl.auth.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import ru.tsl.auth.client.jdk.TslAuthHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** §8 п. 3 middleware: реальный HTTP-сервер на свободном порту с TslAuthHandler. */
class MiddlewareTest {
    private static HttpServer server;
    private static String base;
    private static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void start() throws IOException {
        TslAuthHandler auth = new TslAuthHandler(new TslAuthVerifier(Vectors.options().build()));
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/me", auth.protect(MiddlewareTest::me));
        server.createContext("/orders/write", auth.protect(MiddlewareTest::me, Require.permission("orders.write")));
        server.createContext("/orders", auth.protect(MiddlewareTest::me, Require.permission("orders.read")));
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    private static void me(HttpExchange ex) throws IOException {
        Principal p = TslAuthHandler.principal(ex);
        byte[] body = Json.write(Map.of("username", p.username())).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", Challenge.CONTENT_TYPE);
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream out = ex.getResponseBody()) { out.write(body); }
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
        if (token != null) b.header("Authorization", "Bearer " + token);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> json(HttpResponse<String> r) throws IOException {
        return Json.parseObject(r.body());
    }

    @Test
    void no_token_401_missing() throws Exception {
        HttpResponse<String> r = get("/me", null);
        assertEquals(401, r.statusCode());
        assertEquals("Bearer realm=\"tsl-auth\", error=\"invalid_token\", error_description=\"missing\"",
                r.headers().firstValue("WWW-Authenticate").orElse(null));
        assertEquals("application/json; charset=utf-8", r.headers().firstValue("Content-Type").orElse(null));
        assertEquals(Map.of("error", "invalid_token", "error_description", "missing"), json(r));
    }

    @Test
    void bad_token_401() throws Exception {
        HttpResponse<String> r = get("/me", Vectors.token("tampered_payload"));
        assertEquals(401, r.statusCode());
        assertEquals("bad_signature", json(r).get("error_description"));
        assertTrue(r.headers().firstValue("WWW-Authenticate").orElse("").contains("error_description=\"bad_signature\""));

        r = get("/me", Vectors.token("garbage"));
        assertEquals(401, r.statusCode());
        assertEquals("malformed", json(r).get("error_description"));
    }

    @Test
    void viewer_403_on_write() throws Exception {
        HttpResponse<String> r = get("/orders/write", Vectors.token("ok_viewer"));
        assertEquals(403, r.statusCode());
        assertEquals("Bearer realm=\"tsl-auth\", error=\"insufficient_permissions\", error_description=\""
                + Vectors.AUDIENCE + ":orders.write\"", r.headers().firstValue("WWW-Authenticate").orElse(null));
        assertEquals(Map.of("error", "insufficient_permissions", "error_description", Vectors.AUDIENCE + ":orders.write"), json(r));

        r = get("/orders", Vectors.token("ok_viewer"));
        assertEquals(200, r.statusCode());
    }

    @Test
    void user_200() throws Exception {
        HttpResponse<String> r = get("/orders/write", Vectors.token("ok_user"));
        assertEquals(200, r.statusCode());
        assertEquals("sdk-operator", json(r).get("username"));
        r = get("/me", Vectors.token("ok_user"));
        assertEquals(200, r.statusCode());
        assertEquals("sdk-operator", json(r).get("username"));
    }

    @Test
    void bearer_case_insensitive() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/me"))
                .header("Authorization", "bearer " + Vectors.token("ok_user")).build();
        assertEquals(200, http.send(req, HttpResponse.BodyHandlers.ofString()).statusCode());
    }
}
