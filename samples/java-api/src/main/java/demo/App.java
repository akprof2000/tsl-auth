package demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ru.tsl.auth.client.Principal;
import ru.tsl.auth.client.Require;
import ru.tsl.auth.client.TslAuthOptions;
import ru.tsl.auth.client.TslAuthVerifier;
import ru.tsl.auth.client.jdk.TslAuthHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Демо Java API на SDK ru.tsl.auth:tsl-auth-client (только JDK + SDK).
 *
 * Маршруты: /health; /api/me — аутентификация; /api/inventory — permission inventory.read;
 * /api/inventory/adjust (POST ?sku=..&delta=..) — permission inventory.write.
 * Переменные: AUTH_ISSUER (http://localhost:8080/), API_AUDIENCE (demo-java-api), PORT (5105).
 */
public final class App {
    private static final Map<String, Integer> STOCK = new ConcurrentHashMap<>(Map.of("bolt-m6", 120, "nut-m6", 80, "washer-6", 300));

    public static void main(String[] args) throws IOException {
        String issuer = env("AUTH_ISSUER", "http://localhost:8080/");
        String audience = env("API_AUDIENCE", "demo-java-api");
        int port = Integer.parseInt(env("PORT", "5105"));

        TslAuthVerifier verifier = new TslAuthVerifier(TslAuthOptions.builder().issuer(issuer).audience(audience).build());
        TslAuthHandler auth = new TslAuthHandler(verifier);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", ex -> json(ex, 200, Map.of("status", "ok", "audience", audience)));
        server.createContext("/api/me", auth.protect(App::me));
        server.createContext("/api/inventory/adjust", auth.protect(App::adjust, Require.permission("inventory.write")));
        server.createContext("/api/inventory", auth.protect(App::inventory, Require.permission("inventory.read")));
        server.start();
        System.out.println("demo-java-api: http://localhost:" + port + "  issuer=" + issuer + "  audience=" + audience);
    }

    private static void me(HttpExchange ex) throws IOException {
        Principal p = TslAuthHandler.principal(ex);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", p.subject());
        body.put("subjectType", p.subjectType());
        body.put("username", p.username());
        body.put("roles", p.roles());
        body.put("permissions", p.permissions());
        body.put("mfa", p.isMfa());
        json(ex, 200, body);
    }

    private static void inventory(HttpExchange ex) throws IOException {
        json(ex, 200, Map.of("items", STOCK));
    }

    private static void adjust(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            json(ex, 405, Map.of("error", "method_not_allowed"));
            return;
        }
        Map<String, String> q = query(ex);
        String sku = q.get("sku");
        if (sku == null || !q.containsKey("delta")) {
            json(ex, 400, Map.of("error", "bad_request", "error_description", "нужны sku и delta"));
            return;
        }
        int delta;
        try {
            delta = Integer.parseInt(q.get("delta"));
        } catch (NumberFormatException e) {
            json(ex, 400, Map.of("error", "bad_request", "error_description", "delta — целое число"));
            return;
        }
        int value = STOCK.merge(sku, delta, Integer::sum);
        Principal p = TslAuthHandler.principal(ex);
        json(ex, 200, Map.of("sku", sku, "quantity", value, "by", p.username() == null ? p.subject() : p.username()));
    }

    // ---------- вспомогательное ----------

    private static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new LinkedHashMap<>();
        String raw = ex.getRequestURI().getRawQuery();
        if (raw == null) return m;
        for (String pair : raw.split("&")) {
            int i = pair.indexOf('=');
            String k = java.net.URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), StandardCharsets.UTF_8);
            String v = i < 0 ? "" : java.net.URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
            m.put(k, v);
        }
        return m;
    }

    /** Минимальный JSON без библиотек: строки, числа, булевы, списки, карты. */
    private static void json(HttpExchange ex, int status, Object value) throws IOException {
        byte[] body = toJson(value).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(body);
        }
    }

    private static String toJson(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return quote((String) v);
        if (v instanceof Number || v instanceof Boolean) return v.toString();
        if (v instanceof Map) {
            StringBuilder sb = new StringBuilder("{");
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (sb.length() > 1) sb.append(',');
                sb.append(quote(String.valueOf(e.getKey()))).append(':').append(toJson(e.getValue()));
            }
            return sb.append('}').toString();
        }
        if (v instanceof Iterable) {
            StringBuilder sb = new StringBuilder("[");
            for (Object o : (Iterable<?>) v) {
                if (sb.length() > 1) sb.append(',');
                sb.append(toJson(o));
            }
            return sb.append(']').toString();
        }
        return quote(v.toString());
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? d : v;
    }
}
