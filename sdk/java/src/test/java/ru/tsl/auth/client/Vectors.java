package ru.tsl.auth.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

/** tests/sdk-contract/vectors.json: путь из SDK_CONTRACT_VECTORS или ../../tests/sdk-contract/vectors.json. */
final class Vectors {
    static final JsonNode ROOT = load();
    static final String ISSUER = ROOT.get("issuer").asText();
    static final String AUDIENCE = ROOT.get("audience").asText();
    static final String JWKS_URI = ROOT.get("jwksUri").asText();
    static final String CLIENT_ID = ROOT.get("client").get("id").asText();
    static final String CLIENT_SECRET = ROOT.get("client").get("secret").asText();

    private Vectors() {}

    private static JsonNode load() {
        String env = System.getenv("SDK_CONTRACT_VECTORS");
        Path path = env != null && !env.isBlank() ? Paths.get(env) : Paths.get("..", "..", "tests", "sdk-contract", "vectors.json");
        try {
            return new ObjectMapper().readTree(Files.readAllBytes(path));
        } catch (IOException e) {
            throw new IllegalStateException("Нет vectors.json (" + path.toAbsolutePath() + "): запустите tests/sdk-contract/make-vectors.py", e);
        }
    }

    static String token(String caseName) {
        for (JsonNode c : ROOT.get("cases")) {
            if (caseName.equals(c.get("name").asText())) return c.get("token").asText();
        }
        throw new IllegalArgumentException("нет случая " + caseName);
    }

    static JsonNode user(String key) {
        return ROOT.get("users").get(key);
    }

    static TslAuthOptions.Builder options() {
        return TslAuthOptions.builder().issuer(ISSUER).audience(AUDIENCE)
                .clientId(CLIENT_ID).clientSecret(CLIENT_SECRET);
    }

    /** Payload JWT без проверки (для чтения exp в тестах). */
    static Map<String, Object> payload(String jwt) throws IOException {
        return Json.parseObject(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    /** Часы с ручным переводом. */
    static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant start) { this.now = start; }

        void set(Instant instant) { this.now = instant; }

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
