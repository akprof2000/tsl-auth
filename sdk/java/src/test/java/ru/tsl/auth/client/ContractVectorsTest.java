package ru.tsl.auth.client;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** §8 п. 2: каждый случай vectors.json даёт ровно ожидаемый код; для ok_* — поля principal из expected. */
class ContractVectorsTest {
    private static final TslAuthVerifier DEFAULT = new TslAuthVerifier(Vectors.options().build());

    @TestFactory
    List<DynamicTest> vectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : Vectors.ROOT.get("cases")) {
            String name = c.get("name").asText();
            if (c.hasNonNull("skipIfNoNbf") && c.get("skipIfNoNbf").asBoolean()) continue;
            tests.add(DynamicTest.dynamicTest(name, () -> run(c)));
        }
        return tests;
    }

    private void run(JsonNode c) {
        String name = c.get("name").asText();
        String token = c.get("token").asText();
        String expect = c.get("expect").asText();
        TslAuthVerifier verifier = DEFAULT;
        if (c.hasNonNull("now")) {
            Clock fixed = Clock.fixed(Instant.ofEpochSecond(c.get("now").asLong()), ZoneOffset.UTC);
            verifier = new TslAuthVerifier(Vectors.options().clock(fixed).build());
        } else if (c.hasNonNull("issuer")) {
            verifier = new TslAuthVerifier(Vectors.options().issuer(c.get("issuer").asText()).jwksUri(Vectors.JWKS_URI).build());
        }
        TslAuthVerifier v = verifier;
        if (!"ok".equals(expect)) {
            TslAuthException e = assertThrows(TslAuthException.class, () -> v.verify(token), name);
            assertEquals(expect, e.getCode(), name);
            return;
        }
        Principal p = verifier.verify(token);
        JsonNode exp = Vectors.ROOT.get("expected").get(name);
        if (exp == null) return;
        if (exp.has("subjectType")) assertEquals(exp.get("subjectType").asText(), p.subjectType());
        if (exp.has("username")) assertEquals(exp.get("username").asText(), p.username());
        if (exp.has("subject")) assertEquals(exp.get("subject").asText(), p.subject());
        if (exp.has("permissions")) {
            List<String> want = new ArrayList<>();
            exp.get("permissions").forEach(n -> want.add(n.asText()));
            assertEquals(want, new ArrayList<>(p.permissions()));
        }
        if (exp.has("roles")) {
            List<String> want = new ArrayList<>();
            exp.get("roles").forEach(n -> want.add(n.asText()));
            assertEquals(want, new ArrayList<>(p.roles()));
        }
        if (exp.has("actorSub")) {
            assertNotNull(p.actor());
            assertEquals(exp.get("actorSub").asText(), p.actor().subject());
        }
        if ("ok_viewer".equals(name)) assertFalse(p.hasPermission("orders.write"));
        if ("ok_client".equals(name)) assertNull(p.username());
        if ("ok_user".equals(name)) {
            assertTrue(p.hasPermission("orders.write"));
            assertFalse(p.hasPermission(Vectors.AUDIENCE + ":orders.write"), "полная форма не принимается");
            assertTrue(p.hasRole("operator"));
            assertNotNull(p.expiresAt());
            assertEquals(Vectors.ISSUER, p.claims().get("iss"));
        }
    }
}
