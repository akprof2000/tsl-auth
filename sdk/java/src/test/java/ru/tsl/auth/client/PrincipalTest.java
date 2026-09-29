package ru.tsl.auth.client;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** §4: нормализация claim-списков и требования §5 без сети. */
class PrincipalTest {
    private static Principal principal(Object role, Object permissions, Object amr, String type) {
        Map<String, Object> c = new HashMap<>();
        c.put("sub", "u1");
        c.put("subject_type", type);
        c.put("role", role);
        c.put("permissions", permissions);
        c.put("amr", amr);
        c.put("scope", "openid api");
        c.put("exp", 1_800_000_000L);
        return new Principal(c, "api");
    }

    @Test
    void string_claims_become_lists_and_prefixes_are_stripped() {
        Principal p = principal("api:admin", List.of("api:a.read", "other:x", "api:a.write"), "pwd", "user");
        assertEquals(List.of("admin"), p.roles());
        assertEquals(List.of("api:admin"), p.allRoles());
        assertEquals(List.of("a.read", "a.write"), p.permissions());
        assertEquals(3, p.allPermissions().size());
        assertEquals(List.of("openid", "api"), p.scopes());
        assertTrue(p.hasPermission("a.read"));
        assertFalse(p.hasPermission("api:a.read"));
        assertFalse(p.isMfa());
        assertNull(p.actor());
        assertEquals(1_800_000_000L, p.expiresAt().getEpochSecond());
    }

    @Test
    void missing_claims_are_empty_lists() {
        Principal p = principal(null, null, null, "client");
        assertTrue(p.roles().isEmpty());
        assertTrue(p.permissions().isEmpty());
        assertTrue(p.amr().isEmpty());
        assertNull(p.username());
    }

    @Test
    void require_checks_in_contract_order() {
        Principal p = principal(List.of("api:viewer"), List.of("api:a.read"), List.of("pwd", "otp", "mfa"), "user");
        assertNull(Require.permission("a.read").check(p));
        Require.Denial d = Require.permission("a.write").check(p);
        assertEquals("insufficient_permissions", d.code());
        assertEquals("api:a.write", d.description());
        d = Require.anyPermission("a.write", "a.delete").check(p);
        assertEquals("api:a.write api:a.delete", d.description());
        d = Require.role("admin").check(p);
        assertEquals("insufficient_role", d.code());
        assertEquals("api:admin", d.description());
        assertNull(Require.authenticated().andMfa().check(p));
        d = Require.authenticated().andSubjectType("client").check(p);
        assertEquals("subject_type_not_allowed", d.code());
        assertEquals("client", d.description());
        Challenge c = Challenge.forbidden(d);
        assertEquals(403, c.status());
        assertEquals("{\"error\":\"subject_type_not_allowed\",\"error_description\":\"client\"}", c.body());
    }

    @Test
    void options_from_environment() {
        Map<String, String> env = Map.of("TSL_AUTH_ISSUER", "https://auth.corp/", "TSL_AUTH_AUDIENCE", "api",
                "TSL_AUTH_INTROSPECT", "true", "TSL_AUTH_CLOCK_SKEW_SECONDS", "5");
        TslAuthOptions o = TslAuthOptions.fromEnvironment(env).build();
        assertEquals("https://auth.corp", o.issuerNormalized());
        assertTrue(o.introspect());
        assertEquals(5, o.clockSkew().getSeconds());
        assertEquals(600, o.jwksTtl().getSeconds());
        assertThrows(IllegalArgumentException.class, () -> TslAuthOptions.fromEnvironment(Map.of()).build());
    }
}
