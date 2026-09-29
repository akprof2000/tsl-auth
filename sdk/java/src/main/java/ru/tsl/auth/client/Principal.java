package ru.tsl.auth.client;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Проверенный субъект (§4): права этого API без префикса, полные списки для шлюзов, сырые claims. */
public final class Principal {
    /** Цепочка token exchange (claim act): {sub, act?}. */
    public static final class Actor {
        private final String subject;
        private final Actor actor;

        Actor(String subject, Actor actor) {
            this.subject = subject;
            this.actor = actor;
        }

        public String subject() { return subject; }
        /** Вложенный актор или null. */
        public Actor actor() { return actor; }

        static Actor from(Object v) {
            if (!(v instanceof Map)) return null;
            Map<?, ?> m = (Map<?, ?>) v;
            Object sub = m.get("sub");
            return new Actor(sub == null ? null : sub.toString(), from(m.get("act")));
        }
    }

    private final String audience;
    private final String subject;
    private final String subjectType;
    private final String username;
    private final String name;
    private final String email;
    private final List<String> roles;
    private final List<String> permissions;
    private final List<String> allRoles;
    private final List<String> allPermissions;
    private final List<String> scopes;
    private final List<String> amr;
    private final Actor actor;
    private final Instant expiresAt;
    private final Map<String, Object> claims;

    public Principal(Map<String, Object> claims, String audience) {
        this.audience = audience;
        this.claims = Collections.unmodifiableMap(claims);
        this.subject = str(claims.get("sub"));
        this.subjectType = str(claims.get("subject_type"));
        this.username = str(claims.get("preferred_username"));
        this.name = str(claims.get("name"));
        this.email = str(claims.get("email"));
        this.allRoles = asList(claims.get("role"));
        this.allPermissions = asList(claims.get("permissions"));
        this.roles = stripPrefix(allRoles, audience);
        this.permissions = stripPrefix(allPermissions, audience);
        String scope = str(claims.get("scope"));
        List<String> sc = new ArrayList<>();
        if (scope != null) {
            for (String s : scope.split(" ")) if (!s.isEmpty()) sc.add(s);
        }
        this.scopes = Collections.unmodifiableList(sc);
        this.amr = asList(claims.get("amr"));
        this.actor = Actor.from(claims.get("act"));
        Object exp = claims.get("exp");
        this.expiresAt = exp instanceof Number ? Instant.ofEpochSecond(((Number) exp).longValue()) : null;
    }

    private static String str(Object v) {
        return v == null ? null : v.toString();
    }

    /** Claim-список приходит строкой (одно значение) или массивом; отсутствующий — пустой список. */
    static List<String> asList(Object v) {
        if (v == null) return Collections.emptyList();
        List<String> out = new ArrayList<>();
        if (v instanceof List) {
            for (Object o : (List<?>) v) if (o != null) out.add(o.toString());
        } else {
            out.add(v.toString());
        }
        return Collections.unmodifiableList(out);
    }

    private static List<String> stripPrefix(List<String> values, String audience) {
        if (audience == null) return Collections.emptyList();
        String prefix = audience + ":";
        List<String> out = new ArrayList<>();
        for (String v : values) {
            if (v.startsWith(prefix)) out.add(v.substring(prefix.length()));
        }
        return Collections.unmodifiableList(out);
    }

    /** Настроенный audience этого API (для описаний в 403). */
    public String audience() { return audience; }
    public String subject() { return subject; }
    /** user или client. */
    public String subjectType() { return subjectType; }
    /** Отсутствует (null) у сервисных токенов. */
    public String username() { return username; }
    public String name() { return name; }
    public String email() { return email; }
    /** Роли этого API без префикса. */
    public List<String> roles() { return roles; }
    /** Разрешения этого API без префикса. */
    public List<String> permissions() { return permissions; }
    public List<String> allRoles() { return allRoles; }
    public List<String> allPermissions() { return allPermissions; }
    public List<String> scopes() { return scopes; }
    public List<String> amr() { return amr; }
    /** Актор token exchange или null. */
    public Actor actor() { return actor; }
    public Instant expiresAt() { return expiresAt; }
    /** Сырые claims токена. */
    public Map<String, Object> claims() { return claims; }

    /** Короткая форма («orders.read»); полная форма с префиксом не принимается. */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean isMfa() {
        return amr.contains("mfa");
    }
}
