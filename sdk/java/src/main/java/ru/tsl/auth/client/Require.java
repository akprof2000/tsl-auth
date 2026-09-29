package ru.tsl.auth.client;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Требования к субъекту для защищённого маршрута (§5): permission, anyPermission, role, mfa, subjectType.
 * Проверяются в этом порядке; первое невыполненное даёт 403 с соответствующим кодом.
 */
public final class Require {
    /** Отказ авторизации: код и «что требовалось» для error_description. */
    public static final class Denial {
        private final String code;
        private final String description;

        Denial(String code, String description) {
            this.code = code;
            this.description = description;
        }

        public String code() { return code; }
        public String description() { return description; }
    }

    private final String permission;
    private final List<String> anyPermission;
    private final String role;
    private final boolean mfa;
    private final String subjectType;

    private Require(String permission, List<String> anyPermission, String role, boolean mfa, String subjectType) {
        this.permission = permission;
        this.anyPermission = anyPermission;
        this.role = role;
        this.mfa = mfa;
        this.subjectType = subjectType;
    }

    /** Только аутентификация. */
    public static Require authenticated() {
        return new Require(null, Collections.emptyList(), null, false, null);
    }

    public static Require permission(String permission) {
        return authenticated().andPermission(permission);
    }

    public static Require anyPermission(String... permissions) {
        return authenticated().andAnyPermission(permissions);
    }

    public static Require role(String role) {
        return authenticated().andRole(role);
    }

    public Require andPermission(String p) {
        return new Require(p, anyPermission, role, mfa, subjectType);
    }

    public Require andAnyPermission(String... p) {
        return new Require(permission, Collections.unmodifiableList(Arrays.asList(p)), role, mfa, subjectType);
    }

    public Require andRole(String r) {
        return new Require(permission, anyPermission, r, mfa, subjectType);
    }

    public Require andMfa() {
        return new Require(permission, anyPermission, role, true, subjectType);
    }

    /** user или client. */
    public Require andSubjectType(String type) {
        return new Require(permission, anyPermission, role, mfa, type);
    }

    /** null — доступ разрешён, иначе отказ для 403. */
    public Denial check(Principal p) {
        String aud = p.audience() == null ? "" : p.audience() + ":";
        if (permission != null && !p.hasPermission(permission)) {
            return new Denial("insufficient_permissions", aud + permission);
        }
        if (!anyPermission.isEmpty()) {
            boolean any = false;
            for (String x : anyPermission) if (p.hasPermission(x)) { any = true; break; }
            if (!any) {
                StringBuilder sb = new StringBuilder();
                for (String x : anyPermission) sb.append(sb.length() > 0 ? " " : "").append(aud).append(x);
                return new Denial("insufficient_permissions", sb.toString());
            }
        }
        if (role != null && !p.hasRole(role)) {
            return new Denial("insufficient_role", aud + role);
        }
        if (mfa && !p.isMfa()) {
            return new Denial("mfa_required", "mfa");
        }
        if (subjectType != null && !subjectType.equals(p.subjectType())) {
            return new Denial("subject_type_not_allowed", subjectType);
        }
        return null;
    }
}
