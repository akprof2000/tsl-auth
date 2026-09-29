package ru.tsl.auth.client.servlet;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import ru.tsl.auth.client.Challenge;
import ru.tsl.auth.client.Principal;
import ru.tsl.auth.client.Require;
import ru.tsl.auth.client.TslAuthException;
import ru.tsl.auth.client.TslAuthVerifier;

import java.io.IOException;

/**
 * Фильтр jakarta.servlet (§5): 401/403 по RFC 6750, principal — в атрибуте запроса "tslauth.principal".
 * Один фильтр — одно требование; маршруты с разными правами регистрируются отдельными фильтрами (или проверяются в коде
 * через {@link Require#check(Principal)}).
 */
public final class TslAuthFilter implements Filter {
    private final TslAuthVerifier verifier;
    private final Require require;

    /** Только аутентификация. */
    public TslAuthFilter(TslAuthVerifier verifier) {
        this(verifier, Require.authenticated());
    }

    public TslAuthFilter(TslAuthVerifier verifier, Require require) {
        this.verifier = verifier;
        this.require = require;
    }

    /** Principal текущего запроса или null. */
    public static Principal principal(ServletRequest request) {
        return (Principal) request.getAttribute(Challenge.ATTRIBUTE);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        Principal principal;
        try {
            principal = verifier.verifyAuthorization(request.getHeader("Authorization"));
        } catch (TslAuthException e) {
            send(response, Challenge.unauthorized(e));
            return;
        }
        Require.Denial denial = require.check(principal);
        if (denial != null) {
            send(response, Challenge.forbidden(denial));
            return;
        }
        request.setAttribute(Challenge.ATTRIBUTE, principal);
        chain.doFilter(req, res);
    }

    private static void send(HttpServletResponse response, Challenge c) throws IOException {
        response.setStatus(c.status());
        response.setHeader("WWW-Authenticate", c.wwwAuthenticate());
        response.setContentType(Challenge.CONTENT_TYPE);
        byte[] body = c.bodyBytes();
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
