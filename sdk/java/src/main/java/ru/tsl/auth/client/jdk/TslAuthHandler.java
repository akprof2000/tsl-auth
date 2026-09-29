package ru.tsl.auth.client.jdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import ru.tsl.auth.client.Challenge;
import ru.tsl.auth.client.Principal;
import ru.tsl.auth.client.Require;
import ru.tsl.auth.client.TslAuthException;
import ru.tsl.auth.client.TslAuthVerifier;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Защита обработчиков com.sun.net.httpserver (§5). Principal — в exchange.getAttribute("tslauth.principal").
 * <pre>server.createContext("/orders", auth.protect(ordersHandler, Require.permission("orders.read")));</pre>
 */
public final class TslAuthHandler {
    private final TslAuthVerifier verifier;

    public TslAuthHandler(TslAuthVerifier verifier) {
        this.verifier = verifier;
    }

    /** Только аутентификация. */
    public HttpHandler protect(HttpHandler handler) {
        return protect(handler, Require.authenticated());
    }

    public HttpHandler protect(HttpHandler handler, Require require) {
        return exchange -> {
            Principal principal;
            try {
                principal = verifier.verifyAuthorization(exchange.getRequestHeaders().getFirst("Authorization"));
            } catch (TslAuthException e) {
                send(exchange, Challenge.unauthorized(e));
                return;
            }
            Require.Denial denial = require.check(principal);
            if (denial != null) {
                send(exchange, Challenge.forbidden(denial));
                return;
            }
            exchange.setAttribute(Challenge.ATTRIBUTE, principal);
            handler.handle(exchange);
        };
    }

    /** Principal текущего запроса или null. */
    public static Principal principal(HttpExchange exchange) {
        return (Principal) exchange.getAttribute(Challenge.ATTRIBUTE);
    }

    private static void send(HttpExchange exchange, Challenge c) throws IOException {
        byte[] body = c.bodyBytes();
        exchange.getResponseHeaders().set("WWW-Authenticate", c.wwwAuthenticate());
        exchange.getResponseHeaders().set("Content-Type", Challenge.CONTENT_TYPE);
        exchange.sendResponseHeaders(c.status(), body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
