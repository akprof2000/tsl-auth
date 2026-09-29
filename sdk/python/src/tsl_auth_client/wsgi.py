"""WSGI без зависимостей: middleware на всё приложение (или префиксы путей) и декоратор для обработчиков.

Principal кладётся в environ["tslauth.principal"].
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Iterable

from .authz import Requirement, authorize
from .principal import Principal
from .verifier import Verifier

ENVIRON_KEY = "tslauth.principal"
WsgiApp = Callable[[dict[str, Any], Callable], Iterable[bytes]]


def _deny(denied, start_response) -> Iterable[bytes]:
    reason = {401: "Unauthorized", 403: "Forbidden"}[denied.status]
    body = denied.body
    start_response(f"{denied.status} {reason}", denied.headers + [("Content-Length", str(len(body)))])
    return [body]


def principal_of(environ: dict[str, Any]) -> Principal | None:
    return environ.get(ENVIRON_KEY)


class TslAuthMiddleware:
    """Защищает всё приложение или только пути с заданными префиксами (`paths`)."""

    def __init__(self, app: WsgiApp, verifier: Verifier | None = None, require: Requirement | dict | None = None,
                 paths: Iterable[str] | None = None):
        self.app = app
        self.verifier = verifier or Verifier()
        self.require = _requirement(require)
        self.paths = tuple(paths) if paths else None

    def __call__(self, environ: dict[str, Any], start_response):
        path = environ.get("PATH_INFO", "") or "/"
        if self.paths is not None and not any(path.startswith(p) for p in self.paths):
            return self.app(environ, start_response)
        principal, denied = authorize(self.verifier, environ.get("HTTP_AUTHORIZATION"), self.require)
        if denied:
            return _deny(denied, start_response)
        environ[ENVIRON_KEY] = principal
        return self.app(environ, start_response)


def protect(verifier: Verifier, permission: str | None = None, any_permission: Iterable[str] | None = None,
            role: str | None = None, mfa: bool = False, subject_type: str | None = None):
    """Декоратор для WSGI-обработчика `handler(environ, start_response)`."""
    req = Requirement.of(permission, any_permission, role, mfa, subject_type)

    def decorator(handler: WsgiApp) -> WsgiApp:
        @functools.wraps(handler)
        def wrapper(environ: dict[str, Any], start_response):
            principal, denied = authorize(verifier, environ.get("HTTP_AUTHORIZATION"), req)
            if denied:
                return _deny(denied, start_response)
            environ[ENVIRON_KEY] = principal
            return handler(environ, start_response)
        return wrapper
    return decorator


def _requirement(value: Requirement | dict | None) -> Requirement:
    if value is None:
        return Requirement()
    if isinstance(value, Requirement):
        return value
    return Requirement.of(**value)
