"""FastAPI: `install(app, verifier)` + dependency `require(...)` → Principal (и request.state.auth).

FastAPI импортируется только здесь: базовый пакет остаётся без зависимостей.
"""
from __future__ import annotations

from typing import Any, Iterable

from fastapi import Depends, FastAPI, Request
from fastapi.responses import Response

from .authz import Denied, Requirement, authorize
from .principal import Principal
from .verifier import Verifier

STATE_KEY = "tsl_auth_verifier"


class AuthDenied(Exception):
    """Поднимается dependency; обработчик из install() превращает её в 401/403 по контракту."""

    def __init__(self, denied: Denied):
        super().__init__(denied.error)
        self.denied = denied


def _response(denied: Denied) -> Response:
    return Response(content=denied.body, status_code=denied.status, headers=dict(denied.headers))


def install(app: FastAPI, verifier: Verifier | None = None) -> Verifier:
    """Одна строка подключения: регистрирует verifier в app.state и обработчик отказов."""
    v = verifier or Verifier()
    setattr(app.state, STATE_KEY, v)

    @app.exception_handler(AuthDenied)
    async def _on_denied(_: Request, exc: AuthDenied) -> Response:
        return _response(exc.denied)

    return v


def require(permission: str | None = None, any_permission: Iterable[str] | None = None, role: str | None = None,
            mfa: bool = False, subject_type: str | None = None, verifier: Verifier | None = None) -> Any:
    """Dependency: `principal: Principal = Depends(require(permission="orders.read"))`."""
    req = Requirement.of(permission, any_permission, role, mfa, subject_type)

    def dependency(request: Request) -> Principal:
        v = verifier or getattr(request.app.state, STATE_KEY, None)
        if v is None:
            raise RuntimeError("вызовите tsl_auth_client.fastapi.install(app) или передайте verifier=")
        principal, denied = authorize(v, request.headers.get("authorization"), req)
        if denied:
            raise AuthDenied(denied)
        request.state.auth = principal
        return principal  # type: ignore[return-value]

    return Depends(dependency)
