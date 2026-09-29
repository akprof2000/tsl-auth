"""Flask: декоратор `protect(...)`; principal — в flask.g.auth. Flask импортируется только здесь."""
from __future__ import annotations

import functools
from typing import Callable, Iterable

from flask import g, request

from .authz import Requirement, authorize
from .verifier import Verifier

_default: dict[str, Verifier] = {}


def _verifier(explicit: Verifier | None) -> Verifier:
    if explicit is not None:
        return explicit
    if "v" not in _default:
        _default["v"] = Verifier()  # из окружения, лениво
    return _default["v"]


def protect(permission: str | None = None, any_permission: Iterable[str] | None = None, role: str | None = None,
            mfa: bool = False, subject_type: str | None = None, verifier: Verifier | None = None) -> Callable:
    """`@app.get("/orders")` + `@protect(permission="orders.read")`; отказ — 401/403 по контракту."""
    req = Requirement.of(permission, any_permission, role, mfa, subject_type)

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            principal, denied = authorize(_verifier(verifier), request.headers.get("Authorization"), req)
            if denied:
                return denied.body, denied.status, dict(denied.headers)
            g.auth = principal
            return view(*args, **kwargs)
        return wrapper
    return decorator
