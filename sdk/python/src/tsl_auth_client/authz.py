"""Общая часть middleware (docs/client-contract.md §5): требования к principal и формат ответов 401/403."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from .errors import TslAuthError
from .principal import Principal
from .verifier import Verifier

REALM = "tsl-auth"
CONTENT_TYPE = "application/json; charset=utf-8"


@dataclass(frozen=True)
class Requirement:
    permission: str | None = None
    any_permission: tuple[str, ...] = ()
    role: str | None = None
    mfa: bool = False
    subject_type: str | None = None

    @classmethod
    def of(cls, permission: str | None = None, any_permission: Iterable[str] | None = None,
           role: str | None = None, mfa: bool = False, subject_type: str | None = None) -> "Requirement":
        return cls(permission, tuple(any_permission or ()), role, mfa, subject_type)


@dataclass(frozen=True)
class Denied:
    """Отказ: статус, код и что требовалось. Ничего из токена, кроме кода."""
    status: int
    error: str
    description: str

    @property
    def www_authenticate(self) -> str:
        return f'Bearer realm="{REALM}", error="{self.error}", error_description="{self.description}"'

    @property
    def body(self) -> bytes:
        return json.dumps({"error": self.error, "error_description": self.description}).encode("utf-8")

    @property
    def headers(self) -> list[tuple[str, str]]:
        return [("Content-Type", CONTENT_TYPE), ("WWW-Authenticate", self.www_authenticate)]


def check(principal: Principal, req: Requirement, audience: str | None) -> Denied | None:
    """Проверяет требования в порядке таблицы §5; None — доступ разрешён."""
    aud = audience or ""
    if req.permission is not None and not principal.has_permission(req.permission):
        return Denied(403, "insufficient_permissions", f"{aud}:{req.permission}")
    if req.any_permission and not principal.has_any_permission(req.any_permission):
        return Denied(403, "insufficient_permissions", " ".join(f"{aud}:{p}" for p in req.any_permission))
    if req.role is not None and not principal.has_role(req.role):
        return Denied(403, "insufficient_role", f"{aud}:{req.role}")
    if req.mfa and not principal.is_mfa:
        return Denied(403, "mfa_required", "mfa")
    if req.subject_type is not None and principal.subject_type != req.subject_type:
        return Denied(403, "subject_type_not_allowed", req.subject_type)
    return None


def authorize(verifier: Verifier, authorization: str | None, req: Requirement) -> tuple[Principal | None, Denied | None]:
    """Аутентификация (401) + требования (403). Возвращает (principal, None) либо (None, Denied)."""
    try:
        principal = verifier.verify_authorization(authorization)
    except TslAuthError as e:
        return None, Denied(401, "invalid_token", e.code)
    denied = check(principal, req, verifier.options.audience)
    return (None, denied) if denied else (principal, None)
