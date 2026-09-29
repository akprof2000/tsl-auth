"""Principal (docs/client-contract.md §4): что приложение читает из проверенного токена."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


def as_list(v: Any) -> list[str]:
    """Claim-список приходит строкой или массивом; отсутствующий — пустой список."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x is not None]
    return [str(v)]


def _strip_prefix(values: list[str], audience: str | None) -> list[str]:
    """Оставляет только значения этого API ("<audience>:<x>") и обрезает префикс."""
    if not audience:
        return []
    prefix = audience + ":"
    return [v[len(prefix):] for v in values if v.startswith(prefix)]


@dataclass
class Principal:
    subject: str
    subject_type: str | None
    username: str | None
    name: str | None
    email: str | None
    roles: list[str]
    permissions: list[str]
    all_roles: list[str]
    all_permissions: list[str]
    scopes: list[str]
    amr: list[str]
    actor: dict[str, Any] | None
    expires_at: float | None
    claims: dict[str, Any] = field(repr=False)

    @classmethod
    def from_claims(cls, claims: dict[str, Any], audience: str | None) -> "Principal":
        all_roles = as_list(claims.get("role"))
        all_permissions = as_list(claims.get("permissions"))
        scope = claims.get("scope")
        act = claims.get("act")
        exp = claims.get("exp")
        return cls(
            subject=str(claims.get("sub", "")),
            subject_type=claims.get("subject_type"),
            username=claims.get("preferred_username"),
            name=claims.get("name"),
            email=claims.get("email"),
            roles=_strip_prefix(all_roles, audience),
            permissions=_strip_prefix(all_permissions, audience),
            all_roles=all_roles,
            all_permissions=all_permissions,
            scopes=scope.split() if isinstance(scope, str) else as_list(scope),
            amr=as_list(claims.get("amr")),
            actor=act if isinstance(act, dict) else None,
            expires_at=float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None,
            claims=claims,
        )

    # Только короткая форма ("orders.read"); полная ("api:orders.read") намеренно не принимается.
    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def has_any_permission(self, permissions: Iterable[str]) -> bool:
        return any(p in self.permissions for p in permissions)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    @property
    def is_mfa(self) -> bool:
        return "mfa" in self.amr
