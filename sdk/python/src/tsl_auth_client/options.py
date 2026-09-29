"""Настройки SDK (docs/client-contract.md §1): явные параметры имеют приоритет над переменными окружения."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

_TRUE = {"1", "true", "yes", "on"}


@dataclass
class Options:
    issuer: str = ""
    audience: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    jwks_uri: str | None = None
    clock_skew: float = 30
    jwks_ttl: float = 600
    jwks_min_refresh: float = 10
    introspect: bool = False
    http_timeout: float = 10
    # Часы инжектируются: тесты (и не только) подменяют now.
    now: Callable[[], float] = field(default=time.time, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> "Options":
        """Читает TSL_AUTH_* из окружения; overrides (jwks_uri=, clock_skew=, now=…) перекрывают их."""
        e = os.environ if env is None else env

        def num(name: str, default: float) -> float:
            raw = e.get(name)
            return float(raw) if raw not in (None, "") else default

        values: dict[str, Any] = dict(
            issuer=e.get("TSL_AUTH_ISSUER", ""),
            audience=e.get("TSL_AUTH_AUDIENCE") or None,
            client_id=e.get("TSL_AUTH_CLIENT_ID") or None,
            client_secret=e.get("TSL_AUTH_CLIENT_SECRET") or None,
            jwks_uri=e.get("TSL_AUTH_JWKS_URI") or None,
            clock_skew=num("TSL_AUTH_CLOCK_SKEW_SECONDS", 30),
            jwks_ttl=num("TSL_AUTH_JWKS_TTL_SECONDS", 600),
            jwks_min_refresh=num("TSL_AUTH_JWKS_MIN_REFRESH_SECONDS", 10),
            introspect=(e.get("TSL_AUTH_INTROSPECT", "false").strip().lower() in _TRUE),
            http_timeout=num("TSL_AUTH_HTTP_TIMEOUT_SECONDS", 10),
        )
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)

    @property
    def issuer_normalized(self) -> str:
        """Сравнение iss и issuer — без завершающего '/'."""
        return self.issuer.rstrip("/")

    def require_issuer(self) -> str:
        if not self.issuer:
            raise ValueError("TSL_AUTH_ISSUER не задан")
        return self.issuer_normalized
