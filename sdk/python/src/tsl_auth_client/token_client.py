"""Клиент токенов (docs/client-contract.md §6): token/introspection/revocation endpoint из discovery."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Iterable

from .errors import TokenError
from .jwks import Discovery, http_json
from .options import Options

# Кэшированный сервисный токен обновляется заранее, за 30 с до истечения.
_CACHE_MARGIN = 30.0


@dataclass
class TokenSet:
    access_token: str
    token_type: str
    expires_at: float
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None

    def expires_in(self, now: float) -> float:
        return self.expires_at - now


def _scope(scopes: Iterable[str] | str | None) -> str | None:
    if scopes is None:
        return None
    if isinstance(scopes, str):
        return scopes or None
    return " ".join(scopes) or None


class TokenClient:
    """Все методы — POST application/x-www-form-urlencoded; client_id всегда в теле, client_secret — если задан."""

    def __init__(self, options: Options | None = None, discovery: Discovery | None = None, **overrides: Any):
        self.options = options or Options.from_env(**overrides)
        if not self.options.client_id:
            raise ValueError("TSL_AUTH_CLIENT_ID не задан")
        self.discovery = discovery or Discovery(self.options)
        self._cache: dict[str, TokenSet] = {}
        self._cache_lock = threading.Lock()

    # --- grant'ы ---
    def client_credentials(self, scopes: Iterable[str] | str | None = None) -> TokenSet:
        """Сервисный токен: кэш по scope до expires_at − 30 с, single-flight при протухшем кэше."""
        key = _scope(scopes) or ""
        now = self.options.now()
        cached = self._cache.get(key)
        if cached is not None and now < cached.expires_at - _CACHE_MARGIN:
            return cached
        with self._cache_lock:
            now = self.options.now()
            cached = self._cache.get(key)
            if cached is not None and now < cached.expires_at - _CACHE_MARGIN:
                return cached
            form = {"grant_type": "client_credentials"}
            if key:
                form["scope"] = key
            fresh = self._token(form)  # ошибка запроса кэш не портит: исключение уходит вызывающему
            self._cache[key] = fresh
            return fresh

    def exchange(self, subject_token: str, scopes: Iterable[str] | str | None = None) -> TokenSet:
        """Token exchange (RFC 8693); не кэшируется — токен привязан к пользователю."""
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if _scope(scopes):
            form["scope"] = _scope(scopes)  # type: ignore[assignment]
        return self._token(form)

    def refresh(self, refresh_token: str, scopes: Iterable[str] | str | None = None) -> TokenSet:
        """Ответ содержит новый refresh_token — вызывающий обязан заменить старый немедленно."""
        form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if _scope(scopes):
            form["scope"] = _scope(scopes)  # type: ignore[assignment]
        return self._token(form)

    def password(self, username: str, password: str, scopes: Iterable[str] | str | None = None) -> TokenSet:
        """Только серверные приложения."""
        form = {"grant_type": "password", "username": username, "password": password}
        if _scope(scopes):
            form["scope"] = _scope(scopes)  # type: ignore[assignment]
        return self._token(form)

    def authorization_code(self, code: str, redirect_uri: str, code_verifier: str) -> TokenSet:
        """PKCE обязателен."""
        return self._token({"grant_type": "authorization_code", "code": code,
                            "redirect_uri": redirect_uri, "code_verifier": code_verifier})

    # --- introspection / revocation ---
    def introspect(self, token: str) -> dict[str, Any]:
        status, body = self._post(self._endpoint("introspection_endpoint"), {"token": token})
        if status != 200 or not isinstance(body, dict):
            raise self._error(status, body)
        return body

    def revoke(self, token: str) -> None:
        status, body = self._post(self._endpoint("revocation_endpoint"), {"token": token})
        if status != 200:
            raise self._error(status, body)

    # --- внутреннее ---
    def _token(self, form: dict[str, str]) -> TokenSet:
        status, body = self._post(self._endpoint("token_endpoint"), form)
        if status != 200 or not isinstance(body, dict) or "access_token" not in body:
            raise self._error(status, body)
        expires_in = body.get("expires_in")
        try:
            ttl = float(expires_in) if expires_in is not None else 0.0
        except (TypeError, ValueError):
            ttl = 0.0
        return TokenSet(
            access_token=str(body["access_token"]),
            token_type=str(body.get("token_type") or "Bearer"),
            expires_at=self.options.now() + ttl,
            refresh_token=body.get("refresh_token"),
            id_token=body.get("id_token"),
            scope=body.get("scope"),
        )

    def _endpoint(self, name: str) -> str:
        try:
            return self.discovery.endpoint(name)
        except (OSError, ValueError, ConnectionError) as e:
            raise TokenError("unavailable", str(e), 0) from None

    def _post(self, url: str, form: dict[str, str]) -> tuple[int, Any]:
        o = self.options
        data = {**form, "client_id": o.client_id or ""}
        if o.client_secret:
            data["client_secret"] = o.client_secret
        try:
            return http_json("POST", url, o.http_timeout, data)
        except (OSError, ValueError, ConnectionError) as e:
            raise TokenError("unavailable", str(e), 0) from None

    @staticmethod
    def _error(status: int, body: Any) -> TokenError:
        if status >= 500 or status == 0:
            return TokenError("unavailable", f"HTTP {status}", status)
        if isinstance(body, dict) and body.get("error"):
            return TokenError(str(body["error"]), body.get("error_description"), status)
        return TokenError("invalid_response", f"HTTP {status}", status)
