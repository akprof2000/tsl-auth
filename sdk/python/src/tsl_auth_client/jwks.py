"""Discovery и кэш ключей JWKS (docs/client-contract.md §1, §3). Только urllib; single-flight через Lock."""
from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .options import Options

RsaKey = tuple[int, int]  # (n, e)


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def http_json(method: str, url: str, timeout: float, form: dict[str, str] | None = None) -> tuple[int, Any]:
    """Возвращает (статус, JSON или None). HTTP-ошибки — как статус; сеть — исключение OSError."""
    data, headers = None, {"Accept": "application/json"}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else None)
        except ValueError:
            return e.code, None


class Discovery:
    """Кэш /.well-known/openid-configuration на срок jwks_ttl."""

    def __init__(self, options: Options):
        self._o = options
        self._lock = threading.Lock()
        self._doc: dict[str, Any] | None = None
        self._at = 0.0

    def document(self) -> dict[str, Any]:
        now = self._o.now()
        with self._lock:
            if self._doc is not None and now - self._at < self._o.jwks_ttl:
                return self._doc
            url = self._o.require_issuer() + "/.well-known/openid-configuration"
            try:
                status, doc = http_json("GET", url, self._o.http_timeout)
            except OSError as e:
                if self._doc is not None:
                    return self._doc  # старый ответ лучше отказа
                raise ConnectionError(f"discovery {url}: {e}") from e
            if status != 200 or not isinstance(doc, dict):
                if self._doc is not None:
                    return self._doc
                raise ConnectionError(f"discovery {url}: HTTP {status}")
            self._doc, self._at = doc, now
            return doc

    def endpoint(self, name: str) -> str:
        value = self.document().get(name)
        if not value:
            raise ConnectionError(f"discovery: нет {name}")
        return str(value)


class JwksCache:
    """Ключи RSA по kid: ленивая загрузка, TTL, перечитывание по неизвестному kid не чаще jwks_min_refresh."""

    def __init__(self, options: Options, discovery: Discovery | None = None):
        self._o = options
        self._discovery = discovery or Discovery(options)
        self._lock = threading.Lock()
        self._keys: dict[str, RsaKey] = {}
        self._loaded_at: float | None = None
        self._refresh_at: float | None = None
        self.fetch_count = 0  # диагностика и тесты

    def _jwks_uri(self) -> str:
        return self._o.jwks_uri or self._discovery.endpoint("jwks_uri")

    def _fetch(self) -> bool:
        """Перечитывает JWKS. False — не удалось, старый набор остаётся."""
        self._refresh_at = self._o.now()
        try:
            status, doc = http_json("GET", self._jwks_uri(), self._o.http_timeout)
        except (OSError, ValueError):
            return False
        finally:
            self.fetch_count += 1
        if status != 200 or not isinstance(doc, dict):
            return False
        self._keys = parse_jwks(doc)
        self._loaded_at = self._o.now()
        return True

    def get_key(self, kid: str) -> RsaKey | None:
        now = self._o.now()
        with self._lock:  # single-flight: параллельные проверки ждут одну загрузку
            expired = self._loaded_at is None or now - self._loaded_at >= self._o.jwks_ttl
            if expired:
                self._fetch()
            key = self._keys.get(kid)
            if key is None and not expired:
                # Неизвестный kid — возможно, ротация ключей; но не чаще min_refresh.
                if self._refresh_at is None or now - self._refresh_at >= self._o.jwks_min_refresh:
                    self._fetch()
                    key = self._keys.get(kid)
            return key


def parse_jwks(doc: dict[str, Any]) -> dict[str, RsaKey]:
    """Только kty=RSA с use отсутствующим или sig; ключи с битыми n/e пропускаются."""
    keys: dict[str, RsaKey] = {}
    for k in doc.get("keys") or []:
        if not isinstance(k, dict) or k.get("kty") != "RSA" or k.get("use") not in (None, "sig"):
            continue
        kid = k.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        try:
            n = int.from_bytes(b64url_decode(k["n"]), "big")
            e = int.from_bytes(b64url_decode(k["e"]), "big")
        except (KeyError, TypeError, ValueError):
            continue
        if n <= 0 or e <= 0:
            continue
        keys[kid] = (n, e)
    return keys
