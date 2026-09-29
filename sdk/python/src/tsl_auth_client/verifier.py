"""Проверка access-токена (docs/client-contract.md §2). RS256 без зависимостей: pow() + PKCS#1 v1.5."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .errors import TslAuthError
from .jwks import Discovery, JwksCache, b64url_decode, http_json
from .options import Options
from .principal import Principal, as_list

# DigestInfo для SHA-256 (RFC 8017, §9.2, примечание 1).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def extract_bearer(authorization: str | None) -> str:
    """Шаг 1: `Authorization: Bearer <jwt>` (регистр Bearer не важен), иначе `missing`."""
    if not authorization:
        raise TslAuthError("missing", "нет заголовка Authorization")
    scheme, _, token = authorization.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise TslAuthError("missing", "ожидается Authorization: Bearer <token>")
    return token


def _decode_json_part(part: str) -> dict[str, Any]:
    try:
        value = json.loads(b64url_decode(part))
    except (ValueError, UnicodeDecodeError):
        raise TslAuthError("malformed", "часть токена — не base64url/JSON") from None
    if not isinstance(value, dict):
        raise TslAuthError("malformed", "часть токена — не объект JSON")
    return value


def rs256_verify(n: int, e: int, signing_input: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5/SHA-256: сравниваем весь EM за постоянное время (никакого разбора паддинга)."""
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(signature, "big")
    if len(signature) != k or s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    pad_len = k - 3 - len(_SHA256_DIGEST_INFO) - len(digest)
    if pad_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + _SHA256_DIGEST_INFO + digest
    return hmac.compare_digest(em, expected)


class Verifier:
    """Проверяет JWT в порядке §2 и строит Principal. Часы — options.now."""

    def __init__(self, options: Options | None = None, **overrides: Any):
        self.options = options or Options.from_env(**overrides)
        self.discovery = Discovery(self.options)
        self.jwks = JwksCache(self.options, self.discovery)

    def verify_authorization(self, authorization: str | None) -> Principal:
        """Проверка заголовка Authorization целиком (для middleware): пустой — `missing`."""
        return self.verify(extract_bearer(authorization))

    def verify(self, token: str) -> Principal:
        # 2. Три части, заголовок и payload — JSON.
        if not isinstance(token, str) or token.count(".") != 2:
            raise TslAuthError("malformed", "ожидаются три части через точку")
        h, p, s = token.split(".")
        header = _decode_json_part(h)
        payload = _decode_json_part(p)
        try:
            signature = b64url_decode(s)
        except ValueError:
            raise TslAuthError("malformed", "подпись — не base64url") from None
        # 3. Только RS256 — до любых обращений к ключам.
        if header.get("alg") != "RS256":
            raise TslAuthError("unsupported_alg", "поддерживается только RS256")
        # 4. kid обязателен.
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TslAuthError("malformed", "в заголовке нет kid")
        # 5. Ключ из кэша JWKS.
        key = self.jwks.get_key(kid)
        if key is None:
            raise TslAuthError("unknown_key", "ключ с таким kid не найден")
        # 6. Подпись — до чтения claims.
        if not rs256_verify(key[0], key[1], f"{h}.{p}".encode("ascii"), signature):
            raise TslAuthError("bad_signature", "подпись не сошлась")
        # 7. iss.
        iss = payload.get("iss")
        if not isinstance(iss, str) or iss.rstrip("/") != self.options.issuer_normalized:
            raise TslAuthError("bad_issuer", "iss не совпадает с настроенным issuer")
        # 8. exp / nbf.
        now = self.options.now()
        skew = self.options.clock_skew
        exp = payload.get("exp")
        if not _is_number(exp) or now > exp + skew:
            raise TslAuthError("expired", "токен истёк или без exp")
        nbf = payload.get("nbf")
        if nbf is not None and (not _is_number(nbf) or now < nbf - skew):
            raise TslAuthError("not_yet_valid", "токен ещё не действует")
        # 9. aud.
        audience = self.options.audience
        if audience and audience not in as_list(payload.get("aud")):
            raise TslAuthError("bad_audience", "aud не содержит audience этого API")
        # 10. Introspection (мгновенный отзыв).
        if self.options.introspect:
            self._introspect(token)
        return Principal.from_claims(payload, audience)

    def _introspect(self, token: str) -> None:
        o = self.options
        form = {"token": token, "client_id": o.client_id or o.audience or ""}
        if o.client_secret:
            form["client_secret"] = o.client_secret
        try:
            status, body = http_json("POST", self.discovery.endpoint("introspection_endpoint"), o.http_timeout, form)
        except (OSError, ValueError, ConnectionError):
            raise TslAuthError("introspection_unavailable", "introspection недоступен") from None
        if status != 200 or not isinstance(body, dict):
            raise TslAuthError("introspection_unavailable", f"introspection: HTTP {status}")
        if body.get("active") is not True:
            raise TslAuthError("revoked", "токен неактивен")


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)
