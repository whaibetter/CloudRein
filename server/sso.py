#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JD-Auth SSO client v1 (Python 3.8+, standard library only).

Token format: v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256(secret, "v1."+payloadB64))>
Shared secret: /opt/jd-auth/data/sso.key (64 hex chars, 0600) or JD_SSO_SECRET.

Drop this file into a Python project and use SsoVerifier. It only verifies
tokens/tickets and signs local sessions; it never needs the master key.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    raw = str(text or "").encode("ascii")
    padding = b"=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def parse_cookies(header: str = "") -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in str(header or "").split(";"):
        idx = part.find("=")
        if idx < 0:
            continue
        key = part[:idx].strip()
        if not key:
            continue
        value = part[idx + 1:].strip()
        try:
            from urllib.parse import unquote

            out[key] = unquote(value)
        except Exception:
            out[key] = value
    return out


def normalize_secret(value: Any) -> Optional[bytes]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    return text.encode("utf-8")


class SsoResult:
    def __init__(self, ok: bool, reason: str = "", token: str = "", payload: Optional[Dict[str, Any]] = None, csrf: str = ""):
        self.ok = ok
        self.reason = reason
        self.token = token
        self.payload = payload or {}
        self.csrf = csrf

    def __bool__(self) -> bool:
        return bool(self.ok)


class SsoVerifier:
    def __init__(
        self,
        secret_file: str = "/opt/jd-auth/data/sso.key",
        secret: Optional[str] = None,
        auth_url: str = "",
        cookie_name: str = "jd_sso",
        skew_sec: int = 120,
        cache_seconds: float = 2.0,
    ):
        self.secret_file = secret_file
        self.explicit_secret = secret
        self.auth_url = str(auth_url or "").rstrip("/")
        self.cookie_name = cookie_name
        self.skew_sec = int(skew_sec or 0)
        self.cache_seconds = float(cache_seconds or 0)
        self._cache: Optional[bytes] = None
        self._cache_at = 0.0
        self._cache_mtime = None
        self._cache_size = None
        self._used_tickets: Dict[str, int] = {}

    # ---------- secret ----------

    def _read_secret(self) -> Optional[bytes]:
        now = time.time()
        if (now - self._cache_at) < self.cache_seconds:
            return self._cache
        self._cache_at = now

        if self.explicit_secret:
            self._cache = normalize_secret(self.explicit_secret)
            return self._cache

        try:
            stat = os.stat(self.secret_file)
            if self._cache is not None and self._cache_mtime == stat.st_mtime and self._cache_size == stat.st_size:
                return self._cache
            with open(self.secret_file, "r", encoding="utf-8") as handle:
                self._cache = normalize_secret(handle.read())
            self._cache_mtime = stat.st_mtime
            self._cache_size = stat.st_size
            return self._cache
        except OSError:
            self._cache = normalize_secret(os.environ.get("JD_SSO_SECRET", ""))
            self._cache_mtime = None
            self._cache_size = None
            return self._cache

    def is_configured(self) -> bool:
        return bool(self._read_secret())

    # ---------- token ----------

    def sign_payload(self, payload: Dict[str, Any]) -> str:
        secret = self._read_secret()
        if not secret:
            return ""
        body = "v1." + b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        signature = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
        return body + "." + b64url_encode(signature)

    def verify_token(self, token: str) -> SsoResult:
        if not token or not isinstance(token, str):
            return SsoResult(False, "missing")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "v1" or not parts[1] or not parts[2]:
            return SsoResult(False, "format")
        secret = self._read_secret()
        if not secret:
            return SsoResult(False, "no_secret")

        body = parts[0] + "." + parts[1]
        expected = b64url_encode(hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(parts[2], expected):
            return SsoResult(False, "signature")

        try:
            payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        except Exception:
            return SsoResult(False, "payload")
        if not isinstance(payload, dict) or payload.get("v") != 1:
            return SsoResult(False, "version")

        now = int(time.time())
        try:
            exp = int(payload.get("exp"))
        except Exception:
            return SsoResult(False, "expired")
        if exp <= now - self.skew_sec:
            return SsoResult(False, "expired")
        if payload.get("iat") is not None:
            try:
                if int(payload.get("iat")) > now + self.skew_sec:
                    return SsoResult(False, "not_yet_valid")
            except Exception:
                return SsoResult(False, "not_yet_valid")
        return SsoResult(True, token=token, payload=payload)

    @staticmethod
    def _audience_ok(payload: Dict[str, Any], app_id: str) -> bool:
        if not app_id:
            return True
        return payload.get("aud") in ("all", app_id)

    def csrf_for(self, token: str) -> str:
        secret = self._read_secret()
        if not secret or not token:
            return ""
        return b64url_encode(hmac.new(secret, ("csrf:" + token).encode("ascii"), hashlib.sha256).digest())

    def verify_cookie_header(self, cookie_header: str, app_id: str = "") -> SsoResult:
        token = parse_cookies(cookie_header).get(self.cookie_name, "")
        if not token:
            return SsoResult(False, "missing")
        result = self.verify_token(token)
        if not result.ok:
            return result
        if result.payload.get("typ") != "session":
            return SsoResult(False, "type")
        if not self._audience_ok(result.payload, app_id):
            return SsoResult(False, "audience")
        return SsoResult(True, token=token, payload=result.payload, csrf=self.csrf_for(token))

    def verify_headers(self, headers: Any, app_id: str = "") -> SsoResult:
        cookie = ""
        try:
            cookie = headers.get("Cookie") or headers.get("cookie") or ""
        except Exception:
            cookie = ""
        return self.verify_cookie_header(cookie, app_id)

    # ---------- ticket ----------

    def verify_ticket(self, token: str, app_id: str) -> SsoResult:
        result = self.verify_token(token)
        if not result.ok:
            return result
        payload = result.payload
        if payload.get("typ") != "ticket":
            return SsoResult(False, "type")
        if not app_id or payload.get("aud") != app_id:
            return SsoResult(False, "audience")
        jti = payload.get("jti")
        if not jti:
            return SsoResult(False, "jti")
        now = int(time.time())
        if len(self._used_tickets) > 500:
            for key, exp in list(self._used_tickets.items()):
                if exp <= now:
                    self._used_tickets.pop(key, None)
        if jti in self._used_tickets:
            return SsoResult(False, "replay")
        self._used_tickets[jti] = int(payload.get("exp") or (now + 60))
        return SsoResult(True, token=token, payload=payload)

    # ---------- sign local sessions ----------

    def sign_session(self, app_id: str = "all", ttl_sec: int = 2592000) -> str:
        now = int(time.time())
        return self.sign_payload(
            {
                "v": 1,
                "typ": "session",
                "iss": "jd-auth",
                "aud": app_id,
                "sub": "owner",
                "iat": now,
                "exp": now + int(ttl_sec),
                "jti": b64url_encode(os.urandom(12)),
            }
        )

    # ---------- urls / cookies ----------

    def login_url(self, return_url: str = "") -> str:
        if not self.auth_url:
            return ""
        from urllib.parse import quote

        return self.auth_url + "/auth?return=" + quote(return_url or "", safe="")

    def logout_url(self, return_url: str = "") -> str:
        if not self.auth_url:
            return ""
        from urllib.parse import quote

        return self.auth_url + "/logout?return=" + quote(return_url or "", safe="")

    def cookie_header(self, token: str, max_age: int = 2592000) -> str:
        from urllib.parse import quote

        return "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d" % (
            self.cookie_name,
            quote(token, safe=""),
            int(max_age),
        )

    def clear_cookie_header(self) -> str:
        return "%s=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" % self.cookie_name
