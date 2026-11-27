"""
Session 管理模块
"""

import hmac
import ipaddress
import os
import secrets
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

from flask import g, request

from .config import SESSION_TIMEOUT

try:
    from .sso import SsoVerifier
except Exception:
    SsoVerifier = None

SSO_APP_ID = os.environ.get("CLOUDREIN_SSO_APP_ID", "webdav")
TRUSTED_PROXIES = []
for _proxy in os.environ.get("CLOUDREIN_TRUSTED_PROXIES", "").split(","):
    _proxy = _proxy.strip()
    if not _proxy:
        continue
    try:
        TRUSTED_PROXIES.append(ipaddress.ip_network(_proxy, strict=False))
    except ValueError:
        print("Warning: ignoring invalid CLOUDREIN_TRUSTED_PROXIES entry")
SSO_VERIFIER = None
if SsoVerifier is not None:
    try:
        SSO_VERIFIER = SsoVerifier(
            secret_file=os.environ.get("JD_SSO_SECRET_FILE", "/opt/jd-auth/data/sso.key"),
            auth_url=os.environ.get("JD_AUTH_URL", "http://117.72.196.45:12006"),
        )
    except Exception as exc:
        print(f"Warning: JD-Auth SSO disabled: {exc}")


def sso_authenticated() -> bool:
    result = sso_session()
    return bool(result and result.ok)


def sso_session():
    if SSO_VERIFIER is None:
        return None
    try:
        if not SSO_VERIFIER.is_configured():
            return None
        result = SSO_VERIFIER.verify_headers(request.headers, SSO_APP_ID)
        return result if result.ok else None
    except Exception:
        return None

# Session 存储
sessions = {}
_sessions_lock = threading.RLock()


def cleanup_sessions():
    """清理过期会话"""
    now = int(time.time())
    with _sessions_lock:
        expired = [sid for sid, sess in sessions.items() if sess["expire"] < now]
        for sid in expired:
            del sessions[sid]


def create_session(user: str) -> str:
    """创建新会话"""
    cleanup_sessions()
    sid = secrets.token_urlsafe(32)
    with _sessions_lock:
        sessions[sid] = {
            "user": user,
            "expire": int(time.time()) + SESSION_TIMEOUT,
            "csrf": secrets.token_urlsafe(32),
        }
    return sid


def get_session(sid: str) -> Optional[dict]:
    """获取会话；没有本地会话时，有效 jd_sso 视为已登录"""
    cleanup_sessions()
    with _sessions_lock:
        sess = sessions.get(sid)
        if sess and sess["expire"] >= int(time.time()):
            return dict(sess)
    if sso_authenticated():
        return {"user": "sso", "expire": int(time.time()) + 60}
    return None


def auth_session() -> dict:
    if hasattr(g, "cloudrein_auth"):
        return g.cloudrein_auth
    sid = get_cookie("sessionid")
    sess = get_session(sid) if sid else None
    if sess and sess.get("csrf"):
        result = {"ok": True, "authType": "local", "csrf": sess["csrf"], "sid": sid}
    else:
        sso = sso_session()
        result = ({"ok": True, "authType": "sso", "csrf": sso.csrf, "sid": "jd-sso"}
                  if sso else {"ok": False, "authType": "", "csrf": "", "sid": ""})
    g.cloudrein_auth = result
    return result


def delete_session(sid: str):
    """删除会话"""
    with _sessions_lock:
        sessions.pop(sid, None)


def get_cookie(name: str) -> Optional[str]:
    """获取 cookie"""
    cookies = request.headers.get('Cookie', '')
    for cookie in cookies.split(';'):
        if '=' in cookie:
            k, v = cookie.strip().split('=', 1)
            if k == name:
                return v
    return None


def require_auth() -> Optional[str]:
    """验证登录状态：本地会话优先，其次 JD-Auth 统一密钥"""
    sid = get_cookie('sessionid')
    if sid and get_session(sid):
        return sid
    if sso_authenticated():
        return 'jd-sso'
    return None


def is_authenticated() -> bool:
    """检查是否已认证（本地会话或统一密钥）"""
    return auth_session()["ok"]


def _origin(raw: str) -> str:
    try:
        parsed = urlsplit(str(raw or "").strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if scheme not in ("http", "https") or not host or parsed.username is not None:
            return ""
        port = parsed.port or (443 if scheme == "https" else 80)
        if port < 1 or port > 65535:
            return ""
        authority = f"[{host}]" if ":" in host else host
        normalized = f"{scheme}://{authority}"
        return normalized if port == (443 if scheme == "https" else 80) else f"{normalized}:{port}"
    except (TypeError, ValueError):
        return ""


def trusted_proxy() -> bool:
    try:
        peer = ipaddress.ip_address(request.remote_addr or "")
        return any(peer in network for network in TRUSTED_PROXIES)
    except ValueError:
        return False


def forwarded_value(name: str, default: str) -> str:
    if not trusted_proxy():
        return default
    return request.headers.get(name, default).split(",", 1)[0].strip()


def origin_ok() -> bool:
    origin = request.headers.get("Origin")
    if origin is None:
        return request.headers.get("X-CloudRein-Client", "").lower() == "native"
    if not origin or origin.lower() == "null":
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return False
    scheme = forwarded_value("X-Forwarded-Proto", request.scheme)
    host = forwarded_value("X-Forwarded-Host", request.host)
    return _origin(origin) == _origin(f"{scheme}://{host}")


def csrf_ok() -> bool:
    session = auth_session()
    supplied = request.headers.get("X-CSRF-Token", "")
    return bool(session["ok"] and session["csrf"] and supplied
                and hmac.compare_digest(
                    str(supplied).encode("utf-8"),
                    str(session["csrf"]).encode("utf-8")
                ))


def write_guard_error():
    from flask import jsonify

    if not origin_ok():
        return jsonify({"error": "origin"}), 403
    session = auth_session()
    if not session["ok"]:
        return jsonify({"error": "Unauthorized"}), 401
    if not csrf_ok():
        return jsonify({"error": "csrf"}), 403
    return None


def secure_cookies() -> bool:
    return forwarded_value("X-Forwarded-Proto", request.scheme).lower() == "https"


def client_ip() -> str:
    if trusted_proxy():
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"