"""
Session 管理模块
"""

import os
import time
import secrets
from typing import Optional
from flask import request

from .config import SESSION_TIMEOUT

try:
    from .sso import SsoVerifier
except Exception:
    SsoVerifier = None

SSO_APP_ID = os.environ.get("CLOUDREIN_SSO_APP_ID", "webdav")
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
    if SSO_VERIFIER is None:
        return False
    try:
        if not SSO_VERIFIER.is_configured():
            return False
        return bool(SSO_VERIFIER.verify_headers(request.headers, SSO_APP_ID).ok)
    except Exception:
        return False

# Session 存储
sessions = {}


def cleanup_sessions():
    """清理过期会话"""
    now = int(time.time())
    expired = [sid for sid, sess in sessions.items() if sess["expire"] < now]
    for sid in expired:
        del sessions[sid]


def create_session(user: str) -> str:
    """创建新会话"""
    cleanup_sessions()
    sid = secrets.token_urlsafe(32)
    sessions[sid] = {"user": user, "expire": int(time.time()) + SESSION_TIMEOUT}
    return sid


def get_session(sid: str) -> Optional[dict]:
    """获取会话；没有本地会话时，有效 jd_sso 视为已登录"""
    cleanup_sessions()
    sess = sessions.get(sid)
    if sess and sess["expire"] >= int(time.time()):
        return sess
    if sso_authenticated():
        return {"user": "sso", "expire": int(time.time()) + 60}
    return None


def delete_session(sid: str):
    """删除会话"""
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
    sid = get_cookie('sessionid')
    if bool(sid and get_session(sid)):
        return True
    return sso_authenticated()