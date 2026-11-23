# -*- coding: utf-8 -*-
"""JD-Auth 统一密钥：域名票据换本地会话；退出时清理 jd_sso。"""
import os
from urllib.parse import urlencode

from flask import g, redirect, request

from .session import create_session
from .sso import SsoVerifier

APP_ID = os.environ.get("CLOUDREIN_SSO_APP_ID", "webdav")
VERIFIER = SsoVerifier(
    secret_file=os.environ.get("JD_SSO_SECRET_FILE", "/opt/jd-auth/data/sso.key"),
    auth_url=os.environ.get("JD_AUTH_URL", "http://117.72.196.45:12006"),
)


def register_sso(app):
    @app.before_request
    def _jd_ticket_login():
        token = request.args.get("jd_ticket")
        if not token:
            return None
        try:
            result = VERIFIER.verify_ticket(token, APP_ID)
        except Exception as exc:
            app.logger.warning("JD-Auth ticket error: %s", exc)
            return None
        if not result.ok:
            app.logger.warning("JD-Auth ticket rejected: %s", result.reason)
            return None
        g.sso_session = create_session("sso")
        args = request.args.to_dict(flat=True)
        args.pop("jd_ticket", None)
        target = request.path + ("?" + urlencode(args) if args else "")
        return redirect(target, code=302)

    @app.after_request
    def _jd_ticket_cookie(response):
        sid = getattr(g, "sso_session", None)
        if sid:
            response.set_cookie("sessionid", sid, max_age=3600, httponly=True, samesite="Lax")
            # 按规范换发本域 jd_sso，App/浏览器后续访问不用再走票据
            token = VERIFIER.sign_session(APP_ID, 2592000)
            if token:
                response.set_cookie("jd_sso", token, max_age=2592000, httponly=True, samesite="Lax")
        if request.path == "/api/logout":
            response.set_cookie("jd_sso", "", max_age=0, path="/", httponly=True, samesite="Lax")
        return response