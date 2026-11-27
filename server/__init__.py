# -*- coding: utf-8 -*-
"""
CloudRein Server - Modular Package
"""

import os
from pathlib import Path
from flask import Flask, request
from flask_socketio import SocketIO

# 项目根目录
PROJECT_DIR = Path(__file__).parent.parent
PROJECT_CONFIG_FILE = PROJECT_DIR / "config.yaml"

# 全局配置对象
_config = None
_config_file_path = None

# Flask 应用
app = None
socketio = None


def create_app() -> Flask:
    """创建并配置Flask应用"""
    global app, socketio, _config, _config_file_path

    # 加载配置
    from .config import load_config, load_user_config
    _config = load_config()
    load_user_config()

    # 创建Flask应用
    app = Flask(__name__, static_folder=None)
    app.config['SECRET_KEY'] = os.urandom(32)
    allowed_origins = [value.strip() for value in
                       os.environ.get("CLOUDREIN_ALLOWED_ORIGINS", "").split(",")
                       if value.strip()]
    socketio = SocketIO(
        app,
        cors_allowed_origins=allowed_origins,
        async_mode='threading'
    )

    from .session import origin_ok, write_guard_error

    @app.get("/api/health")
    def _public_health():
        return {"ok": True}

    @app.before_request
    def _protect_api_writes():
        if not request.path.startswith('/api/') or request.method in ('GET', 'HEAD'):
            return None
        if not origin_ok():
            return write_guard_error()
        if request.path == '/api/login':
            return None
        return write_guard_error()

    @app.errorhandler(Exception)
    def _handle_api_error(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception("CloudRein request failed")
        if request.path.startswith('/api/'):
            return {"error": "Internal server error"}, 500
        raise exc

    # 注册路由蓝图
    from .routes import register_routes
    register_routes(app)

    # JD-Auth 统一密钥：跨域名票据换本地会话
    try:
        from .sso_hooks import register_sso
        register_sso(app)
    except Exception as exc:
        print(f"Warning: JD-Auth SSO hooks disabled: {exc}")

    return app


def get_app() -> Flask:
    """获取Flask应用实例"""
    global app
    if app is None:
        create_app()
    return app


def get_socketio() -> SocketIO:
    """获取SocketIO实例"""
    global socketio
    if socketio is None:
        get_app()  # 确保已初始化
    return socketio