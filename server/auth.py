"""
权限与验证模块
"""

import os
import stat
import pwd
import grp
import hashlib
import hmac
import secrets
import tempfile
import threading
import time
from typing import Optional

from .config import (
    get_security_config,
    get_permissions_config,
    get_effective_config,
    DEFAULT_PERMISSIONS,
    FOLDER_PERMISSIONS,
    PASSWORD_FILE,
    QUICK_PATHS_FILE,
    DATA_DIR,
)


# === 白名单管理 ===
def load_whitelist() -> list:
    """加载删除白名单（从主配置文件）"""
    return get_security_config().get("delete_whitelist", ["/tmp", "/var/tmp"])


def save_whitelist(whitelist: list) -> bool:
    """保存删除白名单（到主配置文件）"""
    from .config import get_config, save_config

    config = get_config()
    if "security" not in config:
        config["security"] = {}
    config["security"]["delete_whitelist"] = whitelist
    return save_config(config)


def is_in_whitelist(path: str) -> bool:
    """检查路径是否在白名单中"""
    whitelist = load_whitelist()
    normalized_path = os.path.normpath(path)
    for allowed_path in whitelist:
        normalized_allowed = os.path.normpath(allowed_path)
        if normalized_path == normalized_allowed:
            return True
        if normalized_path.startswith(normalized_allowed + os.sep):
            return True
    return False


def format_whitelist_with_types(whitelist: list) -> list:
    """为白名单添加类型信息"""
    result = []
    for p in whitelist:
        normalized = os.path.normpath(p)
        if os.path.exists(normalized):
            path_type = "file" if os.path.isfile(normalized) else "dir"
        else:
            path_type = "unknown"
        result.append({"path": p, "type": path_type})
    return result


# === 快捷路径管理 ===
def get_quick_paths() -> list:
    """获取快捷路径配置（从 JSON 文件）"""
    try:
        if QUICK_PATHS_FILE.exists():
            with QUICK_PATHS_FILE.open("r", encoding="utf-8") as f:
                return __import__('json').load(f)
    except:
        pass
    return [
        {"path": "/", "name": "/ 根目录"},
        {"path": "/etc", "name": "/etc"},
        {"path": "/var/log", "name": "/var/log"},
        {"path": "/var/www/html", "name": "/var/www/html"},
    ]


def save_quick_paths(paths: list) -> bool:
    """保存快捷路径配置（到 JSON 文件）"""
    import json
    try:
        QUICK_PATHS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with QUICK_PATHS_FILE.open("w", encoding="utf-8") as f:
            json.dump(paths, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"Failed to save quick paths: {e}")
        return False


# === 文件权限 ===
def get_file_permissions(path: str) -> dict:
    """获取文件权限信息"""
    try:
        st = os.stat(path)
        mode = st.st_mode
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)
        return {
            "mode": stat.filemode(mode),
            "octal": oct(stat.S_IMODE(mode)),
            "owner": owner,
            "group": group,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime": st.st_mtime,
        }
    except Exception as e:
        print(f"Failed to read permissions for {path}: {e}")
        return {"error": "Unable to read permissions"}


def get_folder_permission_config(path: str) -> dict:
    """获取文件夹权限配置"""
    best_match = None
    best_len = 0
    for folder_path, perms in FOLDER_PERMISSIONS.items():
        if path.startswith(folder_path) and len(folder_path) > best_len:
            best_match = perms
            best_len = len(folder_path)
    return best_match if best_match else DEFAULT_PERMISSIONS


def check_permission(path: str, action: str) -> tuple:
    """检查权限"""
    perms = get_folder_permission_config(path)
    if action in perms:
        if perms[action] is None or perms[action]:
            return True, "allowed"
        else:
            return False, f"{action} permission denied for this folder"
    else:
        if action == "delete":
            return True, "allowed"
        if action == "read":
            return True, "allowed"
        else:
            return False, f"{action} permission denied by default"


# === 密码验证 ===
SCRYPT_PREFIX = "scrypt$16384$8$1$"
LOGIN_FAILURE_LIMIT = 10
LOGIN_FAILURE_WINDOW = 600
_login_failures = {}
_login_failures_lock = threading.Lock()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("ascii"),
        n=16384,
        r=8,
        p=1,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    ).hex()
    return SCRYPT_PREFIX + salt + "$" + digest


def _write_password_hash(password_hash: str) -> None:
    PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".passwd-", dir=str(PASSWORD_FILE.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(password_hash + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, PASSWORD_FILE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _password_status(password: str) -> str:
    if not isinstance(password, str):
        return "invalid"
    try:
        if not PASSWORD_FILE.exists():
            return "invalid"
        stored_hash = PASSWORD_FILE.read_text(encoding="ascii").strip()
        if stored_hash.startswith(SCRYPT_PREFIX):
            parts = stored_hash.split("$")
            if len(parts) != 6:
                return "invalid"
            digest = hashlib.scrypt(
                password.encode("utf-8"),
                salt=parts[4].encode("ascii"),
                n=int(parts[1]),
                r=int(parts[2]),
                p=1,
                dklen=32,
                maxmem=64 * 1024 * 1024,
            ).hex()
            return "valid" if hmac.compare_digest(digest, parts[5]) else "invalid"
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return "legacy" if hmac.compare_digest(stored_hash, legacy) else "invalid"
    except (OSError, ValueError, TypeError):
        return "invalid"


def verify_password(password: str, upgrade: bool = False) -> bool:
    """验证密码；旧 SHA-256 密码可在成功登录后升级"""
    status = _password_status(password)
    if status == "legacy" and upgrade:
        try:
            _write_password_hash(hash_password(password))
        except OSError:
            pass
    return status in ("valid", "legacy")


def login_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _login_failures_lock:
        for key, attempts in list(_login_failures.items()):
            if not attempts or now - attempts[-1] >= LOGIN_FAILURE_WINDOW:
                _login_failures.pop(key, None)
        attempts = _login_failures.get(ip, [])
        return len(attempts) >= LOGIN_FAILURE_LIMIT


def record_login_failure(ip: str) -> None:
    now = time.monotonic()
    with _login_failures_lock:
        attempts = [value for value in _login_failures.get(ip, [])
                    if now - value < LOGIN_FAILURE_WINDOW]
        attempts.append(now)
        _login_failures[ip] = attempts


def clear_login_failures(ip: str) -> None:
    with _login_failures_lock:
        _login_failures.pop(ip, None)


def change_password(old_password: str, new_password: str) -> tuple:
    """修改密码 - 验证旧密码后设置新密码"""
    if not verify_password(old_password):
        return False, "旧密码错误"
    if not isinstance(new_password, str) or len(new_password) < 12:
        return False, "新密码长度至少12位"
    try:
        _write_password_hash(hash_password(new_password))
        return True, "密码修改成功"
    except OSError:
        return False, "修改失败"