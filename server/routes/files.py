"""
文件操作路由模块
"""

import os
import shutil
import zipfile
import io
from pathlib import Path
from flask import Blueprint, current_app, request, jsonify, send_from_directory, Response

from ..config import (
    PROJECT_DIR,
    MAX_FILE_PREVIEW_SIZE,
    MAX_SINGLE_FILE_SIZE,
    MAX_TOTAL_DOWNLOAD_SIZE,
    MAX_FILES_IN_ZIP,
    MAX_DIR_DEPTH,
)
from ..session import (
    auth_session,
    client_ip,
    create_session,
    delete_session,
    get_cookie,
    is_authenticated,
    require_auth,
    secure_cookies,
)
from ..auth import (
    check_permission,
    clear_login_failures,
    get_file_permissions,
    get_folder_permission_config,
    is_in_whitelist,
    login_rate_limited,
    record_login_failure,
    verify_password,
)

# 创建蓝图
files_bp = Blueprint('files', __name__)


def _zip_response(tmp_path, download_name):
    response = current_app.make_response(send_from_directory(
        os.path.dirname(tmp_path), os.path.basename(tmp_path),
        as_attachment=True, download_name=download_name
    ))

    def cleanup():
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

    response.direct_passthrough = False
    response.call_on_close(cleanup)
    return response


class _DownloadLimitError(Exception):
    """下载内容超过配置限额；由路由转换为 413/400。"""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _resolved(path):
    """统一先走 normpath + realpath，避免 symlink/.. 绕过目录权限。"""
    return os.path.realpath(os.path.normpath(str(path or "")))


def _readable_target(path):
    target = _resolved(path)
    if not os.path.exists(target):
        return None, ('File not found', 404)
    allowed, reason = check_permission(target, 'read')
    if not allowed:
        return None, (reason or 'read permission denied', 403)
    return target, None


def _dir_files(root):
    """列出目录内真实文件；跳过逃逸到目录外的 symlink，并执行深度限制。"""
    resolved_root = _resolved(root)
    for dirpath, dirnames, filenames in os.walk(resolved_root, followlinks=False):
        rel = os.path.relpath(dirpath, resolved_root)
        depth = 0 if rel == '.' else rel.count(os.sep) + 1
        if depth > MAX_DIR_DEPTH:
            raise _DownloadLimitError(400, '目录层级超过限制')
        dirnames[:] = [name for name in dirnames
                       if not os.path.islink(os.path.join(dirpath, name))]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            real = os.path.realpath(full)
            if real != resolved_root and not real.startswith(resolved_root + os.sep):
                continue
            yield real


def _collect_download_files(items):
    """先收集并校验总量，再写 zip，避免超限请求留下半成品。"""
    collected = []
    total = 0
    for target, is_dir, root_name in items:
        if is_dir:
            for full in _dir_files(target):
                size = os.path.getsize(full)
                total += size
                if total > MAX_TOTAL_DOWNLOAD_SIZE:
                    raise _DownloadLimitError(413, '下载内容超过总大小限制')
                if len(collected) >= MAX_FILES_IN_ZIP:
                    raise _DownloadLimitError(400, '下载文件数量超过限制')
                collected.append((full, os.path.join(root_name, os.path.relpath(full, target))))
        else:
            size = os.path.getsize(target)
            if size > MAX_SINGLE_FILE_SIZE:
                raise _DownloadLimitError(413, '单个文件超过下载大小限制')
            total += size
            if total > MAX_TOTAL_DOWNLOAD_SIZE:
                raise _DownloadLimitError(413, '下载内容超过总大小限制')
            if len(collected) >= MAX_FILES_IN_ZIP:
                raise _DownloadLimitError(400, '下载文件数量超过限制')
            collected.append((target, root_name))
    return collected


def _limit_response(exc):
    return jsonify({'error': exc.message}), exc.status


@files_bp.route('/')
@files_bp.route('/monitor')
@files_bp.route('/files')
@files_bp.route('/tools')
@files_bp.route('/index.html')
def index():
    """主页 - 所有页面使用同一个 HTML，前端根据 URL 显示不同内容"""
    index_path = PROJECT_DIR / 'index.html'
    if index_path.exists():
        with open(index_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/html; charset=utf-8'}
    return jsonify({'error': 'index.html not found'}), 404


@files_bp.route('/logo.svg')
def logo():
    """Logo SVG"""
    logo_path = PROJECT_DIR / 'logo.svg'
    if logo_path.exists():
        with open(logo_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'image/svg+xml'}
    return jsonify({'error': 'logo.svg not found'}), 404


@files_bp.route('/api/login', methods=['POST'])
def login():
    """登录"""
    ip = client_ip()
    if login_rate_limited(ip):
        return jsonify({'error': 'Too many login attempts'}), 429, {'Retry-After': '600'}
    try:
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        if verify_password(password, upgrade=True):
            clear_login_failures(ip)
            sid = create_session('admin')
            response = jsonify({'success': True})
            response.set_cookie(
                'sessionid', sid, max_age=3600, httponly=True,
                samesite='Lax', secure=secure_cookies(), path='/'
            )
            return response
        record_login_failure(ip)
        return jsonify({'error': 'Invalid password'}), 401
    except Exception:
        record_login_failure(ip)
        return jsonify({'error': 'Bad request'}), 400


@files_bp.route('/api/logout', methods=['POST'])
def logout():
    """登出"""
    sid = get_cookie('sessionid')
    if sid:
        delete_session(sid)
    response = jsonify({'success': True})
    response.set_cookie(
        'sessionid', '', max_age=0, path='/', httponly=True,
        samesite='Lax', secure=secure_cookies()
    )
    return response


@files_bp.route('/api/session', methods=['GET'])
def session_info():
    session = auth_session()
    return jsonify({
        'authenticated': session['ok'],
        'authType': session['authType'],
        'csrf': session['csrf'],
    })


@files_bp.route('/api/auth/check', methods=['GET'])
def auth_check():
    """检查认证状态"""
    return jsonify({'authenticated': is_authenticated()})


@files_bp.route('/api/system', methods=['GET'])
def system():
    """系统信息"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    from ..system import collect_system_info
    return jsonify(collect_system_info())


@files_bp.route('/api/system/history', methods=['GET'])
def system_history():
    """系统历史数据"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    hours = request.args.get('hours', 1, type=int)
    # 限制只能查询 1、6、24 小时
    if hours not in [1, 6, 24]:
        hours = 1

    from ..monitor_history import get_history
    return jsonify(get_history(hours))


@files_bp.route('/api/system/restart', methods=['POST'])
def system_restart():
    """重启服务"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        import subprocess
        import threading
        import time
        
        def restart_after_delay():
            """延迟重启，让响应先返回"""
            time.sleep(0.5)  # 等待500ms让响应返回
            try:
                # 使用 systemctl 重启服务
                subprocess.run(['systemctl', 'restart', 'cloudrein'], 
                             check=True, 
                             capture_output=True,
                             timeout=10)
            except Exception as e:
                print(f"Failed to restart service: {e}")
        
        # 在后台线程中执行重启
        restart_thread = threading.Thread(target=restart_after_delay, daemon=True)
        restart_thread.start()
        
        return jsonify({'success': True, 'message': '服务重启中...'})
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file', methods=['GET'])
def file_info():
    """获取文件/目录信息"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    path = request.args.get('path', '')
    if not path:
        return jsonify({'error': "Missing 'path' parameter"}), 400

    file_path = _resolved(path)
    if not os.path.exists(file_path):
        return jsonify({'error': f'File not found: {file_path}'}), 404

    allowed, reason = check_permission(file_path, 'read')
    if not allowed:
        return jsonify({'error': reason}), 403

    folder_perms = get_folder_permission_config(file_path)

    if os.path.isdir(file_path):
        try:
            entries = []
            for name in sorted(os.listdir(file_path)):
                full = os.path.join(file_path, name)
                entries.append({
                    'name': name,
                    'type': 'dir' if os.path.isdir(full) else 'file',
                    'size': os.path.getsize(full) if os.path.isfile(full) else None,
                    'permissions': get_file_permissions(full),
                    'can_delete': is_in_whitelist(full),
                })
            dir_can_delete = is_in_whitelist(file_path)
            return jsonify({
                'type': 'directory',
                'path': file_path,
                'entries': entries,
                'permissions': get_file_permissions(file_path),
                'folder_permissions': folder_perms,
                'can_delete': dir_can_delete
            })
        except PermissionError:
            return jsonify({'error': 'Permission denied'}), 403

    # 文件
    size = os.path.getsize(file_path)
    if size > MAX_FILE_PREVIEW_SIZE:
        limit_mb = MAX_FILE_PREVIEW_SIZE // (1024 * 1024)
        return jsonify({'error': f'File too large ({size} bytes). Limit is {limit_mb} MB.'}), 413

    try:
        with open(file_path, 'rb') as f:
            raw = f.read()
        try:
            content = raw.decode('utf-8')
            encoding = 'utf-8'
        except UnicodeDecodeError:
            try:
                content = raw.decode('gbk')
                encoding = 'gbk'
            except UnicodeDecodeError:
                return jsonify({'error': 'Binary file, cannot display as text'}), 415

        return jsonify({
            'type': 'file',
            'path': file_path,
            'size': size,
            'encoding': encoding,
            'content': content,
            'permissions': get_file_permissions(file_path),
            'folder_permissions': folder_perms
        })
    except PermissionError:
        return jsonify({'error': 'Permission denied'}), 403


@files_bp.route('/api/file/save', methods=['POST'])
def file_save():
    """保存文件"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        file_path = data.get('path', '')
        content = data.get('content', '')

        if not file_path:
            return jsonify({'error': "Missing 'path' parameter"}), 400
        if not isinstance(content, str):
            return jsonify({'error': 'content must be a string'}), 400

        payload_size = len(content.encode('utf-8'))
        if payload_size > MAX_SINGLE_FILE_SIZE:
            return jsonify({'error': '文件超过单文件大小限制'}), 413

        file_path = _resolved(file_path)
        allowed, reason = check_permission(file_path, 'write')
        if not allowed:
            return jsonify({'error': reason}), 403

        if os.path.exists(file_path):
            shutil.copy2(file_path, file_path + '.bak')

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return jsonify({'success': True, 'path': file_path, 'size': payload_size})
    except PermissionError:
        return jsonify({'error': 'Permission denied'}), 403
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file/create', methods=['POST'])
def file_create():
    """创建文件/目录"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        # Support both 'path' and 'parent+name' format
        path = data.get('path', '')
        if not path:
            parent = data.get('parent', '')
            name = data.get('name', '')
            if not parent or not name:
                return jsonify({'error': "Missing 'path' or 'parent'+'name' parameters"}), 400
            path = os.path.join(parent, name)
        file_type = data.get('type', 'file')

        path = _resolved(path)
        parent = os.path.dirname(path)

        if not os.path.exists(parent):
            return jsonify({'error': 'Parent directory does not exist'}), 400

        allowed, reason = check_permission(parent, 'write')
        if not allowed:
            return jsonify({'error': reason}), 403

        if os.path.exists(path):
            return jsonify({'error': 'File or directory already exists'}), 400

        if file_type == 'directory':
            os.makedirs(path)
        else:
            with open(path, 'w') as f:
                pass

        return jsonify({'success': True, 'path': path})
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file/delete', methods=['POST'])
def file_delete():
    """删除文件/目录"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        paths = data.get('paths', [])

        if not paths:
            return jsonify({'error': "Missing 'paths' parameter"}), 400

        deleted = []
        failed = []

        for path in paths:
            path = os.path.join(_resolved(os.path.dirname(path)), os.path.basename(path))
            if not os.path.exists(path):
                failed.append({'path': path, 'error': 'File not found'})
                continue
            if not is_in_whitelist(path):
                failed.append({'path': path, 'error': 'Not in whitelist'})
                continue

            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                deleted.append(path)
            except Exception:
                current_app.logger.exception("Failed to delete %s", path)
                failed.append({'path': path, 'error': 'Delete failed'})

        msg = f'已删除 {len(deleted)} 项'
        if failed:
            msg += f'，{len(failed)} 项失败'

        return jsonify({'success': True, 'deleted': deleted, 'failed': failed, 'message': msg})
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file/rename', methods=['POST'])
def file_rename():
    """重命名文件/目录"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        old_path = data.get('path', '')
        new_name = data.get('new_name', '')

        if not old_path:
            return jsonify({'error': "Missing 'path' parameter"}), 400
        if not new_name:
            return jsonify({'error': "Missing 'new_name' parameter"}), 400

        # 验证新名称不包含路径分隔符
        if '/' in new_name or '\\' in new_name:
            return jsonify({'error': 'New name cannot contain path separators'}), 400

        old_path = os.path.join(_resolved(os.path.dirname(old_path)), os.path.basename(old_path))
        if not os.path.exists(old_path):
            return jsonify({'error': 'File or directory not found'}), 404

        # 检查写入权限
        allowed, reason = check_permission(old_path, 'write')
        if not allowed:
            return jsonify({'error': reason}), 403

        # 构建新路径
        parent = os.path.dirname(old_path)
        new_path = os.path.join(parent, new_name)

        # 检查目标是否已存在
        if os.path.exists(new_path):
            return jsonify({'error': 'File or directory already exists'}), 400

        # 执行重命名
        os.rename(old_path, new_path)

        return jsonify({
            'success': True,
            'old_path': old_path,
            'new_path': new_path,
            'new_name': new_name
        })
    except PermissionError:
        return jsonify({'error': 'Permission denied'}), 403
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file/chmod', methods=['POST'])
def file_chmod():
    """修改文件权限"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        path = data.get('path', '')
        mode = data.get('mode', '755')

        if not path:
            return jsonify({'error': "Missing 'path' parameter"}), 400

        path = _resolved(path)
        if not os.path.exists(path):
            return jsonify({'error': 'File not found'}), 404

        allowed, reason = check_permission(path, 'write')
        if not allowed:
            return jsonify({'error': reason}), 403

        mode_int = int(mode, 8)
        os.chmod(path, mode_int)

        return jsonify({'success': True, 'path': path, 'mode': mode})
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file/upload', methods=['POST'])
def file_upload():
    """上传文件"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        dir_path = request.form.get('path')
        if not dir_path:
            return jsonify({'error': 'Missing path'}), 400

        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file uploaded'}), 400

        # multipart 有边界与头开销，预留 1MB；落盘后再按真实大小复核。
        if request.content_length and request.content_length > MAX_SINGLE_FILE_SIZE + 1024 * 1024:
            return jsonify({'error': '文件超过单文件大小限制'}), 413

        dir_path = _resolved(dir_path)

        allowed, reason = check_permission(dir_path, 'write')
        if not allowed:
            return jsonify({'error': reason}), 403

        # 只允许纯文件名，防止通过文件名跳出目标目录
        filename = os.path.basename((file.filename or '').replace('\\', '/'))
        if not filename or filename in ('.', '..'):
            return jsonify({'error': 'Invalid filename'}), 400

        # 拼接目录 + 文件名
        path = os.path.join(dir_path, filename)

        # 处理文件名冲突
        final_path = path
        counter = 1
        while os.path.exists(final_path):
            base, ext = os.path.splitext(path)
            final_path = f'{base}_{counter}{ext}'
            counter += 1

        file.save(final_path)

        if os.path.getsize(final_path) > MAX_SINGLE_FILE_SIZE:
            try:
                os.unlink(final_path)
            except OSError:
                pass
            return jsonify({'error': '文件超过单文件大小限制'}), 413

        return jsonify({'success': True, 'path': final_path})
    except Exception:
        current_app.logger.exception("CloudRein file API operation failed")
        return jsonify({'error': 'Internal server error'}), 500


@files_bp.route('/api/file/download', methods=['GET'])
def file_download():
    """下载文件"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    path = request.args.get('path', '')
    if not path:
        return jsonify({'error': "Missing 'path' parameter"}), 400

    target, error = _readable_target(path)
    if error:
        message, status = error
        return jsonify({'error': message}), status

    if os.path.isdir(target):
        dirname = os.path.basename(target) or 'root'
        try:
            entries = _collect_download_files([(target, True, dirname)])
        except _DownloadLimitError as exc:
            return _limit_response(exc)

        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_full, arcname in entries:
                    zf.write(file_full, arcname)
        except Exception:
            os.unlink(tmp_path)
            raise

        return _zip_response(tmp_path, f"{dirname}.zip")

    if os.path.getsize(target) > MAX_SINGLE_FILE_SIZE:
        return jsonify({'error': '单个文件超过下载大小限制'}), 413

    return send_from_directory(os.path.dirname(target), os.path.basename(target), as_attachment=True)


@files_bp.route('/api/file/download/batch', methods=['POST'])
def batch_download():
    """批量下载"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.json
        paths = data.get('paths') if isinstance(data, dict) else None

        if not isinstance(paths, list) or not paths:
            return jsonify({'error': "Missing 'paths' parameter"}), 400

        targets = []
        for p in paths:
            if not isinstance(p, str) or not p.strip():
                return jsonify({'error': 'Invalid path'}), 400
            target, error = _readable_target(p)
            if error:
                message, status = error
                return jsonify({'error': f'Access denied: {message}'}), status
            targets.append((target, os.path.isdir(target), os.path.basename(target) or 'root'))

        try:
            entries = _collect_download_files(targets)
        except _DownloadLimitError as exc:
            return _limit_response(exc)

        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_full, arcname in entries:
                    zf.write(file_full, arcname)
        except Exception:
            os.unlink(tmp_path)
            raise

        return _zip_response(tmp_path, "download.zip")
    except _DownloadLimitError as exc:
        return _limit_response(exc)
    except Exception as e:
        current_app.logger.exception("Batch download failed")
        return jsonify({'error': 'Internal server error'}), 500