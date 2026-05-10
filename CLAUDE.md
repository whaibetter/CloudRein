# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CloudRein is a web-based Linux server file management tool with file browsing/editing/upload/download, real-time system monitoring, and OCR text recognition. The UI is a single-page app (`index.html`) served by a Python Flask backend.

## Commands

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run the server (development)
python3 cloudrein-server.py

# Service management (production, requires sudo)
sudo cloudrein restart    # Restart service (reloads code)
sudo cloudrein status     # Check service status
sudo cloudrein logs -f    # View logs in real-time
sudo cloudrein passwd     # Change login password
```

The service runs via systemd (`cloudrein.service`), executing `python3 cloudrein-server.py` from `/home/cloudrein`. No build step — restart the service to pick up changes.

## Deployment

CloudRein is deployed behind nginx at the `/cloudrein/` subpath. Nginx strips the prefix when proxying to Flask on `127.0.0.1:9001`.

The nginx config is at `/etc/nginx/conf.d/light-cloud-disk.conf` — a single unified server block on port 80 that also handles other services (`/cloud/`, `/accounting/`, `/wallpaper/`). Per-port configs for independent services live in `sites-enabled/` (toolhub:8081, cloudfiles:8082, syncCloud:8083).

The frontend auto-detects the base path via `BASE_PATH` (defined in `index.html`). All API calls go through `apiUrl(path)` which prepends `BASE_PATH`. All `fetch()` calls and `history.pushState()` use this mechanism — do not hardcode paths.

## Architecture

### Backend (`server/` package)

- **`server/__init__.py`** — Flask app factory. Creates the Flask app and SocketIO instance, registers route blueprints. Uses `async_mode='threading'`.
- **`server/main.py`** — Entry point called by `cloudrein-server.py`. Runs the SocketIO server.
- **`server/config.py`** — Configuration management. Loads `config.yaml` (project defaults) and `/etc/cloudrein/user_config.yaml` (user overrides, takes precedence). Exports module-level constants (`SERVER_HOST`, `SERVER_PORT`, `SESSION_TIMEOUT`, `MAX_*` limits, etc.) that are evaluated at import time.
- **`server/auth.py`** — Permission checking, whitelist management, quick paths, password verification (SHA256 hash stored in `/etc/cloudrein/passwd`).
- **`server/session.py`** — In-memory session store with cookie-based auth. Sessions expire after `SESSION_TIMEOUT` seconds.
- **`server/system.py`** — System info collection by reading `/proc/*` files and running shell commands. No external dependencies (no psutil).
- **`server/monitor_history.py`** — In-memory deque-based history for monitoring metrics (CPU, memory, network, disk I/O, temperature).

### Routes (`server/routes/`)

All routes are registered as Flask Blueprints in `server/routes/__init__.py`:
- **`files.py`** — Core file operations (browse, save, create, delete, rename, chmod, upload, download). Also serves the SPA HTML and handles login/logout/auth check. Routes: `/`, `/files`, `/monitor`, `/tools`, `/api/file/*`, `/api/login`, `/api/logout`, `/api/auth/check`, `/api/system`, `/api/system/restart`.
- **`config.py`** — Quick paths, password change, user config CRUD. Routes: `/api/quickpaths`, `/api/changepwd`, `/api/userconfig/*`.
- **`whitelist.py`** — Delete whitelist management. Routes: `/api/whitelist`.
- **`ai.py`** — OCR via SiliconFlow API (DeepSeek-OCR model). Routes: `/api/ai/config`, `/api/ai/models`, `/api/ai/ocr`.

### Frontend

`index.html` is a self-contained single-page application (~197KB). All pages (file manager, system monitor, tools) are rendered client-side based on URL path. Uses Highlight.js for code viewing and CodeMirror for editing.

Frontend routing uses `BASE_PATH` + relative paths: `switchTab()` pushes `BASE_PATH + '/files'` etc. into browser history, and `initPageFromUrl()` strips `BASE_PATH` before comparing. The `apiUrl(path)` helper prepends `BASE_PATH` to all API endpoints.

### Configuration

| File | Location | Purpose |
|------|----------|---------|
| `config.yaml` | `/home/cloudrein/` | Project defaults (server, security, permissions, download limits) |
| `user_config.yaml` | `/etc/cloudrein/` | User overrides (session timeout, permissions, download limits) |
| `passwd` | `/etc/cloudrein/` | SHA256 password hash |
| `ai_config.json` | `/etc/cloudrein/` | OCR API key and model config |
| `quick_paths.json` | `/etc/cloudrein/` | Navigation shortcuts |

User config merges over project config at startup. The `get_effective_config()` function in `config.py` handles the merge logic.

## Key Patterns

- **Auth**: All `/api/*` routes (except login) call `require_auth()` which checks a `sessionid` cookie against the in-memory session store.
- **Permissions**: File operations check `check_permission(path, action)` which looks up `folder_permissions` from config, falling back to `default_permissions`.
- **Delete safety**: Deletion requires the path to be in the whitelist (`is_in_whitelist()`).
- **Config hot-reload**: The server reads config at startup. After changing config files, a service restart is needed.
- **No external system deps**: System monitoring reads directly from `/proc/*` and uses shell commands — no psutil or similar.
