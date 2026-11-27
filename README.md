# CloudRein

基于 Web 的 Linux 服务器文件管理工具，提供文件浏览、编辑、上传、下载、系统监控、OCR 文字识别等功能。

> **本分支（`feature/file-library-webdav-gateway`）是"文件库精简版"**：在原版基础上裁剪功能、限定文件范围，并新增 WebDAV 分流网关，适合与 rclone WebDAV 共用同一端口对外服务。详见下文[本分支变更](#本分支变更)。

## 本分支变更

### 功能裁剪

- 界面只保留「文件管理」标签；系统监控、工具中心（OCR）入口已隐藏（后端能力保留，去掉隐藏样式即可恢复）
- 设置面板只保留「快捷路径」和「密码修改」两个标签页
- 文件浏览 / 读写范围限定在 `/data/webdav`，其余目录默认无任何权限（`default_permissions` 全关）
- 快捷路径默认指向 `/data/webdav` 及其常用子目录

### WebDAV 分流网关（新增 `gateway/server.js`）

零依赖 Node HTTP 网关，单端口同时对外提供网页和 WebDAV 两种服务，按请求特征分流：

```
浏览器 ──> 12179 网关 ──┬─> CloudRein 127.0.0.1:12151   网页 / API / WebSocket
                        ├─> rclone    127.0.0.1:12150   WebDAV（PROPFIND/PUT/MKCOL 等方法、Basic 认证）
                        └─> assets/                     本地静态资源
```

分流规则：

| 请求特征 | 去向 |
|----------|------|
| WebDAV 方法（PROPFIND、PROPPATCH、MKCOL、LOCK、UNLOCK、MOVE、COPY、OPTIONS）或 PUT / DELETE / PATCH | rclone |
| GET/HEAD 且带 Basic 认证头 | rclone |
| `/api/*`、`/socket.io/*`、页面路径 | CloudRein |
| `/assets/*` | 网关本地目录 |

网关环境变量：`PORT`（默认 12179）、`CLOUDREIN_PORT`、`RCLONE_PORT`、`ASSETS_DIR`。

Flask 的 `CLOUDREIN_TRUSTED_PROXIES` 是逗号分隔的可信代理 IP/CIDR 列表；只对这些直连 peer 信任 `X-Forwarded-Proto`、`X-Forwarded-Host` 和 `X-Forwarded-For`。经本地网关访问时配置 `127.0.0.1`，直接访问 Flask 时留空。网关自己的 `CLOUDREIN_TRUST_PROXY=1` 是另一项开关，只在明确需要读取上游协议头时启用。

### 前端资源本地化

原版 `index.html` 引用 55 个外网 CDN 的 JS/CSS（Vue、CodeMirror、Highlight.js 等），本分支全部下载到 `assets/` 并改写为 `/assets/...` 本地引用，内网或离线环境可正常使用；个别 CDN 上本就不存在的语言包（toml/vue/typescript）已一并移除引用。

### 安全加固

- 上传接口修复文件名路径穿越问题：只取纯文件名（`basename`），拒绝空名和 `.`/`..`（`server/routes/files.py`）

### 部署要点（本分支实际使用的配置）

```yaml
server:
  host: "127.0.0.1"   # 只监听本地，由网关对外
  port: 12151

permissions:
  folder_permissions:
    "/data/webdav": {read: true, write: true}
  default_permissions: {read: false, write: false}

security:
  delete_whitelist: ["/data/webdav"]
```

- systemd 服务：`cloudrein.service`（12151，`MemoryMax=512M`）+ `cloudrein-gateway.service`（12179，`MemoryMax=128M`）
- rclone WebDAV 改绑 `127.0.0.1:12150`，不再直接对外

## 功能特性

### 文件管理
- **文件浏览** - 浏览服务器上的任意目录和文件
- **文件排序** - 支持按名称、大小、类型、所有者排序，文件夹优先显示
- **类型显示** - 中文友好显示文件类型（文件夹、Python、文本文件等）
- **快捷路径** - 自定义快捷访问路径，方便快速导航
- **文件编辑** - 在线编辑文本文件，保存前自动备份
- **语法高亮** - 代码查看和编辑支持语法高亮
  - 支持 30+ 种语言：Python、YAML、JSON、JavaScript、TypeScript、Go、Rust、Java、C/C++、Ruby、PHP 等
  - 查看模式使用 Highlight.js 提供行号和语法着色
  - 编辑模式使用 CodeMirror 提供完整 IDE 体验（括号匹配、自动补全、快捷键等）
  - 支持 Ctrl+S / Cmd+S 快捷保存
- **新建文件/文件夹** - 快速创建新文件或目录
- **重命名** - 支持重命名文件和文件夹，自动校验名称合法性
- **文件上传** - 支持拖拽上传，自动重命名冲突文件
- **文件下载** - 支持单文件下载和批量打包下载
- **文件删除** - 支持白名单管控，防止误删系统重要文件
- **权限管理** - 查看和修改文件权限

### 系统监控（本分支已隐藏入口，后端保留）
- **实时监控** - CPU、内存、磁盘、网络状态实时展示
- **历史数据** - 支持查看 1 小时、6 小时、24 小时历史数据
- **进程管理** - 查看系统进程列表和资源占用
- **温度监控** - 支持 CPU/系统温度监控（需硬件支持）
- **磁盘 I/O** - 实时磁盘读写速率监控

### 工具中心（本分支已隐藏入口，后端保留）
- **OCR 文字识别** - 支持图片文字识别，多种模型可选
  - 三种识别模式：OCR文字识别、Markdown格式、纯文本提取
  - 支持 DeepSeek-OCR、Qwen2-VL 等多种模型
  - 可折叠调试面板，显示请求/响应参数

### 系统配置
- **用户配置** - Web 界面管理白名单、快捷路径等配置
- **URL 历史** - 支持浏览器前进/后退导航
- **YAML 配置** - 统一配置管理，无需修改代码

## 环境要求

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| Python | 3.8+ | 运行环境 |
| pip | 最新 | Python 包管理器 |
| systemd | - | 服务管理（仅支持 Linux） |
| Nginx | 可选 | 反向代理 / HTTPS |

## 快速开始

### 方式一：一键安装脚本（推荐）

```bash
# 1. 克隆项目
git clone https://github.com/whaibetter/cloudrein.git /home/cloudrein
cd /home/cloudrein

# 2. 运行安装脚本
sudo ./install.sh

# 3. 修改默认密码
sudo cloudrein passwd
```

### 方式二：手动安装

<details>
<summary>点击展开手动安装步骤</summary>

#### 步骤 1：克隆项目

```bash
git clone https://github.com/whaibetter/cloudrein.git /home/cloudrein
cd /home/cloudrein
```

#### 步骤 2：安装 Python 依赖

```bash
pip3 install pyyaml flask flask-socketio python-socketio eventlet aiohttp python-dotenv
```

#### 步骤 3：创建数据目录

```bash
sudo mkdir -p /etc/cloudrein
```

#### 步骤 4：初始化密码文件

```bash
# 设置默认密码为 admin（SHA256 哈希）
echo -n "admin" | sha256sum | awk '{print $1}' | sudo tee /etc/cloudrein/passwd
sudo chmod 600 /etc/cloudrein/passwd
```

#### 步骤 5：安装管理脚本

```bash
sudo cp cloudrein /usr/local/bin/
sudo chmod 755 /usr/local/bin/cloudrein
```

#### 步骤 6：安装 systemd 服务

```bash
sudo cp cloudrein.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudrein
sudo systemctl start cloudrein
```

#### 步骤 7：验证安装

```bash
# 检查服务状态
sudo cloudrein status

# 查看日志
sudo cloudrein logs
```

</details>

## 详细部署教程

### 1. 系统准备

确保您的服务器满足以下条件：

```bash
# 检查 Python 版本
python3 --version  # 应 >= 3.8

# 检查 pip
pip3 --version

# 检查 systemd
systemctl --version
```

如缺少必要组件，请先安装：

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip

# CentOS/RHEL
sudo yum install -y python3 python3-pip
```

### 2. 安装 CloudRein

```bash
# 克隆项目到指定目录
git clone https://github.com/whaibbetter/cloudrein.git /home/cloudrein
cd /home/cloudrein

# 运行一键安装脚本
sudo ./install.sh
```

安装脚本会自动完成以下操作：
- 检查系统环境（Python、pip、systemd）
- 安装所有 Python 依赖
- 创建数据目录 `/etc/cloudrein`
- 初始化密码文件、AI 配置、快捷路径配置
- 安装管理脚本到 `/usr/local/bin/cloudrein`
- 注册并启动 systemd 服务

### 3. 修改默认密码

```bash
sudo cloudrein passwd
```

按提示输入新密码并确认。密码将以 SHA256 哈希形式存储在 `/etc/cloudrein/passwd`。

### 4. 访问 Web 界面

安装完成后，通过浏览器访问：

```
http://<服务器IP>:9001
```

使用您设置的密码登录系统。

### 5. 配置 Nginx 反向代理（推荐）

直接暴露 9001 端口不够安全，推荐使用 Nginx 做反向代理并启用 HTTPS。

#### 5.1 安装 Nginx

```bash
# Debian/Ubuntu
sudo apt install -y nginx

# CentOS/RHEL
sudo yum install -y nginx
```

#### 5.2 配置 Nginx

创建配置文件 `/etc/nginx/sites-available/cloudrein`：

```bash
sudo nano /etc/nginx/sites-available/cloudrein
```

**HTTP 配置（临时使用）：**

```nginx
server {
    listen 80;
    server_name your-domain.com;  # 替换为您的域名或服务器IP

    # 客户端最大上传大小
    client_max_body_size 100M;

    # WebSocket 支持
    location /socket.io/ {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }

    # API 请求
    location /api/ {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }

    # 前端页面
    location / {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 5.3 启用配置

```bash
# 启用站点
sudo ln -s /etc/nginx/sites-available/cloudrein /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重载 Nginx
sudo systemctl reload nginx
```

#### 5.4 配置 HTTPS（推荐）

使用 Let's Encrypt 免费 SSL 证书：

```bash
# 安装 Certbot
sudo apt install -y certbot python3-certbot-nginx  # Debian/Ubuntu
# 或
sudo yum install -y certbot python3-certbot-nginx  # CentOS/RHEL

# 获取证书
sudo certbot --nginx -d your-domain.com

# 自动续期
sudo certbot renew --dry-run
```

Certbot 会自动更新 Nginx 配置以启用 HTTPS。

### 6. 安全加固

#### 6.1 防火墙配置

```bash
# 仅开放必要端口
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# 或直接关闭 9001 端口的公网访问（Nginx 已做代理）
sudo ufw deny 9001/tcp
```

#### 6.2 配置删除白名单

登录 Web 界面后，点击右上角"设置" -> "删除白名单"，添加允许删除的路径，例如：

```
/tmp
/var/tmp
/home/user/uploads
/var/www/html/uploads
```

#### 6.3 配置目录权限

在"设置" -> "系统配置"中可以限制特定目录的读写权限。

### 7. 配置 OCR 功能

如需使用 OCR 文字识别功能：

1. 前往 [SiliconFlow](https://siliconflow.cn/) 注册账号并获取 API Key
2. 编辑配置文件 `/etc/cloudrein/ai_config.json`：

```json
{
    "api_key": "<your-api-key>",
    "model": "deepseek-ocr",
    "base_url": "https://api.siliconflow.cn/v1/chat/completions"
}
```

3. 或在 Web 界面的"工具中心"页面直接配置

## 管理命令

```bash
# 服务管理
sudo cloudrein start          # 启动服务
sudo cloudrein stop           # 停止服务
sudo cloudrein restart        # 重启服务（加载最新代码）
sudo cloudrein status         # 查看服务状态
sudo cloudrein enable         # 设置开机自启
sudo cloudrein disable        # 取消开机自启

# 日志管理
sudo cloudrein logs           # 查看日志
sudo cloudrein logs -f        # 实时查看日志

# 密码管理
sudo cloudrein passwd         # 修改登录密码
```

## 文件结构

```
/home/cloudrein/              # 项目目录
├── config.yaml               # 主配置文件
├── cloudrein                 # CLI 管理脚本
├── cloudrein-server.py       # 后端入口
├── cloudrein.service         # systemd 服务配置
├── index.html                # 前端页面
├── install.sh                # 安装脚本
├── requirements.txt          # Python 依赖
├── gateway/                  # WebDAV 分流网关（本分支新增）
│   └── server.js             # 零依赖 Node 网关
├── assets/                   # 本地化前端静态资源（本分支新增）
└── server/                   # 后端代码
    ├── __init__.py           # Flask 应用工厂
    ├── main.py               # 服务启动
    ├── config.py             # 配置加载
    ├── auth.py               # 认证模块
    ├── session.py            # 会话管理
    ├── system.py             # 系统监控
    ├── monitor_history.py    # 历史数据存储
    └── routes/               # API 路由
        ├── files.py          # 文件操作
        ├── config.py         # 配置管理
        ├── whitelist.py      # 白名单管理
        └── ai.py             # OCR/AI 功能

/etc/cloudrein/               # 系统数据目录
├── passwd                    # 密码文件（SHA256 哈希）
├── user_config.yaml          # 用户覆盖配置（可选）
├── ai_config.json            # AI/OCR 配置
└── quick_paths.json          # 快捷路径配置
```

## 配置说明

### 配置存储位置

| 配置项 | 路径 | 说明 |
|--------|------|------|
| 主配置 | `/home/cloudrein/config.yaml` | 项目默认配置 |
| 用户配置 | `/etc/cloudrein/user_config.yaml` | 用户自定义配置（覆盖主配置） |
| 密码文件 | `/etc/cloudrein/passwd` | SHA256 哈希存储 |
| AI 配置 | `/etc/cloudrein/ai_config.json` | OCR API 配置 |
| 快捷路径 | `/etc/cloudrein/quick_paths.json` | 导航快捷路径 |

### YAML 配置文件

```yaml
# CloudRein 主配置文件

# 服务器配置
server:
  host: "127.0.0.1"        # 监听地址
  port: 9001               # 监听端口
  session_timeout: 3600    # 会话超时时间（秒）

# 数据存储配置
storage:
  data_dir: "/etc/cloudrein"
  user_config_file: "/etc/cloudrein/user_config.yaml"

# 安全配置
security:
  delete_whitelist:
    - "/tmp"
    - "/var/tmp"
    - "/home"

# 权限配置
permissions:
  folder_permissions:
    "/var/www/html":
      read: true
      write: true
    "/etc":
      read: true
      write: false
  default_permissions:
    read: true
    write: true

# 下载限制
download_limits:
  max_single_file_size: 104857600    # 单文件最大 100MB
  max_total_download_size: 209715200 # 批量下载最大 200MB
  max_files_in_zip: 500              # ZIP 最多 500 个文件
  max_dir_depth: 20                  # 目录最大深度
  max_file_preview_size: 2097152     # 文件预览最大 2MB

# 监控配置
monitor:
  history_minutes: 60    # 历史数据保留时长（1-60分钟）
```

### 下载限额与路径安全

`download_limits` 现在对上传、单文件下载、目录打包和批量下载全部生效：

- 路径先 `normpath` + `realpath`，再按真实目标做权限判断；指向目录外的 symlink 会被跳过。
- 单文件超过 `max_single_file_size` 返回 413；目录/批量超过 `max_total_download_size` 返回 413；超过 `max_files_in_zip` 返回 400。
- 打包前先收集并校验总量，超限请求不会留下半成品 zip。
- 上传超过单文件上限返回 413，已落盘的超限文件会被删除；`max_dir_depth` 用于限制递归打包层级。

### Web 设置面板

登录后点击右上角"设置"按钮，可管理以下配置：

| 标签页 | 功能 |
|--------|------|
| 删除白名单 | 添加/删除允许删除的路径 |
| 快捷路径 | 自定义文件浏览页面的快捷按钮 |
| 系统配置 | 会话超时、默认权限、下载限制等 |
| 密码修改 | 修改登录密码 |

## 开发模式

服务直接运行项目目录中的代码，修改前后端代码后只需重启即可：

```bash
# 修改 index.html 或 cloudrein-server.py 后
sudo cloudrein restart
```

无需复制文件，重启即生效。

## API 接口

### 认证相关
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/login` | POST | 登录认证 |
| `/api/logout` | POST | 退出登录 |
| `/api/auth/check` | GET | 检查登录状态 |

### 文件操作
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/file` | GET | 获取文件/目录内容 |
| `/api/file/save` | POST | 保存文件 |
| `/api/file/create` | POST | 新建文件/目录 |
| `/api/file/rename` | POST | 重命名文件/目录 |
| `/api/file/delete` | POST | 删除文件（需白名单） |
| `/api/file/chmod` | POST | 修改权限 |
| `/api/file/upload` | POST | 上传文件 |
| `/api/file/download` | GET | 单文件下载 |
| `/api/file/download/batch` | POST | 批量下载 |

### 配置管理
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/whitelist` | GET/POST/DELETE/PUT | 白名单管理 |
| `/api/quickpaths` | GET/POST | 快捷路径管理 |
| `/api/userconfig` | GET/POST | 用户配置管理 |
| `/api/userconfig/reset` | POST | 重置用户配置 |
| `/api/userconfig/raw` | GET/POST | 原始配置读写 |
| `/api/changepwd` | POST | 修改密码 |

### 系统监控
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/system` | GET | 系统监控信息 |
| `/api/system/history` | GET | 历史监控数据 |

### AI / OCR
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/ai/config` | GET | 获取AI配置 |
| `/api/ai/models` | GET | 获取可用模型列表 |
| `/api/ai/ocr` | POST | OCR文字识别 |

## 常见问题

### Q: 登录后显示 401 错误？

A: 检查密码文件是否存在并重新设置密码：
```bash
ls -la /etc/cloudrein/passwd
sudo cloudrein passwd
```

### Q: 无法编辑/上传文件？

A: 检查配置文件中的 `folder_permissions` 和 `default_permissions` 设置，确保目标目录有写入权限。

### Q: 删除按钮不显示？

A: 该路径不在删除白名单中，请在"设置"页面添加允许删除的路径。

### Q: 修改代码后不生效？

A: 重启服务即可：
```bash
sudo cloudrein restart
```

### Q: 如何查看日志？

```bash
sudo cloudrein logs
# 或实时查看
sudo cloudrein logs -f
# 或使用 journalctl
sudo journalctl -u cloudrein -f
```

### Q: OCR 识别失败？

A: 检查 API Key 是否配置正确：
```bash
cat /etc/cloudrein/ai_config.json
```

### Q: 服务无法启动？

A: 检查端口是否被占用，以及日志中的错误信息：
```bash
# 检查端口占用
sudo ss -tlnp | grep 9001

# 查看详细日志
sudo journalctl -u cloudrein -n 50
```

### Q: 如何更新到最新版本？

```bash
cd /home/cloudrein
git pull
sudo cloudrein restart
```

## 安全建议

1. **修改默认密码** - 首次安装后立即运行 `sudo cloudrein passwd`
2. **配置删除白名单** - 只添加必要的临时目录或上传目录
3. **限制写入权限** - 在配置文件中限制敏感目录的写入权限
4. **使用 HTTPS** - 配置 SSL 证书加密传输
5. **限制访问 IP** - 在 Nginx 中配置 IP 白名单（可选）
6. **定期备份** - 定期备份 `/etc/cloudrein/passwd` 和配置文件

## License

MIT License
