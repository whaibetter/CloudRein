# JD-Auth 统一密钥（SSO）

CloudRein 文件库可以接入 JD-Auth 统一登录，属于可选能力；未配置共享密钥或平台不可用时自动回退到原密码登录。

- 浏览器 / API：`session.get_session()` 在没有本地 `sessionid` 时接受有效 `jd_sso`；`require_auth()` / `is_authenticated()` 同样识别，前端 `/api/auth/check` 会自动跳过登录页。
- 域名入口：`sso_hooks.py` 校验 `jd_ticket`，建立本地会话并换发本域 `jd_sso`（30 天），后续不再重复走票据。
- WebDAV 客户端（Finder、rclone 等）继续使用 Basic 认证，不受影响。
- 页面「退出」同时清除 `jd_sso`，避免退出后被立刻重新识别。
- `server/sso.py` 是 JD-Auth 的 Python SDK 副本，只读 `/opt/jd-auth/data/sso.key`，不需要主密钥。

## 部署

把 `deploy/cloudrein-sso.conf` 放到 `/etc/systemd/system/cloudrein.service.d/sso.conf`（按需修改平台地址），然后：

```bash
systemctl daemon-reload && systemctl restart cloudrein
```

## 验证

```bash
# 平台登录后带 jd_sso 访问
curl -H "Cookie: jd_sso=<token>" http://127.0.0.1:12179/api/auth/check
# => {"authenticated":true}

# 未登录仍回退到密码登录；WebDAV 未认证仍是 401
curl -o /dev/null -w '%{http_code}\n' -X PROPFIND http://127.0.0.1:12179/
```
