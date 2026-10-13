# Gmail Web Reader

本项目是一个仅限本机使用的 Flask Gmail IMAP/SMTP 客户端。

## 启动

```text
python app.py
```

浏览器打开 `http://127.0.0.1:5000`。默认只允许 Gmail：

- IMAP：`imap.gmail.com:993` + SSL
- SMTP：`smtp.gmail.com:465` + SSL

登录请使用 Gmail 应用专用密码，不要使用账户主密码。

## 使用其他邮件服务器

启动前设置白名单环境变量。多个主机用逗号分隔；IMAP 的非 SSL 配置仍必须支持 STARTTLS，SMTP 587 也必须使用 STARTTLS。

```powershell
$env:GMAIL_WEB_ALLOWED_IMAP_HOSTS = "imap.example.com"
$env:GMAIL_WEB_ALLOWED_SMTP_HOSTS = "smtp.example.com"
python -B app.py
```

配置只保存服务器参数和筛选项，密码不会写入 `localStorage`。项目对 IMAP 使用 UID、限制请求/邮件大小、拒绝跨站 API 请求，并且删除操作只标记目标 UID，不会执行全邮箱 `EXPUNGE`。

常规收件使用服务器返回的 `UIDNEXT` 查询最新 UID 区间，按需逐段向旧邮件回扫，不再先取回整箱 UID 清单；全局搜索仍由邮件服务器执行完整搜索。

## 安全边界

服务绑定 `127.0.0.1`，不要用端口转发、反向代理或 `--host 0.0.0.0` 将它暴露给局域网/公网。邮件 HTML 使用白名单过滤后在无权限 iframe 中展示，远程图片和活动内容会被阻断。
