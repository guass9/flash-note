# 瞬念笔记 下一轮10项待做（最小改动版）

更新时间：2026-02-21  
目标：在不破坏现有功能的前提下，继续提高生产可用性与安全性。

## 待做清单

1. 服务最小权限运行（systemd 从 root 切到专用用户）【已完成】
2. systemd 进程沙箱加固（ProtectSystem/NoNewPrivileges 等）【已完成】
3. 反向代理与 TLS 收口（Nginx + HTTPS）【已完成】
4. 登录与接口防护增强（可选 fail2ban + 基础安全头）【已完成】
5. 日志可靠性增强（请求ID、关键操作审计字段）【已完成】
6. 监控与告警基线（healthz 巡检 + 异常告警脚本）【已完成】
7. SQLite 体积与碎片治理（VACUUM 维护窗口与阈值）【已完成】
8. 静态资源与接口响应优化（缓存头/压缩）【已完成】
9. 发布与回滚标准化（发布脚本 + 回滚检查单）【已完成】
10. 容量与数据生命周期策略（归档与清理策略）【已完成】

## 执行顺序

按 1 -> 10 顺序逐项实施；每项完成后执行：
- `systemctl status flash-note.service --no-pager`
- `curl -sS http://127.0.0.1:5000/healthz`
- `/root/flash-note/scripts/smoke.sh`

## 第1项实施结果

- 服务账号：`flashnote`（系统账号，禁登录）
- 运行方式：`flash-note.service` 已从 `User=root` 切换为 `User=flashnote`
- 权限策略：通过 ACL 提供最小可用访问（代码只读、`data/` 可写、`/root` 仅穿越）
- 验证结果：
  - `systemctl status flash-note.service --no-pager`：`active (running)`
  - `curl -sS http://127.0.0.1:5000/healthz`：`status=ok`
  - `LOGIN_USERNAME='Guass' LOGIN_PASSWORD='909020@aZ' /root/flash-note/scripts/smoke.sh`：全部通过

## 第2项实施结果

- 已加固的 systemd 关键项：
  - `NoNewPrivileges=true`
  - `PrivateTmp=true`
  - `PrivateDevices=true`
  - `ProtectSystem=strict`
  - `ReadWritePaths=/root/flash-note/data /root/flash-note/backend/app.log`
  - `CapabilityBoundingSet=`（清空）
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
  - 以及 `ProtectKernel*`、`ProtectControlGroups`、`RestrictNamespaces`、`UMask=0077` 等
- 验证结果：
  - `systemctl status flash-note.service --no-pager`：`active (running)`
  - `curl -sS http://127.0.0.1:5000/healthz`：`status=ok`
  - `LOGIN_USERNAME='Guass' LOGIN_PASSWORD='909020@aZ' /root/flash-note/scripts/smoke.sh`：全部通过
  - `systemd-analyze security flash-note.service`：评分由 `9.2 UNSAFE` 降至 `3.2 OK`

## 第3项实施结果

- 已安装并启用 `nginx` 服务（`systemctl enable --now nginx`）。
- 新增 Nginx 配置源文件：`/root/flash-note/deploy/nginx/flash-note.conf`。
- 生效配置：`/etc/nginx/conf.d/flash-note.conf`
  - `80` 端口强制跳转到 `https`
  - `443` 端口启用 TLS，反向代理到 `http://127.0.0.1:5000`
- 已签发本机自签证书：
  - `/etc/nginx/ssl/flash-note.crt`
  - `/etc/nginx/ssl/flash-note.key`
- Gunicorn 已收口到本地环回地址：
  - `.env` 增加 `GUNICORN_BIND=127.0.0.1:5000`
  - 外部不再直接访问 Gunicorn 5000
- 验证结果：
  - `ss -ltnp`：`127.0.0.1:5000`（Gunicorn）+ `0.0.0.0:80/443`（Nginx）
  - `curl -I http://127.0.0.1/healthz`：`301` 跳转到 `https`
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`
  - `LOGIN_USERNAME='Guass' LOGIN_PASSWORD='909020@aZ' /root/flash-note/scripts/smoke.sh`：全部通过

## 第4项实施结果

- 已启用 Nginx 基础安全头（HTTPS 响应）：
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - `X-XSS-Protection: 1; mode=block`
- 已新增登录接口限流（Nginx 层）：
  - 限流区：`flashnote_login`
  - 登录路径：`/api/auth/login`
  - 超限状态码：`429`
- 已提供 fail2ban 配置模板（可选）：
  - `deploy/fail2ban/filter.d/nginx-flashnote-login.conf`
  - `deploy/fail2ban/jail.d/flash-note.local`
- 当前主机仓库无 `fail2ban` 包（`dnf` 无匹配），因此采用 Nginx 限流作为落地替代方案。
- 验证结果：
  - `curl -ksSI https://127.0.0.1/login`：安全头返回正确
  - 连续 25 次错误登录：`401 x 9`，`429 x 16`（限流生效）
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`
  - `LOGIN_USERNAME='Guass' LOGIN_PASSWORD='909020@aZ' /root/flash-note/scripts/smoke.sh`：全部通过

## 第5项实施结果

- 后端新增请求追踪 ID：
  - 支持读取请求头 `X-Request-ID`（合法值透传，不合法自动生成）
  - 所有响应都会回写 `X-Request-ID`
- 请求访问日志增强：
  - 统一日志字段新增 `request_id`、`actor`、真实客户端 `ip`
  - 格式示例：`request request_id=... method=... path=... status=... duration_ms=... ip=... actor=...`
- 关键操作审计日志增强（`audit event=...`）：
  - 登录成功/失败/限速/封禁、退出登录
  - 分类新增（成功/冲突/无效）
  - 笔记新增/更新/删除（含 `note_id/category_id/tags_count` 等字段）
  - 缓存管理接口（clear/sweep）
- 删除笔记存储层增强：
  - `storage_delete_note` 返回 `deleted` 布尔值（不改变接口返回协议），用于审计准确性
- 运行手册已补充日志排查命令：
  - `rg -n "request request_id=|audit event=" /root/flash-note/backend/app.log | tail -n 100`
- 验证结果：
  - `curl -ksSI -H 'X-Request-ID: test-req-abc123' https://127.0.0.1/login` 响应含同值 `X-Request-ID`
  - `app.log` 已出现 `request request_id=...` 与 `audit event=...` 记录
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`
  - `LOGIN_USERNAME='Guass' LOGIN_PASSWORD='909020@aZ' /root/flash-note/scripts/smoke.sh`：全部通过

## 第6项实施结果

- 健康巡检任务已正式安装并启用：
  - `/etc/systemd/system/flash-note-health-watchdog.service`
  - `/etc/systemd/system/flash-note-health-watchdog.timer`
- 调度策略：
  - 开机 2 分钟后首次执行
  - 每 2 分钟执行一次（`OnUnitActiveSec=2min`）
- 巡检脚本：`/root/flash-note/scripts/health_watchdog.py`
  - 检查 `flash-note.service`、`nginx.service` 状态
  - 检查 `https://127.0.0.1/healthz` 返回 `status=ok`
  - 支持 webhook 告警与恢复通知（由 `.env` 控制）
- 验证结果：
  - `systemctl status flash-note-health-watchdog.timer --no-pager`：`active (waiting)`
  - `systemctl start flash-note-health-watchdog.service`：执行成功（`status=0/SUCCESS`）
  - `journalctl -u flash-note-health-watchdog.service -n 30 --no-pager`：出现 `[OK] flash-note health ok`

## 第7项实施结果

- `sqlite_optimize.py` 新增 VACUUM 治理能力（阈值触发）：
  - `--with-vacuum`：仅在阈值满足时执行
  - `--force-vacuum`：维护窗口可强制执行
- 阈值参数（支持 `.env`）：
  - `APP_SQLITE_VACUUM_MIN_DB_SIZE_MB`（默认 `128`）
  - `APP_SQLITE_VACUUM_MIN_RECLAIM_MB`（默认 `16`）
  - `APP_SQLITE_VACUUM_FRAGMENTATION_RATIO_THRESHOLD`（默认 `0.20`）
- 新增月度碎片治理定时任务：
  - `/etc/systemd/system/flash-note-sqlite-vacuum.service`
  - `/etc/systemd/system/flash-note-sqlite-vacuum.timer`
  - 调度：每月 1 日 `04:40`（带随机延迟）
- 验证结果：
  - `python3 /root/flash-note/scripts/sqlite_optimize.py --with-vacuum`：执行成功并输出阈值判断结果
  - `systemctl status flash-note-sqlite-vacuum.timer --no-pager`：`active (waiting)`
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`

## 第8项实施结果

- Nginx 响应压缩已启用（HTTPS server 块）：
  - `gzip on`、`gzip_vary on`、`gzip_proxied any`
  - 覆盖 `application/json`、`application/javascript`、`text/css` 等常见类型
- 新增静态资源路径优化：
  - `location /static/` 单独代理
  - `Cache-Control: public, max-age=3600, must-revalidate`
  - `expires 1h`
- 配置同步与生效：
  - 源文件：`/root/flash-note/deploy/nginx/flash-note.conf`
  - 已发布到：`/etc/nginx/conf.d/flash-note.conf`
  - `nginx -t` 通过，`systemctl reload nginx` 成功
- 验证结果：
  - `curl -ksSI https://127.0.0.1/static/vendor/marked.min.js` 返回 `Cache-Control` 与 `Expires`
  - `curl -ksS -H 'Accept-Encoding: gzip' -D - https://127.0.0.1/login` 返回 `content-encoding: gzip`
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`
  - `/root/flash-note/scripts/smoke.sh`：全部通过

## 第9项实施结果

- 新增标准发布脚本：`/root/flash-note/scripts/release_deploy.sh`
  - 标准流程：静态资源同步 -> 发布前快照 -> 服务重启 -> 发布门禁
  - 可选参数：
    - `--auto-rollback-on-fail`（门禁失败自动回滚）
    - `--skip-backup`
    - `--skip-restart`
    - `--dry-run`
- 新增回滚检查单：`/root/flash-note/RELEASE_ROLLBACK_CHECKLIST.md`
  - 包含发布前检查、发布后验收、回滚触发条件与手工回滚步骤
- 运维与部署文档已收口到标准流程：
  - `OPS_RUNBOOK.md` 已增加标准发布命令与检查单入口
  - `deploy/DEPLOY_GUNICORN.md` 已增加 release/rollback 章节
- 验证结果：
  - `bash -n /root/flash-note/scripts/release_deploy.sh`：通过
  - `bash /root/flash-note/scripts/release_deploy.sh --dry-run`：通过
  - `bash /root/flash-note/scripts/release_deploy.sh --skip-restart`：通过
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`

## 第10项实施结果

- 新增生命周期脚本：`/root/flash-note/scripts/data_lifecycle.py`
  - 默认“观察模式”（只输出统计，不改数据）
  - 支持“归档模式”（归档不删除）
  - 支持“归档+清理模式”（归档后删除，建议维护窗口执行）
- 新增月度定时任务：
  - `/etc/systemd/system/flash-note-data-lifecycle.service`
  - `/etc/systemd/system/flash-note-data-lifecycle.timer`
- 新增生命周期策略文档：
  - `/root/flash-note/DATA_LIFECYCLE_POLICY.md`
- 新增配置项（`.env.example`）：
  - `APP_LIFECYCLE_APPLY`
  - `APP_LIFECYCLE_ARCHIVE_DAYS`
  - `APP_LIFECYCLE_ARCHIVE_BATCH_SIZE`
  - `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE`
  - `APP_LIFECYCLE_ARCHIVE_DIR`
  - `APP_LIFECYCLE_ARCHIVE_RETAIN_DAYS`
  - `APP_LIFECYCLE_ARCHIVE_RETAIN_COUNT`
  - `APP_LIFECYCLE_DATA_WARN_MB`
  - `APP_LIFECYCLE_BACKUP_WARN_MB`
- 验证结果：
  - `python3 /root/flash-note/scripts/data_lifecycle.py`：执行成功（观察模式）
  - `systemctl status flash-note-data-lifecycle.timer --no-pager`：`active (waiting)`
  - `curl -ks https://127.0.0.1/healthz`：`status=ok`
  - `/root/flash-note/scripts/smoke.sh`：通过
  - 已切换生产归档策略：`APP_LIFECYCLE_APPLY=1`、`APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0`、`APP_LIFECYCLE_ARCHIVE_DAYS=30`、`APP_LIFECYCLE_ARCHIVE_BATCH_SIZE=500`
  - 已完成一次真实小批量归档演练（临时旧笔记）：
    - `archived_count=1`
    - `deleted_count=0`
    - 归档文件：`/root/flash-note/data/archive/notes-archive-20260221-160849Z.jsonl.gz`
    - 演练笔记已清理（不影响正式数据）
