# 瞬念笔记一页纸运维手册（给后续机器人执行）

更新时间：2026-02-21  
适用环境：`/root/flash-note`（systemd + gunicorn + SQLite）

## 1. 基础信息
- 服务名：`flash-note.service`
- 项目根目录：`/root/flash-note`
- 后端目录：`/root/flash-note/backend`
- 数据目录：`/root/flash-note/data`
- 环境文件：`/root/flash-note/.env`
- 公开健康接口：`GET http://127.0.0.1:5000/healthz`
- 内部诊断接口（需登录）：`GET /api/admin/healthz/internal`

## 2. 3分钟健康检查（优先执行）
```bash
systemctl status flash-note.service --no-pager
curl -sS http://127.0.0.1:5000/healthz
/root/flash-note/scripts/smoke.sh
```

通过标准：
- `flash-note.service` 为 `active (running)`
- `/healthz` 返回 `{"status":"ok"}`
- `smoke.sh` 最后输出 `PASS`

## 3. 日常运维命令
```bash
# 服务控制
systemctl restart flash-note.service
systemctl stop flash-note.service
systemctl start flash-note.service
systemctl status nginx --no-pager
systemctl status fail2ban --no-pager

# 日志
journalctl -u flash-note.service -n 200 --no-pager
tail -n 200 /root/flash-note/backend/app.log
tail -n 200 /var/log/nginx/access.log
rg -n "request request_id=|audit event=" /root/flash-note/backend/app.log | tail -n 100

# SQLite 优化（第4条）
python3 /root/flash-note/scripts/sqlite_optimize.py
python3 /root/flash-note/scripts/sqlite_optimize.py --with-analyze
# SQLite 碎片治理（第7条，阈值触发 VACUUM）
python3 /root/flash-note/scripts/sqlite_optimize.py --with-vacuum
# 强制 VACUUM（仅维护窗口使用）
python3 /root/flash-note/scripts/sqlite_optimize.py --force-vacuum

# 健康与内部诊断（第8条）
curl -sS http://127.0.0.1:5000/healthz
curl -ksS https://127.0.0.1/healthz
# 内部诊断需先登录（示例）
COOKIE_JAR=/tmp/flash-note-admin.cookie
curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" -H 'Content-Type: application/json' \
  -X POST --data '{"username":"<username>","password":"<password>"}' \
  http://127.0.0.1:5000/api/auth/login
curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  http://127.0.0.1:5000/api/admin/healthz/internal

# 缓存管理（第9条，需先登录拿 cookie）
curl -sS http://127.0.0.1:5000/api/admin/cache/notes
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:5000/api/admin/cache/notes/clear
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"resetStats":true}' \
  http://127.0.0.1:5000/api/admin/cache/notes/clear

# 缓存主动清扫（第10条）
curl -sS -X POST http://127.0.0.1:5000/api/admin/cache/notes/sweep

# fail2ban 查看
fail2ban-client status
fail2ban-client status nginx-flashnote-login

# Nginx 登录限流（fallback，无 fail2ban 也可用）
nginx -T | grep -n flashnote_login

# Nginx 压缩与静态缓存（第8条）
curl -ksSI https://127.0.0.1/static/vendor/marked.min.js | rg -i 'cache-control|expires|content-type|vary'
curl -ksS -H 'Accept-Encoding: gzip' -D - https://127.0.0.1/login -o /dev/null | rg -i 'content-encoding|vary|content-type'

# 静态资源单一来源同步
python3 /root/flash-note/scripts/sync_static_assets.py --check
python3 /root/flash-note/scripts/sync_static_assets.py

# 发布门禁（第9条）
/root/flash-note/scripts/release_gate.sh
# 仅 CI/离线检查（跳过运行时检查与 smoke）
SKIP_RUNTIME_CHECKS=1 /root/flash-note/scripts/release_gate.sh

# 标准发布（第9条，含发布前快照）
bash /root/flash-note/scripts/release_deploy.sh
# 失败自动回滚模式
bash /root/flash-note/scripts/release_deploy.sh --auto-rollback-on-fail
# 回滚检查单
cat /root/flash-note/RELEASE_ROLLBACK_CHECKLIST.md
```

分页检索（第3条）示例：
```bash
# 最近5条（默认首页）
curl -sS 'http://127.0.0.1:5000/api/notes?limit=5'

# 搜索分页（需先登录拿 cookie，这里仅示例参数）
curl -sS 'http://127.0.0.1:5000/api/notes?search=关键词&limit=20&offset=0'
curl -sS 'http://127.0.0.1:5000/api/notes?search=关键词&limit=20&offset=20'
```

## 4. 用户管理（第10项）
```bash
python3 /root/flash-note/scripts/user_admin.py list
python3 /root/flash-note/scripts/user_admin.py add --username <name> --password '<pass>' --role user
python3 /root/flash-note/scripts/user_admin.py add --username <name> --password '<pass>' --role admin
python3 /root/flash-note/scripts/user_admin.py passwd --username <name> --password '<newpass>'
python3 /root/flash-note/scripts/user_admin.py status --username <name> --status active
python3 /root/flash-note/scripts/user_admin.py status --username <name> --status locked
python3 /root/flash-note/scripts/user_admin.py role --username <name> --role admin
python3 /root/flash-note/scripts/user_admin.py role --username <name> --role user
python3 /root/flash-note/scripts/user_admin.py delete --username <name>
```

引导账号自动同步策略（可选）：
- `APP_AUTH_BOOTSTRAP_SYNC_MODE=sync`：每次启动都按 `.env` 强制同步引导账号（兼容旧行为）
- `APP_AUTH_BOOTSTRAP_SYNC_MODE=create_only`：仅在引导账号不存在时创建（推荐）
- `APP_AUTH_BOOTSTRAP_SYNC_MODE=disabled`：不自动管理引导账号

## 5. 备份与恢复（第12项）
```bash
# 手工备份
python3 /root/flash-note/scripts/backup_snapshot.py

# 恢复演练校验（只读）
python3 /root/flash-note/scripts/restore_drill.py

# 恢复预演（不改数据）
python3 /root/flash-note/scripts/restore_snapshot.py --dry-run

# 实际恢复（会覆盖当前数据；默认自动停/启服务）
# 若恢复失败，脚本会自动回滚到恢复前快照
python3 /root/flash-note/scripts/restore_snapshot.py --yes

# 数据生命周期（第10项）
# 默认只巡检输出（不改数据）
python3 /root/flash-note/scripts/data_lifecycle.py
# 仅归档（不删除）
APP_LIFECYCLE_APPLY=1 APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0 \
  python3 /root/flash-note/scripts/data_lifecycle.py
# 归档+删除（仅维护窗口）
APP_LIFECYCLE_APPLY=1 APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=1 \
  python3 /root/flash-note/scripts/data_lifecycle.py
```

备份产物目录：
- `APP_BACKUP_DIR`（默认 `/root/flash-note/backups`）
- 文件名形如：`flash-note-backup-YYYYmmdd-HHMMSSZ.tar.gz`

## 6. 定时任务（已启用）
```bash
systemctl status flash-note-backup.timer --no-pager
systemctl status flash-note-restore-drill.timer --no-pager
systemctl status flash-note-sqlite-optimize.timer --no-pager
systemctl status flash-note-health-watchdog.timer --no-pager
systemctl status flash-note-sqlite-vacuum.timer --no-pager
systemctl status flash-note-data-lifecycle.timer --no-pager
systemctl list-timers --all --no-pager | grep -E 'flash-note-backup|flash-note-restore-drill|flash-note-sqlite-optimize|flash-note-sqlite-vacuum|flash-note-health-watchdog|flash-note-data-lifecycle'
```

- `flash-note-backup.timer`：每日备份  
- `flash-note-restore-drill.timer`：每月恢复演练
- `flash-note-sqlite-optimize.timer`：每周 SQLite 优化（含可选 `ANALYZE`）
- `flash-note-sqlite-vacuum.timer`：每月 SQLite 碎片治理（阈值触发 VACUUM）
- `flash-note-health-watchdog.timer`：每 2 分钟健康巡检（异常可触发 webhook 告警）
- `flash-note-data-lifecycle.timer`：每月容量巡检与数据生命周期任务（默认报告模式）

## 7. 发布/变更最小流程（给机器人执行）
1. 修改代码或配置。
2. 执行标准发布：`bash /root/flash-note/scripts/release_deploy.sh`
3. 若发布失败且需自动回滚：`bash /root/flash-note/scripts/release_deploy.sh --auto-rollback-on-fail`
4. 若需人工回滚，按：`/root/flash-note/RELEASE_ROLLBACK_CHECKLIST.md`
5. 查看日志确认无新错误。

## 8. 故障优先排查顺序
1. `systemctl status flash-note.service --no-pager`
2. `journalctl -u flash-note.service -n 200 --no-pager`
3. `tail -n 200 /root/flash-note/backend/app.log`
   - 重点看：`request request_id=` 与 `audit event=`
4. `curl -sS http://127.0.0.1:5000/healthz`
5. `/root/flash-note/scripts/smoke.sh`

## 9. 关键脚本与配置索引
- 冒烟回归：`/root/flash-note/scripts/smoke.sh`
- 用户管理：`/root/flash-note/scripts/user_admin.py`
- JSON->SQLite迁移：`/root/flash-note/scripts/migrate_json_to_sqlite.py`
- SQLite->JSON导出：`/root/flash-note/scripts/export_sqlite_to_json.py`
- 备份：`/root/flash-note/scripts/backup_snapshot.py`
- 数据生命周期：`/root/flash-note/scripts/data_lifecycle.py`
- SQLite 优化：`/root/flash-note/scripts/sqlite_optimize.py`
- 静态资源同步：`/root/flash-note/scripts/sync_static_assets.py`
- 发布门禁：`/root/flash-note/scripts/release_gate.sh`
- 标准发布：`/root/flash-note/scripts/release_deploy.sh`
- 恢复：`/root/flash-note/scripts/restore_snapshot.py`
- 恢复演练：`/root/flash-note/scripts/restore_drill.py`
- 发布回滚检查单：`/root/flash-note/RELEASE_ROLLBACK_CHECKLIST.md`
- 生命周期策略：`/root/flash-note/DATA_LIFECYCLE_POLICY.md`
- 部署说明：`/root/flash-note/deploy/DEPLOY_GUNICORN.md`
- 生产改造记录：`/root/flash-note/CHANGELOG_PROD.md`
- CI gate：`/root/flash-note/.github/workflows/ci-gate.yml`
