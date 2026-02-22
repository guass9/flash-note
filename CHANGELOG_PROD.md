# 瞬念笔记生产化改造记录（1-12）

更新时间：2026-02-21
适用版本：当前 `flash-note` 工作目录

## 1. 配置与密钥治理

目标：将敏感配置从代码默认值迁出，并在生产环境强制校验。

已实现：
- 新增 `APP_ENV`（`dev/prod`）模式。
- `APP_ENV=prod` 时，`APP_SECRET_KEY`、`APP_LOGIN_USERNAME`、`APP_LOGIN_PASSWORD` 缺失将拒绝启动。
- Cookie 安全参数改为环境变量可控并做合法性校验。
- 提供 `.env` 模板。

关键文件：
- `backend/app.py`
- `.env.example`

## 2. 运行方式切换到 Gunicorn + systemd

目标：替换 Flask 开发服务器，提升长期运行稳定性。

已实现：
- 新增 `wsgi.py` 入口。
- 新增 `gunicorn` 配置文件（worker、线程、超时、日志路径）。
- 新增 `systemd` 服务文件并启用。

关键文件：
- `backend/wsgi.py`
- `deploy/gunicorn.conf.py`
- `deploy/systemd/flash-note.service`
- `requirements.txt`

## 3. 日志标准化与滚动

目标：统一日志格式、补齐关键行为日志，并防止日志无限增长。

已实现：
- 统一应用日志格式与日志级别（`APP_LOG_LEVEL`）。
- 增加请求日志（方法/路径/状态/耗时/IP）。
- 增加登录成功/失败/退出日志。
- 增加 logrotate 规则（按天轮转，超阈值提前轮转，压缩保留）。

关键文件：
- `backend/app.py`
- `deploy/logrotate/flash-note.conf`
- `deploy/DEPLOY_GUNICORN.md`
- `.env.example`

## 4. JSON 写入安全（原子写 + 文件锁）

目标：降低多 worker 并发写 JSON 时的数据损坏风险。

已实现：
- `write_json_file()` 改为 `lock + tmp file + fsync + os.replace`。
- 初始化数据也统一走安全写路径。
- 并发写测试已通过（文件保持有效 JSON）。

关键文件：
- `backend/app.py`

## 5. CORS 与 Cookie 安全收口

目标：默认最小暴露，只在需要时按白名单放行跨域。

已实现：
- 默认同源策略，未配置白名单时拒绝跨域来源。
- 支持 `APP_CORS_ALLOW_ORIGINS` 白名单。
- 拦截非法来源并返回 `403`。
- `SESSION_COOKIE_SAMESITE` 可配置并带安全约束（`None` 必须 `Secure=1`）。

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`

## 6. 登录防爆破（限速）

目标：降低密码暴力尝试风险。

已实现：
- 对 `/api/auth/login` 增加按 IP 的失败计数与封禁窗口。
- 超限后返回 `429` 与 `retryAfter`。
- 登录成功会清除该 IP 失败计数。
- 限速参数可通过环境变量配置。

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`

说明：
- 当前是进程内限速（每个 worker 独立计数），最小改动方案。
- 若需全局一致限速，建议后续接入 Redis。

## 7. 前端依赖本地化（去 CDN 依赖）

目标：避免外网/CDN 波动影响 Markdown 编辑与预览功能。

已实现：
- 将 `marked`、`DOMPurify` 落地到本地 `vendor` 目录。
- 页面改为仅加载 `/static/vendor/*.min.js`，移除 CDN 引用。

关键文件：
- `frontend/index.html`
- `backend/static/index.html`
- `frontend/vendor/marked.min.js`
- `frontend/vendor/purify.min.js`
- `backend/static/vendor/marked.min.js`
- `backend/static/vendor/purify.min.js`

## 8. 健康检查与最小回归脚本

目标：提供发布后快速自检能力。

已实现：
- 新增 `GET /healthz`（检查服务状态与数据文件可读性）。
- 新增 `scripts/smoke.sh` 一键回归：
  - 健康检查
  - 匿名鉴权状态
  - 未登录拦截
  - 登录
  - 登录后读取分类/笔记
  - 退出
  - 退出后再次拦截

关键文件：
- `backend/app.py`
- `scripts/smoke.sh`
- `deploy/DEPLOY_GUNICORN.md`

## 9. 全局登录限速（Redis 可选后端）

目标：将“每 worker 独立计数”升级为“可选全局统一计数”，且不破坏现有行为。

已实现：
- 登录限速新增后端模式：`memory` / `redis`。
- 默认保持 `memory`（兼容旧行为，最小改动）。
- 设置 `APP_LOGIN_RATE_LIMIT_BACKEND=redis` 后，限速状态写入 Redis，多个 worker/实例共享计数。
- 增加 Redis 连接与键前缀配置，IP 键做哈希脱敏。
- Redis 后端异常时，登录接口返回 `503`（避免无保护放行）。
- Redis 模式启动时执行连通性校验，后端不可用则启动失败（fail-fast）。

关键文件：
- `backend/app.py`
- `.env.example`
- `requirements.txt`
- `deploy/DEPLOY_GUNICORN.md`

## 10. 账号体系升级（密码哈希 + 多用户）

目标：从单账号明文比对升级为可扩展账户模型，并保持现有登录方式兼容。

已实现：
- 新增 `users.json` 账号存储（`/root/flash-note/data/users.json`），支持多用户列表。
- 密码改为 `PBKDF2-SHA256` 哈希存储，不再使用明文比对。
- 增加用户状态字段：`active/disabled/locked`。
- 启动时自动创建/规范化用户文件，并将 `APP_LOGIN_USERNAME/APP_LOGIN_PASSWORD` 同步为引导账号（兼容原有登录）。
- 登录接口切换为用户存储校验，保留原接口响应语义。
- `healthz` 增加用户存储可读性检查。
- 新增用户管理脚本：`scripts/user_admin.py`（`list/add/passwd/status/delete`）。
- 新增引导账号同步模式：`APP_AUTH_BOOTSTRAP_SYNC_MODE=sync/create_only/disabled`。

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`
- `scripts/user_admin.py`

## 11. 存储层从 JSON 升级为 SQLite

目标：减少并发文件写复杂度，提升查询与数据一致性，同时保持前端 API 不变。

已实现：
- 新增存储后端开关：`APP_STORAGE_BACKEND=json/sqlite`，默认 `sqlite`。
- 新增 SQLite 配置：`APP_SQLITE_DB_FILE`、`APP_SQLITE_TIMEOUT_SEC`。
- 分类/笔记接口改为统一存储层，API 协议保持不变。
- 启动时自动建表，并在 SQLite 空库时自动执行 `notes.json/categories.json` 迁移。
- 自动迁移前会做 JSON 快照备份（`data/backup/json-pre-sqlite-*`）。
- 新增手工迁移脚本：`scripts/migrate_json_to_sqlite.py`。
- 新增回滚导出脚本：`scripts/export_sqlite_to_json.py`。
- `healthz` 增加存储后端可用性检查（JSON 或 SQLite）。

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`
- `scripts/migrate_json_to_sqlite.py`
- `scripts/export_sqlite_to_json.py`

## 12. 备份与恢复机制

目标：把“可运行”升级为“可恢复”，并能日常自动执行。

已实现：
- 新增一键备份脚本：`scripts/backup_snapshot.py`
  - 支持 SQLite 一致性备份（sqlite backup API）
  - 同时备份 `notes.json/categories.json/users.json`
  - 备份包内包含脱敏 `.env`（可配置关闭）
  - 自动保留策略清理（按天数 + 按数量）
- 新增恢复脚本：`scripts/restore_snapshot.py`
  - 支持从最新或指定备份包恢复
  - 默认会先停服务并做“恢复前快照”再覆盖恢复
  - 恢复前自动校验 `checksums.sha256`，发现损坏/篡改会拒绝恢复
  - 恢复过程失败时自动回滚到“恢复前快照”
  - 支持 `--dry-run` 预演
- 新增恢复演练脚本：`scripts/restore_drill.py`
  - 每次校验最近备份包可解压、可读、可统计
- 新增 systemd 定时任务：
  - 每日备份：`flash-note-backup.timer`
  - 每月恢复演练：`flash-note-restore-drill.timer`

关键文件：
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`
- `deploy/systemd/flash-note-backup.service`
- `deploy/systemd/flash-note-backup.timer`
- `deploy/systemd/flash-note-restore-drill.service`
- `deploy/systemd/flash-note-restore-drill.timer`
- `scripts/backup_snapshot.py`
- `scripts/restore_snapshot.py`
- `scripts/restore_drill.py`

## 13. SQLite 检索优化（中优先级增量）

目标：减少“近期笔记”查询的数据量与排序开销，优先利用现有索引。

已实现：
- `GET /api/notes` 新增可选参数 `limit`（向后兼容，不传时行为不变）。
- `GET /api/notes` 新增可选参数 `offset`，支持偏移分页。
- SQLite 查询排序从 `rowid` 调整为 `update_time DESC`，与现有索引对齐。
- 首屏“近期笔记”改为服务端限制返回 5 条（`limit=5`），减少无效传输与前端排序。
- 增加 `APP_NOTES_LIST_MAX_LIMIT`（默认 `200`），限制单次查询最大返回量。
- 前端搜索结果改为分页加载（每次 20 条）并提供“加载更多”。
- 新增 SQLite FTS5 全文检索路径（`APP_SQLITE_ENABLE_FTS=1`）。
- FTS5 不可用时自动回退 `LIKE` 检索，保持功能可用。

关键文件：
- `backend/app.py`
- `frontend/index.html`
- `backend/static/index.html`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`

## 14. SQLite 统计与查询计划维护（第4条）

目标：定期收敛 SQLite 统计信息，稳定长期查询计划与检索性能。

已实现：
- 新增维护脚本：`scripts/sqlite_optimize.py`
  - 执行 `PRAGMA optimize`
  - 可选执行 `ANALYZE`（`--with-analyze`）
- 新增环境参数：
  - `APP_SQLITE_OPTIMIZE_WITH_ANALYZE`
  - `APP_SQLITE_OPTIMIZE_BUSY_TIMEOUT_MS`
- 新增 systemd 周期任务：
  - `flash-note-sqlite-optimize.service`
  - `flash-note-sqlite-optimize.timer`（每周执行）

关键文件：
- `scripts/sqlite_optimize.py`
- `deploy/systemd/flash-note-sqlite-optimize.service`
- `deploy/systemd/flash-note-sqlite-optimize.timer`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`
- `OPS_RUNBOOK.md`

## 15. 搜索请求并发控制（第5条）

目标：避免用户连续输入时出现“旧请求覆盖新结果”的前端乱序渲染。

已实现：
- 搜索请求接入 `AbortController`，新查询会取消上一笔记请求。
- 增加请求序号校验，仅渲染最新请求结果。
- 页面改动已同步到运行静态页。

关键文件：
- `frontend/index.html`
- `backend/static/index.html`

## 16. 搜索结果短时缓存（第6条）

目标：减少相同筛选条件下的重复请求，降低后端压力并提升二次访问响应速度。

已实现：
- 前端新增查询缓存（按 `category/search/limit/offset` 作为键）。
- 缓存 TTL 为 15 秒，最多保留 80 条查询结果。
- 新增分类、保存笔记、删除笔记后自动清理缓存，避免陈旧数据。
- 页面改动已同步到运行静态页。

关键文件：
- `frontend/index.html`
- `backend/static/index.html`

## 17. 后端笔记查询缓存（第7条）

目标：在多终端/多用户场景下减少重复 `GET /api/notes` 计算与 I/O。

已实现：
- 后端新增内存查询缓存（键包含 `category/search/limit/offset` 与检索后端状态）。
- 支持 TTL 与容量上限配置（默认 8 秒、256 条）。
- 命中缓存直接返回，未命中才执行 SQLite/JSON 查询。
- 分类新增、笔记新增/修改/删除后自动失效缓存，避免返回旧数据。

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`

## 18. 查询缓存可观测性（第8条）

目标：让运维可直接观察缓存是否生效（命中率、失效次数、当前大小）。

已实现：
- 在 `healthz` 返回中新增 `notesCache` 指标：
  - `hits/misses/hitRate`
  - `stores/evictions/expired`
  - `invalidations/invalidatedEntries`
  - `size/ttlSec/maxEntries/enabled`
- 指标更新与缓存读写共用锁，保证并发统计一致性。

关键文件：
- `backend/app.py`

## 19. 缓存运维控制接口（第9条）

目标：支持运维在不重启服务的情况下查看/清理缓存与重置统计。

已实现：
- 新增运维接口（登录后可用）：
  - `GET /api/admin/cache/notes`：查看当前缓存统计。
  - `POST /api/admin/cache/notes/clear`：清空缓存。
  - `POST /api/admin/cache/notes/clear` + `{"resetStats": true}`：清空缓存并重置统计。
- 管理操作写入应用日志，便于审计和排障追踪。

关键文件：
- `backend/app.py`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 20. 缓存主动清扫（第10条）

目标：避免长时间低访问场景下陈旧缓存项堆积，提供可控清扫能力。

已实现：
- 新增后台清扫策略：`APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC`（默认 60 秒）。
- 查询缓存在读/写路径按间隔自动清扫过期项。
- 新增强制清扫接口：`POST /api/admin/cache/notes/sweep`。
- `healthz.notesCache` 增加清扫指标：
  - `sweeps`、`sweptEntries`、`sweepIntervalSec`

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`
- `OPS_RUNBOOK.md`

## 21. 日志可靠性增强（第5项）

目标：提升请求级追踪能力与关键操作审计可观测性，便于排障与安全审计。

已实现：
- 新增请求追踪 ID（`X-Request-ID`）：
  - 可透传上游请求头（合法值）
  - 不合法或缺失时自动生成
  - 响应统一回写 `X-Request-ID`
- 请求日志增强：
  - 增加 `request_id`、`actor`、真实客户端 `ip`
  - 日志格式：`request request_id=... method=... path=... status=... duration_ms=... ip=... actor=...`
- 新增关键审计日志（`audit event=...`）：
  - 登录成功/失败/限速/封禁、退出登录
  - 分类新增（成功/冲突/无效）
  - 笔记新增/更新/删除（含 `note_id/category_id/tags_count`）
  - 缓存管理接口 clear/sweep
- 删除笔记存储函数返回 `deleted` 布尔值（不改变接口协议），用于审计精确记录。
- 运维手册补充日志检索命令，支持快速按 `request_id` 追踪。

关键文件：
- `backend/app.py`
- `OPS_RUNBOOK.md`

## 22. 引导账号 disabled 模式条件放宽（第7项）

目标：当 `APP_AUTH_BOOTSTRAP_SYNC_MODE=disabled` 时，不再强制要求 `APP_LOGIN_USERNAME/APP_LOGIN_PASSWORD`，降低纯用户库模式部署门槛。

已实现：
- 调整配置加载顺序：先解析并校验 `APP_AUTH_BOOTSTRAP_SYNC_MODE`。
- 新增条件开关：仅在 `sync/create_only` 模式下，生产环境强制 `APP_LOGIN_USERNAME/APP_LOGIN_PASSWORD`。
- `disabled` 模式下，生产环境允许上述两个环境变量为空。
- 保持兼容：`sync` 模式仍严格要求凭据，行为不变。

验证结果：
- `disabled` + 空凭据：可正常启动（prod）。
- `sync` + 空凭据：仍会启动失败并报缺失凭据。
- 主服务重启后 `/healthz` 与 `smoke.sh` 全部通过。

关键文件：
- `backend/app.py`
- `.env.example`

## 23. 健康检查分级（第8项）

目标：将公开健康探针与内部诊断信息分离，降低公开接口信息暴露。

已实现：
- `GET /healthz` 调整为公开最小健康探针：
  - 成功：`{"status":"ok"}`
  - 失败：`{"status":"degraded"}` + `503`
- 新增内部诊断接口（需登录）：
  - `GET /api/admin/healthz/internal`
  - 返回 `env`、`uptimeSec`、`storageBackend`、`authStore`、`notesCache` 等诊断信息
- 维持存储与用户库可用性检查逻辑不变，仅调整输出分级。
- 运维手册已更新，补充内部诊断的登录 cookie 示例。

验证结果：
- 匿名访问 `/healthz`：`200` 且仅最小状态字段。
- 匿名访问 `/api/admin/healthz/internal`：`401`。
- 登录后访问 `/api/admin/healthz/internal`：`200` 且返回完整诊断数据。
- 主服务 `/healthz` 与 `smoke.sh` 回归通过。

关键文件：
- `backend/app.py`
- `OPS_RUNBOOK.md`

## 24. 前后端静态文件单一来源（第9项）

目标：消除 `frontend/` 与 `backend/static/` 双写漂移风险，建立可执行同步与校验流程。

已实现：
- 新增静态同步脚本：`scripts/sync_static_assets.py`
  - 单一来源：`frontend/`
  - 目标目录：`backend/static/`
  - 支持两种模式：
    - `--check`：只校验漂移，若不一致返回非 0
    - 默认：执行同步覆盖
- 同步范围（固定映射）：
  - `frontend/index.html` -> `backend/static/index.html`
  - `frontend/login.html` -> `backend/static/login.html`
  - `frontend/vendor/marked.min.js` -> `backend/static/vendor/marked.min.js`
  - `frontend/vendor/purify.min.js` -> `backend/static/vendor/purify.min.js`
- 部署文档与运维手册已加入同步/校验命令，发布最小流程已包含静态同步检查。

验证结果：
- 执行 `python3 /root/flash-note/scripts/sync_static_assets.py --check`：通过
- 执行 `python3 /root/flash-note/scripts/sync_static_assets.py`：`changed_count=0`（当前已一致）

关键文件：
- `scripts/sync_static_assets.py`
- `deploy/DEPLOY_GUNICORN.md`
- `OPS_RUNBOOK.md`

## 25. 自动化测试与发布门禁（第10项）

目标：从“人工 smoke 为主”升级到“可重复执行的集成测试 + 发布门禁 + CI gate”。

已实现：
- 新增 API 集成测试：
  - `tests/test_api_integration.py`
  - 覆盖：公开 `/healthz` 最小返回、内部健康接口鉴权、登录后内部诊断、`X-Request-ID` 回显
- 新增发布门禁脚本：
  - `scripts/release_gate.sh`
  - 默认流程：
    - 静态资源漂移检查（`sync_static_assets.py --check`）
    - Python 语法检查（`py_compile`）
    - API 集成测试（`unittest`）
    - 运行时健康检查（`/healthz`）
    - 冒烟回归（`smoke.sh`）
  - 支持 `SKIP_RUNTIME_CHECKS=1`，便于 CI 或无运行时环境执行
- 新增 CI gate 工作流：
  - `.github/workflows/ci-gate.yml`
  - 触发：`push` / `pull_request`
  - 执行：依赖安装 + 静态漂移检查 + 语法检查 + API 集成测试
- 运维手册与部署文档已补充 gate 使用方式。

验证结果：
- `python3 -m unittest discover -s /root/flash-note/tests -p 'test_*.py' -v`：通过
- `/root/flash-note/scripts/release_gate.sh`：通过（包含 smoke）

关键文件：
- `tests/test_api_integration.py`
- `scripts/release_gate.sh`
- `.github/workflows/ci-gate.yml`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 26. HTTPS 下启用安全 Cookie（P0 第2项）

目标：在已启用 HTTPS 反向代理后，正式开启安全会话 Cookie，降低会话在明文链路泄露风险。

已实现：
- 生产环境配置更新：
  - `.env` 中 `SESSION_COOKIE_SECURE=1`
- 回归脚本适配 HTTPS：
  - `scripts/smoke.sh` 默认 `BASE_URL=https://127.0.0.1`
  - 增加 `SMOKE_CURL_INSECURE`（默认 `1`）以兼容自签证书
- 发布门禁兼容验证：
  - `scripts/release_gate.sh` 已在新 smoke 默认模式下通过

验证结果：
- 登录响应头包含 `set-cookie: ...; Secure; HttpOnly; ...`
- `https://127.0.0.1/healthz` 返回 `{"status":"ok"}`
- `/root/flash-note/scripts/smoke.sh`：通过
- `/root/flash-note/scripts/release_gate.sh`：通过

关键文件：
- `.env`
- `scripts/smoke.sh`

## 27. 管理接口角色权限收口（P0 第1项）

目标：将 `/api/admin/*` 从“登录即可调用”收口为“仅管理员可调用”。

已实现：
- 用户模型新增 `role` 字段（`admin/user`），并做兼容迁移：
  - 引导账号默认/同步为 `admin`
  - 其他历史账号默认归一为 `user`
- 登录会话新增 `role`，`/api/auth/status` 返回 `role` 字段。
- 路由保护增强：
  - `/api/admin/*`：未登录返回 `401`
  - 非管理员返回 `403`（`需要管理员权限`）
  - 管理员正常访问 `200`
- 审计日志新增 `admin_access_denied` 事件。
- 用户管理脚本增强：
  - `add` 支持 `--role`
  - 新增 `role` 子命令用于切换角色
  - `list` 输出 role 列

验证结果：
- `users.json` 迁移后角色正确：
  - `Guass=admin`
  - `909020=user`
- `/api/admin/cache/notes` 权限验证：
  - 匿名：`401`
  - `909020`：`403`
  - `Guass`：`200`
- `unittest`、`smoke.sh`、`release_gate.sh` 全部通过。

关键文件：
- `backend/app.py`
- `scripts/user_admin.py`
- `tests/test_api_integration.py`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 28. 全局登录限流后端切换为 Redis（P0 最后一项）

目标：将登录失败计数从进程内内存切换到共享后端，确保多 worker/多实例下限流全局一致。

已实现：
- 主机安装并启用 Redis 服务（开机自启）。
- 生产配置已切换：
  - `.env` 增加 `APP_LOGIN_RATE_LIMIT_BACKEND=redis`
  - `.env` 增加 `APP_REDIS_URL=redis://127.0.0.1:6379/0`
  - `.env` 增加 `APP_REDIS_SOCKET_TIMEOUT_SEC=1.0`
- 重启 `flash-note.service` 后，应用启动日志已显示 `backend=redis`。
- 通过错误登录验证 Redis 键写入（`shunnian:login_rl:*`），并清理测试键避免影响日常登录。

验证结果：
- `systemctl is-active redis`：`active`
- `redis-cli ping`：`PONG`
- `curl -ks https://127.0.0.1/healthz`：`{"status":"ok"}`
- `/root/flash-note/scripts/smoke.sh`：通过

关键文件：
- `.env`
- `backend/app.py`（已支持 redis 后端，本次为生产启用）

## 29. SQLite 体积与碎片治理（VACUUM 阈值化 + 月度任务）

目标：在不影响日常读写的前提下，周期治理 SQLite 碎片，控制库文件体积增长。

已实现：
- `scripts/sqlite_optimize.py` 增加阈值触发 VACUUM：
  - `--with-vacuum`：仅当碎片阈值满足时执行
  - `--force-vacuum`：维护窗口可强制执行
- 新增阈值配置：
  - `APP_SQLITE_VACUUM_MIN_DB_SIZE_MB`
  - `APP_SQLITE_VACUUM_MIN_RECLAIM_MB`
  - `APP_SQLITE_VACUUM_FRAGMENTATION_RATIO_THRESHOLD`
- 新增 systemd 月度任务：
  - `flash-note-sqlite-vacuum.service`
  - `flash-note-sqlite-vacuum.timer`

验证结果：
- `python3 /root/flash-note/scripts/sqlite_optimize.py --with-vacuum`：执行成功并输出阈值判断
- `systemctl is-enabled flash-note-sqlite-vacuum.timer`：`enabled`
- `systemctl is-active flash-note-sqlite-vacuum.timer`：`active`
- `curl -ks https://127.0.0.1/healthz`：`{"status":"ok"}`

关键文件：
- `scripts/sqlite_optimize.py`
- `deploy/systemd/flash-note-sqlite-vacuum.service`
- `deploy/systemd/flash-note-sqlite-vacuum.timer`
- `.env.example`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 30. 静态资源与接口响应优化（缓存头 + gzip 压缩）

目标：降低静态资源重复传输开销，并减少文本类响应体积，提升页面加载与接口传输效率。

已实现：
- Nginx 启用 gzip 压缩（常见文本/JSON/JS/CSS 类型）。
- 新增 `location /static/` 专用代理策略并下发缓存头：
  - `Cache-Control: public, max-age=3600, must-revalidate`
  - `expires 1h`
- 配置已同步到生产并热重载生效（`nginx -t` + `systemctl reload nginx`）。

验证结果：
- `https://127.0.0.1/static/vendor/marked.min.js` 响应含 `Cache-Control` 与 `Expires`
- `https://127.0.0.1/login` 在 `Accept-Encoding: gzip` 下返回 `content-encoding: gzip`
- `https://127.0.0.1/healthz` 正常
- `/root/flash-note/scripts/smoke.sh` 全部通过

关键文件：
- `deploy/nginx/flash-note.conf`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 31. 发布与回滚标准化（发布脚本 + 回滚检查单）

目标：将发布过程收口为可重复执行的标准步骤，并提供明确回滚操作，降低发布失败处置成本。

已实现：
- 新增标准发布脚本：`scripts/release_deploy.sh`
  - 默认流程：`sync_static_assets` -> `backup_snapshot` -> `systemctl restart flash-note.service` -> `release_gate.sh`
  - 支持失败自动回滚：`--auto-rollback-on-fail`
  - 支持控制参数：`--skip-backup`、`--skip-restart`、`--dry-run`
- 新增回滚检查单：`RELEASE_ROLLBACK_CHECKLIST.md`
  - 明确发布前检查、发布后验收、回滚触发条件、手工回滚步骤
- 运维文档与部署文档已统一到新流程。

验证结果：
- `bash -n /root/flash-note/scripts/release_deploy.sh`：通过
- `bash /root/flash-note/scripts/release_deploy.sh --dry-run`：通过
- `bash /root/flash-note/scripts/release_deploy.sh --skip-restart`：通过
- `curl -ks https://127.0.0.1/healthz`：`{"status":"ok"}`

关键文件：
- `scripts/release_deploy.sh`
- `RELEASE_ROLLBACK_CHECKLIST.md`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 32. 容量与数据生命周期策略（归档与清理）

目标：为在线数据建立“观察 -> 归档 -> 清理”的可控路径，降低容量增长风险。

已实现：
- 新增生命周期脚本：`scripts/data_lifecycle.py`
  - 默认观察模式（不改数据）
  - 支持归档不删除：`APP_LIFECYCLE_APPLY=1` + `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0`
  - 支持归档后删除：`APP_LIFECYCLE_APPLY=1` + `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=1`
- 新增归档目录保留策略（天数 + 份数）。
- 新增容量阈值观测（`data`/`backups` 目录告警位）。
- 新增 systemd 月度任务：
  - `flash-note-data-lifecycle.service`
  - `flash-note-data-lifecycle.timer`
- 新增策略文档：`DATA_LIFECYCLE_POLICY.md`

验证结果：
- `python3 /root/flash-note/scripts/data_lifecycle.py`：执行成功
- `systemctl is-enabled flash-note-data-lifecycle.timer`：`enabled`
- `systemctl is-active flash-note-data-lifecycle.timer`：`active`
- `curl -ks https://127.0.0.1/healthz`：`{"status":"ok"}`
- `/root/flash-note/scripts/smoke.sh`：通过
- 生产策略已切为归档不删除：
  - `APP_LIFECYCLE_APPLY=1`
  - `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0`
  - `APP_LIFECYCLE_ARCHIVE_DAYS=30`
  - `APP_LIFECYCLE_ARCHIVE_BATCH_SIZE=500`
- 真实小批量归档演练通过：
  - `archived_count=1`
  - `deleted_count=0`
  - 归档文件：`/root/flash-note/data/archive/notes-archive-20260221-160849Z.jsonl.gz`
  - 演练笔记已清理，线上功能回归通过

关键文件：
- `scripts/data_lifecycle.py`
- `deploy/systemd/flash-note-data-lifecycle.service`
- `deploy/systemd/flash-note-data-lifecycle.timer`
- `.env.example`
- `DATA_LIFECYCLE_POLICY.md`
- `OPS_RUNBOOK.md`
- `deploy/DEPLOY_GUNICORN.md`

## 日常使用建议

- 服务状态：`systemctl status flash-note.service --no-pager`
- 健康检查：`curl http://127.0.0.1:5000/healthz`
- 冒烟回归：`/root/flash-note/scripts/smoke.sh`
- 日志查看：`tail -n 100 /root/flash-note/backend/app.log`

## 下一阶段候选项

- 待你确认下一轮目标后继续扩展。
