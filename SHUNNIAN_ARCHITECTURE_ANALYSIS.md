# 瞬念笔记整体架构分析

更新时间：2026-02-21  
分析基线目录：`/root/flash-note`  
运行状态快照：`flash-note.service=active/enabled`，`/healthz -> status=ok, env=prod`

## 1. 软件定位与边界

瞬念笔记是一个单体部署的本地化笔记系统，定位为：
- 登录后使用的私有笔记应用
- 支持分类、标签、Markdown 编辑与预览
- 支持基础运维能力（健康检查、备份恢复、定时维护）

系统边界：
- 前端：静态页面（登录页 + 主页）
- 后端：Flask API + 会话鉴权 + 存储访问
- 数据：SQLite 为主、JSON 兼容
- 运维：systemd + gunicorn + 脚本化备份恢复

## 2. 软件架构（逻辑分层）

### 2.1 表现层（UI）
- 主页面：`frontend/index.html`（已同步到 `backend/static/index.html`）
- 登录页：`backend/static/login.html`
- 技术：原生 HTML/CSS/JS，无前端框架
- 编辑能力：Markdown 源码/预览双模式，模板插入，标签输入

### 2.2 应用层（API 与业务）
- 单体 Flask 应用：`backend/app.py`
- 路由集中在一个服务进程内：
  - 鉴权：`/api/auth/*`
  - 分类：`/api/categories`
  - 笔记：`/api/notes`
  - 运维：`/healthz`、`/api/admin/cache/notes*`
- 业务规则集中在后端函数（校验、鉴权拦截、缓存、存储读写）

### 2.3 数据层（持久化与缓存）
- 主存储：SQLite（`/root/flash-note/data/flash_note.db`）
- 兼容存储：`notes.json`、`categories.json`、`users.json`
- 全文检索：SQLite FTS5（`notes_fts` 虚表 + 触发器同步）
- 查询缓存：
  - 前端短时缓存（浏览器内存）
  - 后端内存缓存（进程内，TTL + 容量 + 主动清扫）

### 2.4 运维层（部署与维护）
- 进程管理：systemd 服务 `flash-note.service`
- HTTP 运行：gunicorn（gthread worker）
- 日志：应用日志文件 + journald
- 定时任务：
  - 每日备份
  - 每月恢复演练
  - 每周 SQLite optimize

## 3. 技术架构（实现栈）

核心技术：
- Python + Flask（API 与会话）
- Gunicorn（WSGI 服务）
- SQLite（主数据存储）
- Redis（可选，仅用于全局登录限速后端）
- 原生前端 + 本地 vendor 包（`marked`/`DOMPurify`）

依赖文件：
- `requirements.txt`：`Flask`、`gunicorn`、`redis`

运行入口：
- WSGI：`backend/wsgi.py`
- Gunicorn 配置：`deploy/gunicorn.conf.py`
- systemd：`deploy/systemd/flash-note.service`

## 4. 业务功能分析

### 4.1 用户与登录
- 登录页用户名/密码认证
- 会话 Cookie 鉴权，未登录访问 API 返回 401
- 支持登录状态查询与退出

### 4.2 笔记管理
- 创建/编辑/删除笔记
- 字段：标题、内容（含 Markdown 渲染）、分类、标签、时间戳
- 列表查询支持：
  - 分类过滤
  - 搜索
  - 分页参数（`limit` + `offset`）

### 4.3 分类管理
- 分类列表读取
- 新增分类（重名拦截）

### 4.4 搜索与性能体验
- 前端搜索输入防抖（250ms）
- 请求并发控制（AbortController + 序号防乱序）
- 搜索“加载更多”分页
- FTS5 检索优先，异常自动回退 LIKE

## 5. 安全架构分析

已实现安全能力：
- 生产模式强制关键环境变量（`APP_ENV=prod` 下必填）
- 会话安全参数可控（`SameSite` / `Secure`）
- CORS 白名单策略（默认同源）
- 登录防爆破限速（memory / redis 可选）
- 用户密码 PBKDF2 哈希存储（`users.json`）
- 引导账号同步策略（`sync/create_only/disabled`）

当前特征：
- 当前运行环境为 `prod`
- 当前配置为本地 HTTP 场景（`SESSION_COOKIE_SECURE=0`）

## 6. 数据与目录结构分析

### 6.1 关键目录
- `backend/`：后端应用代码与静态资源
- `frontend/`：前端源页面与 vendor 资源
- `data/`：数据库与 JSON 数据文件
- `scripts/`：运维脚本（备份、恢复、迁移、回归、用户管理）
- `deploy/`：gunicorn、systemd、logrotate 配置
- `backups/`：备份包目录

### 6.2 数据文件
- 主数据库：`data/flash_note.db`
- 兼容文件：`data/notes.json`、`data/categories.json`、`data/users.json`
- SQLite 运行文件：`flash_note.db-wal`、`flash_note.db-shm`

## 7. API 架构与接口清单

核心接口：
- 鉴权：
  - `GET /api/auth/status`
  - `POST /api/auth/login`
  - `POST /api/auth/logout`
- 分类：
  - `GET /api/categories`
  - `POST /api/categories`
- 笔记：
  - `GET /api/notes`
  - `POST /api/notes`
  - `DELETE /api/notes/<note_id>`
- 运维：
  - `GET /healthz`
  - `GET /api/admin/cache/notes`
  - `POST /api/admin/cache/notes/clear`
  - `POST /api/admin/cache/notes/sweep`

## 8. 日志与可观测性

日志位置：
- 应用日志：`/root/flash-note/backend/app.log`
- systemd/journald：`journalctl -u flash-note.service`

日志轮转：
- 配置：`deploy/logrotate/flash-note.conf`
- 策略：按天 + 大小阈值，压缩，保留 14 份

健康检查：
- `GET /healthz` 返回
  - `status/env/uptimeSec`
  - `notesCache` 统计（命中率、容量、清扫指标等）

## 9. 运维自动化架构

定时任务：
- `flash-note-backup.timer`：每日备份
- `flash-note-restore-drill.timer`：每月恢复演练
- `flash-note-sqlite-optimize.timer`：每周数据库优化

关键脚本：
- 回归：`scripts/smoke.sh`
- 用户管理：`scripts/user_admin.py`
- 备份：`scripts/backup_snapshot.py`
- 恢复：`scripts/restore_snapshot.py`
- 演练：`scripts/restore_drill.py`
- 优化：`scripts/sqlite_optimize.py`

## 10. 当前架构优势与潜在风险

优势：
- 部署结构简单，单机可运维
- 数据与运维脚本齐全，具备恢复能力
- 安全基线与可观测性较完整
- 已有多层性能优化（FTS、分页、缓存、防抖、并发控制）

潜在风险：
- 仍是单体单库架构，横向扩展能力有限
- 后端查询缓存为进程内缓存，多 worker 下不共享
- 认证与会话仍以单服务实例为中心，跨实例状态一致性需额外设计
- 当前 HTTP 部署下 Cookie `Secure` 未开启（若上公网应先启 HTTPS）

## 11. 结论

当前瞬念笔记已经从“可用原型”升级为“可持续运行的小型生产系统”：
- 功能完整（登录、分类、笔记、搜索）
- 技术链路闭环（部署、日志、备份、恢复、优化、健康检查）
- 架构上适合单机/小规模团队的稳定运行与低维护成本场景。
