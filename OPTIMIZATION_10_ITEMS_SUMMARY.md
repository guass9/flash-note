# 瞬念笔记优化项（第1-10项）实施总结

更新时间：2026-02-21  
适用目录：`/root/flash-note`

## 总览

本轮共完成 10 项优化，均已落地并通过基础回归（`smoke.sh`）与健康检查（`/healthz`）。

---

## 1. SQLite 检索优化（服务端排序 + limit）

目标：降低“近期笔记”查询开销。  
已实现：
- `GET /api/notes` 支持 `limit` 参数（向后兼容）。
- SQLite 查询排序改为 `ORDER BY update_time DESC`，与索引对齐。
- 首页近期笔记改为服务端 `limit=5`。
- 新增上限配置 `APP_NOTES_LIST_MAX_LIMIT`（默认 200）。

关键文件：
- `backend/app.py`
- `frontend/index.html`
- `backend/static/index.html`
- `.env.example`

---

## 2. 搜索输入防抖

目标：减少输入过程中高频请求。  
已实现：
- 搜索框输入由直接请求改为 `250ms` 防抖后触发。

关键文件：
- `frontend/index.html`
- `backend/static/index.html`

---

## 3. 搜索分页与加载更多

目标：避免一次返回过多搜索结果。  
已实现：
- 后端支持 `offset` 参数（与 `limit` 配合分页）。
- 前端搜索默认分页加载（20条/页），支持“加载更多”。

关键文件：
- `backend/app.py`
- `frontend/index.html`
- `backend/static/index.html`

---

## 4. SQLite 定期优化（PRAGMA optimize / ANALYZE）

目标：长期稳定查询计划与统计信息。  
已实现：
- 新增脚本：`scripts/sqlite_optimize.py`。
- 新增 systemd 任务：
  - `flash-note-sqlite-optimize.service`
  - `flash-note-sqlite-optimize.timer`
- 已在主机安装并启用定时任务。

关键文件：
- `scripts/sqlite_optimize.py`
- `deploy/systemd/flash-note-sqlite-optimize.service`
- `deploy/systemd/flash-note-sqlite-optimize.timer`

---

## 5. 搜索请求并发控制

目标：防止旧请求覆盖新结果（乱序渲染）。  
已实现：
- 前端接入 `AbortController`：新请求会取消旧请求。
- 增加请求序号校验，仅渲染最新响应。

关键文件：
- `frontend/index.html`
- `backend/static/index.html`

---

## 6. 前端查询短时缓存

目标：减少短时间内重复条件查询。  
已实现：
- 前端按 `category/search/limit/offset` 做缓存键。
- TTL 15秒、最多80条。
- 分类新增/笔记增删改后自动清理缓存。

关键文件：
- `frontend/index.html`
- `backend/static/index.html`

---

## 7. 后端查询短时缓存

目标：在多终端访问时减少重复数据库查询。  
已实现：
- 后端内存缓存（键包含筛选条件 + 检索后端状态）。
- 配置项：
  - `APP_NOTES_QUERY_CACHE_TTL_SEC`（默认8秒）
  - `APP_NOTES_QUERY_CACHE_MAX_ENTRIES`（默认256）
- 分类/笔记写操作自动失效缓存。

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`

---

## 8. 缓存可观测性

目标：可实时判断缓存是否生效。  
已实现：
- `healthz` 输出新增 `notesCache` 统计字段：
  - `hits/misses/hitRate`
  - `stores/evictions/expired`
  - `invalidations/invalidatedEntries`
  - `size/ttlSec/maxEntries/enabled`

关键文件：
- `backend/app.py`

---

## 9. 缓存运维管理接口

目标：无需重启即可在线管理缓存。  
已实现（登录后可用）：
- `GET /api/admin/cache/notes`：查看缓存统计。
- `POST /api/admin/cache/notes/clear`：清空缓存。
- `POST /api/admin/cache/notes/clear` + `{"resetStats": true}`：清空并重置统计。

关键文件：
- `backend/app.py`
- `OPS_RUNBOOK.md`

---

## 10. 缓存主动清扫

目标：避免低访问下陈旧缓存长期堆积。  
已实现：
- 新增清扫间隔配置：`APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC`（默认60秒）。
- 读/写路径按间隔自动清扫过期缓存。
- 新增强制清扫接口：`POST /api/admin/cache/notes/sweep`。
- `healthz.notesCache` 增加清扫指标：
  - `sweeps`
  - `sweptEntries`
  - `sweepIntervalSec`

关键文件：
- `backend/app.py`
- `.env.example`
- `deploy/DEPLOY_GUNICORN.md`
- `OPS_RUNBOOK.md`

---

## 当前状态

- 第1-10项：已全部完成（10/10）。
- 主服务：正常运行（`/healthz` 返回 `status=ok`）。
- 回归：`/root/flash-note/scripts/smoke.sh` 已通过。
