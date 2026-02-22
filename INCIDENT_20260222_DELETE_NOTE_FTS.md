## 事件处置记录（2026-02-22）

- 事件：登录后删除笔记失败，前端提示“删除笔记失败”。
- 发现时间：2026-02-22 15:02:02（CST, +0800）。
- 影响范围：`DELETE /api/notes/<note_id>` 间歇/持续返回 500，普通查询基本可用。

### 根因

- SQLite FTS5 索引（`notes_fts`）与内容表（`notes`）不一致。
- 删除笔记时触发器 `notes_fts_ad` 执行 FTS 删除指令，报错：
  - `sqlite3.DatabaseError: database disk image is malformed`

### 处置动作

1. 先备份主库  
   - 备份文件：`/root/flash-note/backups/flash_note.db.pre-fts-repair-20260222-151215.bak`
2. 在线重建 FTS 资产  
   - 删除并重建 `notes_fts` 与触发器 `notes_fts_ai/ad/au`
   - 执行 `INSERT INTO notes_fts(notes_fts) VALUES('rebuild')`
   - 执行 `INSERT INTO notes_fts(notes_fts, rank) VALUES('integrity-check', 1)`
3. 代码加固（`backend/app.py`）  
   - 启动阶段增加 FTS 完整性校验，失败自动重建。
   - 删除笔记遇到 `malformed` 时自动触发一次 FTS 修复并重试删除。
4. 重启服务  
   - `flash-note.service` 重启后状态为 `active (running)`。

### 验证结果

- `smoke.sh` 全量通过（登录、鉴权、查询、登出）。
- 实测链路“登录 -> 新建笔记 -> 删除笔记”成功，删除接口返回 `200` 且 `{"success":true}`。
- 日志出现成功审计：
  - `2026-02-22 15:14:10` `event=note_delete ... deleted=True`

### 后续建议

- 保留本次备份至少 7 天。
- 在发布/重启后保留 FTS 自检日志巡检项（关注 `sqlite_fts_integrity_failed`、`sqlite_fts_disabled`）。
