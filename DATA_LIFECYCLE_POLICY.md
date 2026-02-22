# 瞬念笔记容量与数据生命周期策略（第10项）

更新时间：2026-02-21  
适用目录：`/root/flash-note`

## 目标

在不破坏现有功能的前提下，建立“可观察、可归档、可清理”的生命周期策略。

## 策略分级

1. 观察模式（默认，推荐）
   - `APP_LIFECYCLE_APPLY=0`
   - 仅输出容量与候选归档统计，不改动数据。
2. 归档模式（不删除）
   - `APP_LIFECYCLE_APPLY=1`
   - `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0`
   - 把老笔记写入归档文件，保留在线数据（按水位推进，避免重复归档同一批记录）。
3. 归档+清理模式（维护窗口）
   - `APP_LIFECYCLE_APPLY=1`
   - `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=1`
   - 老笔记归档后从在线库删除，降低在线库体积。

## 关键参数（.env）

- `APP_LIFECYCLE_ARCHIVE_DAYS`：归档年龄阈值（天）
- `APP_LIFECYCLE_ARCHIVE_BATCH_SIZE`：单次处理上限
- `APP_LIFECYCLE_ARCHIVE_DIR`：归档文件目录
- `APP_LIFECYCLE_ARCHIVE_RETAIN_DAYS`：归档文件保留天数
- `APP_LIFECYCLE_ARCHIVE_RETAIN_COUNT`：归档文件最小保留份数
- `APP_LIFECYCLE_DATA_WARN_MB`：数据目录告警阈值
- `APP_LIFECYCLE_BACKUP_WARN_MB`：备份目录告警阈值

## 执行命令

```bash
# 观察模式（默认）
python3 /root/flash-note/scripts/data_lifecycle.py

# 归档模式
APP_LIFECYCLE_APPLY=1 APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0 \
  python3 /root/flash-note/scripts/data_lifecycle.py

# 归档+清理模式（维护窗口）
APP_LIFECYCLE_APPLY=1 APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=1 \
  python3 /root/flash-note/scripts/data_lifecycle.py
```

## 定时任务

- `flash-note-data-lifecycle.timer`：每月执行一次生命周期任务。
- 默认建议保持观察模式，待确认归档文件可恢复后再启用删除模式。
