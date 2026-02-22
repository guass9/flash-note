# 瞬念笔记发布与回滚检查单（第9项）

更新时间：2026-02-21  
适用目录：`/root/flash-note`

## 一、发布前检查（必须）

1. 服务当前健康：
   - `systemctl status flash-note.service --no-pager`
   - `curl -ksS https://127.0.0.1/healthz`
2. 依赖服务健康：
   - `systemctl status nginx --no-pager`
   - `systemctl status redis --no-pager`
3. 运行发布脚本（推荐）：
   - `bash /root/flash-note/scripts/release_deploy.sh`

## 二、发布脚本行为（标准流程）

`scripts/release_deploy.sh` 默认执行：
1. 同步静态资源（`sync_static_assets.py`）
2. 生成发布前快照（`backup_snapshot.py`）
3. 重启 `flash-note.service`
4. 执行发布门禁（`release_gate.sh`，含测试 + health + smoke）

常用参数：
- `--skip-backup`：跳过发布前快照
- `--skip-restart`：跳过服务重启
- `--auto-rollback-on-fail`：发布门禁失败时自动回滚快照
- `--dry-run`：只打印计划，不执行

## 三、发布后验收（必须）

1. `curl -ksS https://127.0.0.1/healthz`
2. `bash /root/flash-note/scripts/smoke.sh`
3. `journalctl -u flash-note.service -n 100 --no-pager`

## 四、回滚触发条件

满足任一项立即回滚：
1. 发布后 `healthz` 非 `status=ok`
2. `smoke.sh` 失败
3. 核心接口（登录/分类/笔记）出现明显回归

## 五、手工回滚步骤（推荐）

1. 找到最近发布前快照（发布脚本会输出 `backup_archive=...`）  
2. 执行回滚：
   - `python3 /root/flash-note/scripts/restore_snapshot.py --archive <backup_archive> --yes`
3. 回滚后验证：
   - `curl -ksS https://127.0.0.1/healthz`
   - `bash /root/flash-note/scripts/smoke.sh`
   - `systemctl status flash-note.service --no-pager`

## 六、自动回滚方式（可选）

发布时使用：
- `bash /root/flash-note/scripts/release_deploy.sh --auto-rollback-on-fail`

说明：
- 自动回滚依赖“发布前快照”成功生成。
- 自动回滚完成后仍需人工复核日志与关键页面功能。
