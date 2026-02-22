#!/usr/bin/env python3
import argparse
import gzip
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_now_text():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def env_int(name, default):
    raw = str(os.getenv(name, str(default))).strip()
    try:
        return int(raw)
    except Exception:
        return default


def env_float(name, default):
    raw = str(os.getenv(name, str(default))).strip()
    try:
        return float(raw)
    except Exception:
        return default


def env_bool(name, default):
    raw = str(os.getenv(name, "1" if default else "0")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def sqlite_connect(db_file, timeout_sec):
    conn = sqlite3.connect(db_file, timeout=max(1.0, float(timeout_sec)))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def read_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if isinstance(payload, dict):
            return payload
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def write_json_file(path, payload):
    parent = os.path.dirname(path) or "."
    ensure_dir(parent)
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(temp_path, path)


def safe_tags(raw):
    try:
        parsed = json.loads(raw or "[]")
        if isinstance(parsed, list):
            return [str(v) for v in parsed if str(v).strip()]
    except Exception:
        pass
    return []


def row_to_note_payload(row):
    return {
        "id": str(row["id"]),
        "title": str(row["title"] or ""),
        "content": str(row["content"] or ""),
        "richContent": str(row["rich_content"] or ""),
        "categoryId": str(row["category_id"] or ""),
        "tags": safe_tags(row["tags_json"]),
        "createTime": float(row["create_time"]),
        "updateTime": float(row["update_time"]),
    }


def dir_size_bytes(path):
    total = 0
    if not os.path.isdir(path):
        return 0
    for cur, _, files in os.walk(path):
        for name in files:
            file_path = os.path.join(cur, name)
            try:
                total += os.path.getsize(file_path)
            except OSError:
                continue
    return total


def list_archive_files(archive_dir):
    files = []
    if not os.path.isdir(archive_dir):
        return files
    for name in os.listdir(archive_dir):
        if not name.startswith("notes-archive-"):
            continue
        if not name.endswith(".jsonl.gz"):
            continue
        full_path = os.path.join(archive_dir, name)
        if not os.path.isfile(full_path):
            continue
        try:
            mtime = os.path.getmtime(full_path)
        except OSError:
            continue
        files.append((full_path, mtime))
    files.sort(key=lambda item: item[1], reverse=True)
    return files


def prune_archives(archive_dir, keep_days, keep_count):
    files = list_archive_files(archive_dir)
    now = time.time()
    keep_set = set()
    if keep_count > 0:
        keep_set.update(path for path, _ in files[:keep_count])
    if keep_days > 0:
        min_mtime = now - int(keep_days) * 86400
        keep_set.update(path for path, mtime in files if mtime >= min_mtime)

    removed = []
    for path, _ in files:
        if path in keep_set:
            continue
        os.remove(path)
        removed.append(path)
    return removed


def build_parser():
    parser = argparse.ArgumentParser(description="Flash-note data lifecycle maintenance")
    parser.add_argument(
        "--storage-backend",
        default=str(os.getenv("APP_STORAGE_BACKEND", "sqlite")).strip().lower(),
    )
    parser.add_argument(
        "--db-file",
        default=os.path.expanduser(str(os.getenv("APP_SQLITE_DB_FILE", "/root/flash-note/data/flash_note.db"))),
    )
    parser.add_argument(
        "--sqlite-timeout-sec",
        type=float,
        default=env_float("APP_SQLITE_TIMEOUT_SEC", 5.0),
    )
    parser.add_argument(
        "--data-dir",
        default=os.path.expanduser(str(os.getenv("APP_DATA_DIR", "/root/flash-note/data"))),
    )
    parser.add_argument(
        "--backup-dir",
        default=os.path.expanduser(str(os.getenv("APP_BACKUP_DIR", "/root/flash-note/backups"))),
    )
    parser.add_argument(
        "--archive-dir",
        default=os.path.expanduser(str(os.getenv("APP_LIFECYCLE_ARCHIVE_DIR", "/root/flash-note/data/archive"))),
    )
    parser.add_argument(
        "--archive-days",
        type=int,
        default=env_int("APP_LIFECYCLE_ARCHIVE_DAYS", 365),
    )
    parser.add_argument(
        "--archive-batch-size",
        type=int,
        default=env_int("APP_LIFECYCLE_ARCHIVE_BATCH_SIZE", 500),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        default=env_bool("APP_LIFECYCLE_APPLY", False),
    )
    parser.add_argument(
        "--delete-after-archive",
        action="store_true",
        default=env_bool("APP_LIFECYCLE_DELETE_AFTER_ARCHIVE", False),
    )
    parser.add_argument(
        "--archive-retain-days",
        type=int,
        default=env_int("APP_LIFECYCLE_ARCHIVE_RETAIN_DAYS", 365),
    )
    parser.add_argument(
        "--archive-retain-count",
        type=int,
        default=env_int("APP_LIFECYCLE_ARCHIVE_RETAIN_COUNT", 24),
    )
    parser.add_argument(
        "--data-warn-mb",
        type=int,
        default=env_int("APP_LIFECYCLE_DATA_WARN_MB", 2048),
    )
    parser.add_argument(
        "--backup-warn-mb",
        type=int,
        default=env_int("APP_LIFECYCLE_BACKUP_WARN_MB", 4096),
    )
    return parser


def main():
    args = build_parser().parse_args()
    storage_backend = str(args.storage_backend).strip().lower()
    if storage_backend != "sqlite":
        print(f"time={iso_now()}")
        print(f"storage_backend={storage_backend}")
        print("lifecycle_skipped=1")
        print("reason=storage_backend_not_sqlite")
        return 0

    db_file = os.path.expanduser(str(args.db_file))
    data_dir = os.path.expanduser(str(args.data_dir))
    backup_dir = os.path.expanduser(str(args.backup_dir))
    archive_dir = os.path.expanduser(str(args.archive_dir))
    ensure_dir(archive_dir)

    if not os.path.exists(db_file):
        print(f"time={iso_now()}")
        print(f"storage_backend={storage_backend}")
        print("lifecycle_skipped=1")
        print(f"reason=db_not_found:{db_file}")
        return 0

    now_ts = time.time()
    archive_days = max(1, int(args.archive_days))
    cutoff_ts = now_ts - archive_days * 86400
    batch_size = max(1, int(args.archive_batch_size))
    apply_mode = bool(args.apply)
    delete_after_archive = bool(args.delete_after_archive)

    data_size = dir_size_bytes(data_dir)
    backup_size = dir_size_bytes(backup_dir)
    archive_size_before = dir_size_bytes(archive_dir)
    db_size_before = int(os.path.getsize(db_file))
    data_warn_bytes = max(1, int(args.data_warn_mb)) * 1024 * 1024
    backup_warn_bytes = max(1, int(args.backup_warn_mb)) * 1024 * 1024
    state_file = os.path.join(archive_dir, ".lifecycle_state.json")
    state_payload = read_json_file(state_file)
    archive_watermark = float(state_payload.get("lastArchiveUpdateTime", 0.0) or 0.0)

    archived_count = 0
    deleted_count = 0
    archive_file = ""
    archive_removed_files = 0
    notes_total = 0
    notes_eligible = 0
    oldest_eligible_update_time = 0.0

    with sqlite_connect(db_file, args.sqlite_timeout_sec) as conn:
        notes_total = int(conn.execute("SELECT COUNT(1) FROM notes").fetchone()[0] or 0)
        if apply_mode and not delete_after_archive and archive_watermark > 0:
            eligible_rows = conn.execute(
                """
                SELECT id, title, content, rich_content, category_id, tags_json, create_time, update_time
                FROM notes
                WHERE update_time <= ? AND update_time > ?
                ORDER BY update_time ASC
                LIMIT ?
                """,
                (float(cutoff_ts), float(archive_watermark), int(batch_size)),
            ).fetchall()
        else:
            eligible_rows = conn.execute(
                """
                SELECT id, title, content, rich_content, category_id, tags_json, create_time, update_time
                FROM notes
                WHERE update_time <= ?
                ORDER BY update_time ASC
                LIMIT ?
                """,
                (float(cutoff_ts), int(batch_size)),
            ).fetchall()
        notes_eligible = len(eligible_rows)
        if eligible_rows:
            oldest_eligible_update_time = float(eligible_rows[0]["update_time"])

        if apply_mode and notes_eligible > 0:
            archive_file = os.path.join(archive_dir, f"notes-archive-{utc_now_text()}.jsonl.gz")
            temp_file = f"{archive_file}.tmp"
            with gzip.open(temp_file, "wt", encoding="utf-8") as f:
                for row in eligible_rows:
                    payload = row_to_note_payload(row)
                    f.write(json.dumps(payload, ensure_ascii=False))
                    f.write("\n")
            os.replace(temp_file, archive_file)
            archived_count = notes_eligible
            max_archived_update_time = max(float(row["update_time"]) for row in eligible_rows)

            if delete_after_archive:
                ids = [str(row["id"]) for row in eligible_rows]
                placeholders = ",".join("?" for _ in ids)
                cursor = conn.execute(
                    f"DELETE FROM notes WHERE id IN ({placeholders})",
                    ids,
                )
                deleted_count = int(cursor.rowcount or 0)
                conn.commit()
            else:
                state_payload["lastArchiveUpdateTime"] = float(max_archived_update_time)
                state_payload["updatedAt"] = iso_now()
                write_json_file(state_file, state_payload)

    if apply_mode:
        removed = prune_archives(
            archive_dir=archive_dir,
            keep_days=max(0, int(args.archive_retain_days)),
            keep_count=max(0, int(args.archive_retain_count)),
        )
        archive_removed_files = len(removed)

    archive_size_after = dir_size_bytes(archive_dir)
    db_size_after = int(os.path.getsize(db_file))

    print(f"time={iso_now()}")
    print(f"storage_backend={storage_backend}")
    print("lifecycle_skipped=0")
    print(f"apply_mode={1 if apply_mode else 0}")
    print(f"delete_after_archive={1 if delete_after_archive else 0}")
    print(f"archive_days={archive_days}")
    print(f"archive_batch_size={batch_size}")
    print(f"archive_watermark={archive_watermark:.6f}")
    print(f"cutoff_ts={int(cutoff_ts)}")
    print(f"notes_total={notes_total}")
    print(f"notes_eligible={notes_eligible}")
    print(f"oldest_eligible_update_time={oldest_eligible_update_time:.6f}")
    print(f"archived_count={archived_count}")
    print(f"deleted_count={deleted_count}")
    print(f"archive_file={archive_file}")
    print(f"archive_removed_files={archive_removed_files}")
    print(f"db_size_before_bytes={db_size_before}")
    print(f"db_size_after_bytes={db_size_after}")
    print(f"data_dir_size_bytes={data_size}")
    print(f"backup_dir_size_bytes={backup_size}")
    print(f"archive_dir_size_before_bytes={archive_size_before}")
    print(f"archive_dir_size_after_bytes={archive_size_after}")
    print(f"data_warn_threshold_bytes={data_warn_bytes}")
    print(f"backup_warn_threshold_bytes={backup_warn_bytes}")
    print(f"data_warn={1 if data_size >= data_warn_bytes else 0}")
    print(f"backup_warn={1 if backup_size >= backup_warn_bytes else 0}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
