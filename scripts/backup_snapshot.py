#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone


def utc_now_text():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def env_int(name, default):
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except Exception:
        return default


def env_bool(name, default):
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_if_exists(src, dst):
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        shutil.copy2(src, dst)
        return True
    return False


def redact_env_file(src_path, dst_path):
    if not os.path.exists(src_path):
        return False
    redacted_keys = ("SECRET", "PASSWORD", "TOKEN", "KEY")
    lines = []
    with open(src_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in line:
                lines.append(line)
                continue
            key, value = line.split("=", 1)
            if any(token in key.upper() for token in redacted_keys):
                lines.append(f"{key}=***REDACTED***")
            else:
                lines.append(f"{key}={value}")
    os.makedirs(os.path.dirname(dst_path) or ".", exist_ok=True)
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return True


def sqlite_backup(src_db, dst_db):
    with sqlite3.connect(src_db, timeout=5.0) as src_conn:
        src_conn.execute("PRAGMA busy_timeout=5000")
        with sqlite3.connect(dst_db, timeout=5.0) as dst_conn:
            src_conn.backup(dst_conn)
            dst_conn.commit()


def collect_checksums(root_dir):
    rows = []
    for cur, _, files in os.walk(root_dir):
        for name in sorted(files):
            full_path = os.path.join(cur, name)
            rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")
            if rel_path == "checksums.sha256":
                continue
            rows.append((sha256_file(full_path), rel_path))
    return rows


def prune_archives(backup_dir, keep_days, keep_count):
    prefix = "flash-note-backup-"
    suffix = ".tar.gz"
    entries = []
    for name in os.listdir(backup_dir):
        if not (name.startswith(prefix) and name.endswith(suffix)):
            continue
        full_path = os.path.join(backup_dir, name)
        if not os.path.isfile(full_path):
            continue
        entries.append((full_path, os.path.getmtime(full_path)))
    entries.sort(key=lambda item: item[1], reverse=True)

    now = time.time()
    keep_set = set()
    if keep_count > 0:
        keep_set.update(path for path, _ in entries[:keep_count])
    if keep_days > 0:
        min_mtime = now - keep_days * 86400
        keep_set.update(path for path, mtime in entries if mtime >= min_mtime)

    removed = []
    for path, _ in entries:
        if path in keep_set:
            continue
        os.remove(path)
        removed.append(path)
    return removed


def build_parser():
    default_project_root = os.path.expanduser(os.getenv("APP_PROJECT_ROOT", "/root/flash-note"))
    default_data_dir = os.path.expanduser(os.getenv("APP_DATA_DIR", "~/flash-note/data"))
    default_backup_dir = os.path.expanduser(os.getenv("APP_BACKUP_DIR", "/root/flash-note/backups"))
    parser = argparse.ArgumentParser(description="Create flash-note backup snapshot archive")
    parser.add_argument("--project-root", default=default_project_root)
    parser.add_argument("--data-dir", default=default_data_dir)
    parser.add_argument("--backup-dir", default=default_backup_dir)
    parser.add_argument("--env-file", default="")
    parser.add_argument("--keep-days", type=int, default=env_int("APP_BACKUP_RETAIN_DAYS", 30))
    parser.add_argument("--keep-count", type=int, default=env_int("APP_BACKUP_RETAIN_COUNT", 30))
    parser.add_argument("--include-env", action="store_true", default=env_bool("APP_BACKUP_INCLUDE_ENV", True))
    parser.add_argument("--no-include-env", action="store_false", dest="include_env")
    return parser


def main():
    args = build_parser().parse_args()
    project_root = os.path.expanduser(args.project_root)
    data_dir = os.path.expanduser(args.data_dir)
    backup_dir = os.path.expanduser(args.backup_dir)
    env_file = os.path.expanduser(args.env_file) if args.env_file else os.path.join(project_root, ".env")

    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    ts_text = utc_now_text()
    archive_name = f"flash-note-backup-{ts_text}.tar.gz"
    archive_path = os.path.join(backup_dir, archive_name)

    with tempfile.TemporaryDirectory(prefix="flash-note-backup-", dir=backup_dir) as tmp_dir:
        snapshot_root = os.path.join(tmp_dir, "snapshot")
        data_out = os.path.join(snapshot_root, "data")
        conf_out = os.path.join(snapshot_root, "config")
        os.makedirs(data_out, exist_ok=True)
        os.makedirs(conf_out, exist_ok=True)

        storage_files = []
        db_path = os.path.join(data_dir, "flash_note.db")
        if os.path.exists(db_path):
            db_out = os.path.join(data_out, "flash_note.db")
            sqlite_backup(db_path, db_out)
            storage_files.append("data/flash_note.db")

        for filename in ("notes.json", "categories.json", "users.json"):
            src = os.path.join(data_dir, filename)
            dst = os.path.join(data_out, filename)
            if copy_if_exists(src, dst):
                storage_files.append(f"data/{filename}")

        env_redacted = ""
        if args.include_env:
            dst = os.path.join(conf_out, "env.redacted")
            if redact_env_file(env_file, dst):
                env_redacted = "config/env.redacted"

        manifest = {
            "createdAt": iso_now(),
            "host": socket.gethostname(),
            "projectRoot": project_root,
            "dataDir": data_dir,
            "storageFiles": storage_files,
            "envRedactedFile": env_redacted,
            "backupVersion": 1,
        }
        with open(os.path.join(snapshot_root, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)

        checksums = collect_checksums(snapshot_root)
        with open(os.path.join(snapshot_root, "checksums.sha256"), "w", encoding="utf-8") as f:
            for digest, rel in checksums:
                f.write(f"{digest}  {rel}\n")

        with tarfile.open(archive_path, mode="w:gz") as tar:
            tar.add(snapshot_root, arcname="flash-note-backup")

    removed = prune_archives(backup_dir, args.keep_days, args.keep_count)
    print(f"backup_archive={archive_path}")
    print(f"retention_removed={len(removed)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
