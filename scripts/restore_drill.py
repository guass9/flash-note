#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
import sys
import tarfile
import tempfile


def safe_extract_tar(tar_obj, dst_dir):
    abs_dst = os.path.abspath(dst_dir)
    for member in tar_obj.getmembers():
        member_path = os.path.abspath(os.path.join(dst_dir, member.name))
        if not member_path.startswith(abs_dst + os.sep) and member_path != abs_dst:
            raise RuntimeError(f"unsafe archive entry: {member.name}")
    tar_obj.extractall(dst_dir)


def find_latest_archive(backup_dir):
    prefix = "flash-note-backup-"
    suffix = ".tar.gz"
    candidates = []
    for name in os.listdir(backup_dir):
        if name.startswith(prefix) and name.endswith(suffix):
            full_path = os.path.join(backup_dir, name)
            if os.path.isfile(full_path):
                candidates.append((full_path, os.path.getmtime(full_path)))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[1], reverse=True)
    return candidates[0][0]


def count_sqlite(db_file):
    with sqlite3.connect(db_file, timeout=5.0) as conn:
        categories = int(conn.execute("SELECT COUNT(1) FROM categories").fetchone()[0])
        notes = int(conn.execute("SELECT COUNT(1) FROM notes").fetchone()[0])
    return categories, notes


def parse_json_list(path):
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload if isinstance(payload, list) else []


def parse_users(path):
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        users = payload.get("users", [])
    elif isinstance(payload, list):
        users = payload
    else:
        users = []
    return users if isinstance(users, list) else []


def build_parser():
    default_backup_dir = os.path.expanduser(os.getenv("APP_BACKUP_DIR", "/root/flash-note/backups"))
    parser = argparse.ArgumentParser(description="Validate latest backup archive can be read/restored")
    parser.add_argument("--backup-dir", default=default_backup_dir)
    parser.add_argument("--archive", default="", help="optional explicit archive path")
    return parser


def main():
    args = build_parser().parse_args()
    backup_dir = os.path.expanduser(args.backup_dir)
    archive = os.path.expanduser(args.archive) if args.archive else find_latest_archive(backup_dir)
    if not archive:
        raise RuntimeError("no backup archive found")
    if not os.path.exists(archive):
        raise RuntimeError(f"archive not found: {archive}")

    with tempfile.TemporaryDirectory(prefix="flash-note-drill-") as tmp_dir:
        with tarfile.open(archive, mode="r:gz") as tar:
            safe_extract_tar(tar, tmp_dir)

        root = os.path.join(tmp_dir, "flash-note-backup")
        manifest_file = os.path.join(root, "manifest.json")
        if not os.path.exists(manifest_file):
            raise RuntimeError("missing manifest.json in archive")
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict):
            raise RuntimeError("invalid manifest content")

        data_dir = os.path.join(root, "data")
        sqlite_file = os.path.join(data_dir, "flash_note.db")
        categories_json = os.path.join(data_dir, "categories.json")
        notes_json = os.path.join(data_dir, "notes.json")
        users_json = os.path.join(data_dir, "users.json")

        categories_count = 0
        notes_count = 0
        if os.path.exists(sqlite_file):
            categories_count, notes_count = count_sqlite(sqlite_file)
            storage_mode = "sqlite"
        else:
            storage_mode = "json"
            if os.path.exists(categories_json):
                categories_count = len(parse_json_list(categories_json))
            if os.path.exists(notes_json):
                notes_count = len(parse_json_list(notes_json))

        users_count = len(parse_users(users_json)) if os.path.exists(users_json) else 0

    print(f"drill_archive={archive}")
    print(f"drill_storage_mode={storage_mode}")
    print(f"drill_categories={categories_count}")
    print(f"drill_notes={notes_count}")
    print(f"drill_users={users_count}")
    print("drill_status=ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
