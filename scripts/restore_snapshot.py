#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone


def utc_now_text():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def safe_extract_tar(tar_obj, dst_dir):
    abs_dst = os.path.abspath(dst_dir)
    for member in tar_obj.getmembers():
        member_path = os.path.abspath(os.path.join(dst_dir, member.name))
        if not member_path.startswith(abs_dst + os.sep) and member_path != abs_dst:
            raise RuntimeError(f"unsafe archive entry: {member.name}")
    tar_obj.extractall(dst_dir)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_snapshot_checksums(extracted_root):
    backup_root = os.path.join(extracted_root, "flash-note-backup")
    checksums_path = os.path.join(backup_root, "checksums.sha256")
    if not os.path.exists(checksums_path):
        raise RuntimeError("invalid backup archive: missing checksums.sha256")

    verified = 0
    abs_backup_root = os.path.abspath(backup_root)
    with open(checksums_path, "r", encoding="utf-8") as f:
        for idx, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue

            if "  " in line:
                expected, rel_path = line.split("  ", 1)
            else:
                parts = line.split()
                if len(parts) != 2:
                    raise RuntimeError(f"invalid checksum line {idx}")
                expected, rel_path = parts

            expected = expected.strip().lower()
            rel_path = rel_path.strip().replace("\\", "/")
            if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
                raise RuntimeError(f"invalid checksum digest at line {idx}")

            target = os.path.abspath(os.path.join(backup_root, rel_path))
            if not target.startswith(abs_backup_root + os.sep):
                raise RuntimeError(f"invalid checksum path at line {idx}: {rel_path}")
            if not os.path.isfile(target):
                raise RuntimeError(f"checksum target missing at line {idx}: {rel_path}")

            actual = sha256_file(target)
            if actual != expected:
                raise RuntimeError(f"checksum mismatch at line {idx}: {rel_path}")
            verified += 1

    if verified <= 0:
        raise RuntimeError("invalid backup archive: no checksum entries")
    return verified


def run_systemctl(args):
    subprocess.run(["systemctl"] + args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def is_service_active(service_name):
    proc = subprocess.run(
        ["systemctl", "is-active", service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "active"


def find_latest_archive(backup_dir):
    prefix = "flash-note-backup-"
    suffix = ".tar.gz"
    candidates = []
    for name in os.listdir(backup_dir):
        if not (name.startswith(prefix) and name.endswith(suffix)):
            continue
        full_path = os.path.join(backup_dir, name)
        if os.path.isfile(full_path):
            candidates.append((full_path, os.path.getmtime(full_path)))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[1], reverse=True)
    return candidates[0][0]


def copy_if_exists(src, dst):
    if not os.path.exists(src):
        return False
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    shutil.copy2(src, dst)
    return True


def backup_current_state(data_dir):
    backup_dir = os.path.join(data_dir, "backup", f"pre-restore-{utc_now_text()}")
    os.makedirs(backup_dir, exist_ok=True)
    copied = 0
    for filename in (
        "flash_note.db",
        "flash_note.db-wal",
        "flash_note.db-shm",
        "notes.json",
        "categories.json",
        "users.json",
    ):
        src = os.path.join(data_dir, filename)
        dst = os.path.join(backup_dir, filename)
        if copy_if_exists(src, dst):
            copied += 1
    return backup_dir, copied


def apply_restore(snapshot_root, data_dir):
    data_in = os.path.join(snapshot_root, "flash-note-backup", "data")
    if not os.path.isdir(data_in):
        raise RuntimeError("invalid backup archive: missing flash-note-backup/data")

    os.makedirs(data_dir, exist_ok=True)
    for filename in ("flash_note.db-wal", "flash_note.db-shm"):
        target = os.path.join(data_dir, filename)
        if os.path.exists(target):
            os.remove(target)

    restored = 0
    restored_files = []
    for filename in os.listdir(data_in):
        src = os.path.join(data_in, filename)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(data_dir, filename)
        shutil.copy2(src, dst)
        restored_files.append(filename)
        restored += 1
    return restored, sorted(restored_files)


def rollback_from_backup(backup_dir_before, data_dir):
    if not os.path.isdir(backup_dir_before):
        raise RuntimeError(f"rollback source missing: {backup_dir_before}")

    os.makedirs(data_dir, exist_ok=True)
    restored = 0
    restored_files = []
    for filename in os.listdir(backup_dir_before):
        src = os.path.join(backup_dir_before, filename)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(data_dir, filename)
        shutil.copy2(src, dst)
        restored += 1
        restored_files.append(filename)
    return restored, sorted(restored_files)


def validate_restored_data(data_dir, restored_files):
    restored_set = set(restored_files)
    db_path = os.path.join(data_dir, "flash_note.db")

    if "flash_note.db" in restored_set:
        if not os.path.exists(db_path):
            raise RuntimeError("restore validation failed: flash_note.db missing")
        with sqlite3.connect(db_path, timeout=5.0) as conn:
            row = conn.execute(
                """
                SELECT COUNT(1)
                FROM sqlite_master
                WHERE type='table' AND name IN ('categories', 'notes')
                """
            ).fetchone()
            table_count = int(row[0]) if row else 0
            if table_count < 2:
                raise RuntimeError("restore validation failed: sqlite schema incomplete")
            conn.execute("SELECT COUNT(1) FROM categories").fetchone()
            conn.execute("SELECT COUNT(1) FROM notes").fetchone()
        return

    for filename in ("categories.json", "notes.json"):
        if filename not in restored_set:
            continue
        path = os.path.join(data_dir, filename)
        if not os.path.exists(path):
            raise RuntimeError(f"restore validation failed: {filename} missing")
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if not isinstance(payload, list):
            raise RuntimeError(f"restore validation failed: {filename} is not JSON list")


def validate_snapshot(snapshot_root):
    manifest_path = os.path.join(snapshot_root, "flash-note-backup", "manifest.json")
    if not os.path.exists(manifest_path):
        raise RuntimeError("invalid backup archive: missing manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if not isinstance(manifest, dict):
        raise RuntimeError("invalid manifest payload")
    return manifest


def build_parser():
    default_project_root = os.path.expanduser(os.getenv("APP_PROJECT_ROOT", "/root/flash-note"))
    default_data_dir = os.path.expanduser(os.getenv("APP_DATA_DIR", "~/flash-note/data"))
    default_backup_dir = os.path.expanduser(os.getenv("APP_BACKUP_DIR", "/root/flash-note/backups"))
    parser = argparse.ArgumentParser(description="Restore flash-note data from backup archive")
    parser.add_argument("--archive", default="", help="backup archive path; default latest in backup-dir")
    parser.add_argument("--backup-dir", default=default_backup_dir)
    parser.add_argument("--data-dir", default=default_data_dir)
    parser.add_argument("--service-name", default="flash-note.service")
    parser.add_argument("--manage-service", action="store_true", default=True)
    parser.add_argument("--no-manage-service", action="store_false", dest="manage_service")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true", help="skip safety prompt in non-dry-run mode")
    parser.add_argument("--project-root", default=default_project_root)
    return parser


def main():
    args = build_parser().parse_args()
    backup_dir = os.path.expanduser(args.backup_dir)
    data_dir = os.path.expanduser(args.data_dir)
    archive = os.path.expanduser(args.archive) if args.archive else find_latest_archive(backup_dir)
    if not archive:
        raise RuntimeError("no backup archive found")
    if not os.path.exists(archive):
        raise RuntimeError(f"backup archive not found: {archive}")

    with tempfile.TemporaryDirectory(prefix="flash-note-restore-") as tmp_dir:
        with tarfile.open(archive, mode="r:gz") as tar:
            safe_extract_tar(tar, tmp_dir)
        checksum_verified_files = verify_snapshot_checksums(tmp_dir)
        manifest = validate_snapshot(tmp_dir)
        print(f"restore_archive={archive}")
        print(f"manifest_created_at={manifest.get('createdAt', '')}")
        print(f"manifest_storage_files={len(manifest.get('storageFiles', []))}")
        print(f"checksum_verified_files={checksum_verified_files}")
        if args.dry_run:
            print("dry_run=1")
            return 0

        if not args.yes:
            raise RuntimeError("use --yes to confirm restore (this overwrites current data files)")

        service_was_active = is_service_active(args.service_name) if args.manage_service else False
        if args.manage_service and service_was_active:
            run_systemctl(["stop", args.service_name])

        backup_dir_before = ""
        copied_count = 0
        restored_count = 0
        rollback_performed = False
        rollback_files = 0
        rollback_file_names = []
        try:
            backup_dir_before, copied_count = backup_current_state(data_dir)
            restored_count, restored_file_names = apply_restore(tmp_dir, data_dir)
            validate_restored_data(data_dir, restored_file_names)
        except Exception as restore_exc:
            if backup_dir_before and copied_count > 0:
                try:
                    rollback_files, rollback_file_names = rollback_from_backup(backup_dir_before, data_dir)
                    rollback_performed = True
                except Exception as rollback_exc:
                    raise RuntimeError(
                        f"restore failed: {restore_exc}; rollback failed: {rollback_exc}"
                    )
            if rollback_performed:
                raise RuntimeError(
                    f"restore failed: {restore_exc}; rollback restored_files={rollback_files}"
                )
            raise
        finally:
            if args.manage_service and service_was_active:
                run_systemctl(["start", args.service_name])

    print(f"pre_restore_backup={backup_dir_before}")
    print(f"pre_restore_files={copied_count}")
    print(f"restored_files={restored_count}")
    if rollback_performed:
        print(f"rollback_restored_files={rollback_files}")
        print(f"rollback_file_list={','.join(rollback_file_names)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
