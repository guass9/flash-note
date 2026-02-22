#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import shutil
import sqlite3
import sys
import time


def read_json_list(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload if isinstance(payload, list) else []


def ensure_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS categories (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            content TEXT NOT NULL DEFAULT '',
            rich_content TEXT NOT NULL DEFAULT '',
            category_id TEXT NOT NULL DEFAULT '',
            tags_json TEXT NOT NULL DEFAULT '[]',
            create_time REAL NOT NULL,
            update_time REAL NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notes_category_update ON notes (category_id, update_time DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notes_update_time ON notes (update_time DESC)"
    )


def normalize_categories(raw):
    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        category_id = str(item.get("id", "")).strip() or f"cate_{time.time()}_{secrets.token_hex(3)}"
        result.append({"id": category_id, "name": name})
    return result


def normalize_notes(raw):
    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        note_id = str(item.get("id", "")).strip() or f"note_{time.time()}_{secrets.token_hex(3)}"
        title = str(item.get("title", "")).strip()
        content = str(item.get("content", "") or "").strip()
        rich = str(item.get("richContent", "") or "").strip()
        category_id = str(item.get("categoryId", "") or "").strip()
        tags = item.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        try:
            create_time = float(item.get("createTime", item.get("updateTime", time.time())))
        except Exception:
            create_time = float(time.time())
        try:
            update_time = float(item.get("updateTime", create_time))
        except Exception:
            update_time = create_time
        result.append(
            {
                "id": note_id,
                "title": title,
                "content": content,
                "rich_content": rich,
                "category_id": category_id,
                "tags_json": json.dumps(tags, ensure_ascii=False),
                "create_time": create_time,
                "update_time": update_time,
            }
        )
    return result


def backup_sources(src_files, backup_dir):
    os.makedirs(backup_dir, exist_ok=True)
    copied = 0
    for src in src_files:
        if not os.path.exists(src):
            continue
        shutil.copy2(src, os.path.join(backup_dir, os.path.basename(src)))
        copied += 1
    return copied


def build_parser():
    default_data_dir = os.path.expanduser("~/flash-note/data")
    parser = argparse.ArgumentParser(description="Migrate notes/categories JSON to SQLite")
    parser.add_argument("--data-dir", default=default_data_dir)
    parser.add_argument("--db-file", default="")
    parser.add_argument("--notes-file", default="")
    parser.add_argument("--categories-file", default="")
    parser.add_argument("--backup-dir", default="")
    parser.add_argument("--force", action="store_true", help="clear target tables before import")
    return parser


def main():
    args = build_parser().parse_args()
    data_dir = os.path.expanduser(args.data_dir)
    db_file = args.db_file or os.path.join(data_dir, "flash_note.db")
    notes_file = args.notes_file or os.path.join(data_dir, "notes.json")
    categories_file = args.categories_file or os.path.join(data_dir, "categories.json")
    backup_dir = args.backup_dir or os.path.join(
        data_dir, "backup", f"json-pre-sqlite-manual-{time.strftime('%Y%m%d-%H%M%S')}"
    )

    os.makedirs(os.path.dirname(db_file) or ".", exist_ok=True)
    raw_categories = read_json_list(categories_file)
    raw_notes = read_json_list(notes_file)
    categories = normalize_categories(raw_categories)
    notes = normalize_notes(raw_notes)
    copied = backup_sources([categories_file, notes_file], backup_dir)

    with sqlite3.connect(db_file, timeout=5.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        ensure_schema(conn)
        if args.force:
            conn.execute("DELETE FROM notes")
            conn.execute("DELETE FROM categories")
        for category in categories:
            conn.execute(
                "INSERT OR IGNORE INTO categories (id, name) VALUES (?, ?)",
                (category["id"], category["name"]),
            )
        for note in notes:
            conn.execute(
                """
                INSERT OR REPLACE INTO notes
                (id, title, content, rich_content, category_id, tags_json, create_time, update_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    note["id"],
                    note["title"],
                    note["content"],
                    note["rich_content"],
                    note["category_id"],
                    note["tags_json"],
                    note["create_time"],
                    note["update_time"],
                ),
            )
        conn.commit()

        category_count = int(conn.execute("SELECT COUNT(1) FROM categories").fetchone()[0])
        note_count = int(conn.execute("SELECT COUNT(1) FROM notes").fetchone()[0])

    print(f"migrated_categories={len(categories)} migrated_notes={len(notes)}")
    print(f"sqlite_totals categories={category_count} notes={note_count}")
    if copied > 0:
        print(f"backup_dir={backup_dir}")
    else:
        print("backup_dir=(none)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
