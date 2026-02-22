#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import sqlite3
import sys
import time


def write_json_atomic(file_path, payload):
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    tmp_path = os.path.join(
        os.path.dirname(file_path) or ".",
        f".{os.path.basename(file_path)}.tmp.{os.getpid()}.{time.time_ns()}",
    )
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, file_path)


def build_parser():
    default_data_dir = os.path.expanduser("~/flash-note/data")
    parser = argparse.ArgumentParser(description="Export SQLite notes/categories to JSON")
    parser.add_argument("--data-dir", default=default_data_dir)
    parser.add_argument("--db-file", default="")
    parser.add_argument("--notes-file", default="")
    parser.add_argument("--categories-file", default="")
    parser.add_argument("--backup-dir", default="")
    return parser


def main():
    args = build_parser().parse_args()
    data_dir = os.path.expanduser(args.data_dir)
    db_file = args.db_file or os.path.join(data_dir, "flash_note.db")
    notes_file = args.notes_file or os.path.join(data_dir, "notes.json")
    categories_file = args.categories_file or os.path.join(data_dir, "categories.json")
    backup_dir = args.backup_dir or os.path.join(
        data_dir, "backup", f"json-pre-export-{time.strftime('%Y%m%d-%H%M%S')}"
    )

    if not os.path.exists(db_file):
        raise RuntimeError(f"sqlite db not found: {db_file}")

    os.makedirs(backup_dir, exist_ok=True)
    for src in (categories_file, notes_file):
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(backup_dir, os.path.basename(src)))

    with sqlite3.connect(db_file, timeout=5.0) as conn:
        conn.row_factory = sqlite3.Row
        categories_rows = conn.execute(
            "SELECT id, name FROM categories ORDER BY rowid ASC"
        ).fetchall()
        notes_rows = conn.execute(
            """
            SELECT id, title, content, rich_content, category_id, tags_json, create_time, update_time
            FROM notes
            ORDER BY rowid ASC
            """
        ).fetchall()

    categories = []
    for row in categories_rows:
        categories.append(
            {
                "id": row["id"],
                "name": row["name"],
            }
        )

    notes = []
    for row in notes_rows:
        try:
            tags = json.loads(row["tags_json"] or "[]")
        except Exception:
            tags = []
        if not isinstance(tags, list):
            tags = []
        notes.append(
            {
                "id": row["id"],
                "title": row["title"] or "",
                "content": row["content"] or "",
                "richContent": row["rich_content"] or "",
                "categoryId": row["category_id"] or "",
                "tags": tags,
                "createTime": float(row["create_time"]),
                "updateTime": float(row["update_time"]),
            }
        )

    write_json_atomic(categories_file, categories)
    write_json_atomic(notes_file, notes)

    print(f"exported_categories={len(categories)} exported_notes={len(notes)}")
    print(f"backup_dir={backup_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
