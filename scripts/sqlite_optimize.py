#!/usr/bin/env python3
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def env_bool(name, default):
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def env_int(name, default):
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except Exception:
        return default


def env_float(name, default):
    raw = os.getenv(name, str(default)).strip()
    try:
        return float(raw)
    except Exception:
        return default


def read_db_stats(conn):
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0] or 0)
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0] or 0)
    freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0] or 0)
    return {
        "page_size": page_size,
        "page_count": page_count,
        "freelist_count": freelist_count,
    }


def build_parser():
    default_db_file = os.path.expanduser(
        os.getenv("APP_SQLITE_DB_FILE", "~/flash-note/data/flash_note.db")
    )
    parser = argparse.ArgumentParser(description="Run SQLite optimize/analyze maintenance")
    parser.add_argument("--db-file", default=default_db_file)
    parser.add_argument(
        "--with-analyze",
        action="store_true",
        default=env_bool("APP_SQLITE_OPTIMIZE_WITH_ANALYZE", False),
        help="run ANALYZE after PRAGMA optimize",
    )
    parser.add_argument(
        "--busy-timeout-ms",
        type=int,
        default=env_int("APP_SQLITE_OPTIMIZE_BUSY_TIMEOUT_MS", 5000),
    )
    parser.add_argument(
        "--with-vacuum",
        action="store_true",
        default=env_bool("APP_SQLITE_VACUUM_ENABLED", False),
        help="run VACUUM only when threshold conditions are met",
    )
    parser.add_argument(
        "--force-vacuum",
        action="store_true",
        help="force VACUUM regardless of thresholds",
    )
    parser.add_argument(
        "--vacuum-min-db-size-mb",
        type=int,
        default=env_int("APP_SQLITE_VACUUM_MIN_DB_SIZE_MB", 128),
        help="minimum db file size to consider VACUUM",
    )
    parser.add_argument(
        "--vacuum-min-reclaim-mb",
        type=int,
        default=env_int("APP_SQLITE_VACUUM_MIN_RECLAIM_MB", 16),
        help="minimum estimated reclaim size to run VACUUM",
    )
    parser.add_argument(
        "--vacuum-fragmentation-ratio-threshold",
        type=float,
        default=env_float("APP_SQLITE_VACUUM_FRAGMENTATION_RATIO_THRESHOLD", 0.20),
        help="minimum freelist/page_count ratio to run VACUUM",
    )
    return parser


def main():
    args = build_parser().parse_args()
    db_file = os.path.expanduser(args.db_file)
    busy_timeout_ms = max(1000, int(args.busy_timeout_ms))

    if not os.path.exists(db_file):
        print(f"error: db file not found: {db_file}", file=sys.stderr)
        return 1

    db_size_before = int(os.path.getsize(db_file))
    min_db_size_bytes = max(1, int(args.vacuum_min_db_size_mb)) * 1024 * 1024
    min_reclaim_bytes = max(1, int(args.vacuum_min_reclaim_mb)) * 1024 * 1024
    fragmentation_threshold = max(0.0, float(args.vacuum_fragmentation_ratio_threshold))
    analyzed = False
    vacuum_executed = False
    vacuum_reason = "disabled"

    with sqlite3.connect(db_file, timeout=max(1.0, busy_timeout_ms / 1000.0)) as conn:
        conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        optimize_rows = conn.execute("PRAGMA optimize").fetchall()
        if args.with_analyze:
            conn.execute("ANALYZE")
            analyzed = True
        before_stats = read_db_stats(conn)
        estimated_reclaim_bytes_before = (
            int(before_stats["freelist_count"]) * int(before_stats["page_size"])
        )
        if args.force_vacuum:
            vacuum_executed = True
            vacuum_reason = "forced"
        elif args.with_vacuum:
            page_count = max(0, int(before_stats["page_count"]))
            freelist_count = max(0, int(before_stats["freelist_count"]))
            fragmentation_ratio = (
                (float(freelist_count) / float(page_count))
                if page_count > 0
                else 0.0
            )
            threshold_met = (
                db_size_before >= min_db_size_bytes
                and estimated_reclaim_bytes_before >= min_reclaim_bytes
                and fragmentation_ratio >= fragmentation_threshold
            )
            if threshold_met:
                vacuum_executed = True
                vacuum_reason = "threshold_met"
            else:
                vacuum_reason = (
                    "threshold_not_met"
                    f"(db_size_bytes={db_size_before},min_db_size_bytes={min_db_size_bytes},"
                    f"estimated_reclaim_bytes={estimated_reclaim_bytes_before},"
                    f"min_reclaim_bytes={min_reclaim_bytes},"
                    f"fragmentation_ratio={fragmentation_ratio:.4f},"
                    f"fragmentation_threshold={fragmentation_threshold:.4f})"
                )

        conn.commit()
        if vacuum_executed:
            conn.execute("VACUUM")
            conn.commit()

        after_stats = read_db_stats(conn)
        conn.commit()

    db_size_after = int(os.path.getsize(db_file))
    estimated_reclaim_bytes_after = (
        int(after_stats["freelist_count"]) * int(after_stats["page_size"])
    )
    reclaimed_bytes = max(0, db_size_before - db_size_after)
    fragmentation_ratio_before = (
        (float(before_stats["freelist_count"]) / float(before_stats["page_count"]))
        if int(before_stats["page_count"]) > 0
        else 0.0
    )
    fragmentation_ratio_after = (
        (float(after_stats["freelist_count"]) / float(after_stats["page_count"]))
        if int(after_stats["page_count"]) > 0
        else 0.0
    )

    print(f"time={iso_now()}")
    print(f"db_file={db_file}")
    print(f"optimize_rows={len(optimize_rows)}")
    print(f"with_analyze={1 if analyzed else 0}")
    print(f"with_vacuum={1 if args.with_vacuum else 0}")
    print(f"force_vacuum={1 if args.force_vacuum else 0}")
    print(f"vacuum_executed={1 if vacuum_executed else 0}")
    print(f"vacuum_reason={vacuum_reason}")
    print(f"vacuum_min_db_size_mb={int(args.vacuum_min_db_size_mb)}")
    print(f"vacuum_min_reclaim_mb={int(args.vacuum_min_reclaim_mb)}")
    print(f"vacuum_fragmentation_ratio_threshold={fragmentation_threshold:.4f}")
    print(f"db_size_before_bytes={db_size_before}")
    print(f"db_size_after_bytes={db_size_after}")
    print(f"reclaimed_bytes={reclaimed_bytes}")
    print(f"page_size_before={int(before_stats['page_size'])}")
    print(f"page_count_before={int(before_stats['page_count'])}")
    print(f"freelist_count_before={int(before_stats['freelist_count'])}")
    print(f"estimated_reclaim_before_bytes={estimated_reclaim_bytes_before}")
    print(f"fragmentation_ratio_before={fragmentation_ratio_before:.4f}")
    print(f"page_size_after={int(after_stats['page_size'])}")
    print(f"page_count_after={int(after_stats['page_count'])}")
    print(f"freelist_count_after={int(after_stats['freelist_count'])}")
    print(f"estimated_reclaim_after_bytes={estimated_reclaim_bytes_after}")
    print(f"fragmentation_ratio_after={fragmentation_ratio_after:.4f}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
