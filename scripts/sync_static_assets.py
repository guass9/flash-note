#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
import sys
from dataclasses import dataclass


PROJECT_ROOT = "/root/flash-note"
SOURCE_ROOT = os.path.join(PROJECT_ROOT, "frontend")
TARGET_ROOT = os.path.join(PROJECT_ROOT, "backend", "static")


@dataclass(frozen=True)
class SyncPair:
    source_rel: str
    target_rel: str


SYNC_PAIRS = [
    SyncPair("index.html", "index.html"),
    SyncPair("login.html", "login.html"),
    SyncPair("vendor/marked.min.js", "vendor/marked.min.js"),
    SyncPair("vendor/purify.min.js", "vendor/purify.min.js"),
]


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_exists(path: str, label: str) -> None:
    if not os.path.exists(path):
        raise FileNotFoundError(f"{label} missing: {path}")


def check_pair(pair: SyncPair) -> tuple[bool, str]:
    src = os.path.join(SOURCE_ROOT, pair.source_rel)
    dst = os.path.join(TARGET_ROOT, pair.target_rel)
    ensure_exists(src, "source")
    ensure_exists(dst, "target")
    same = sha256_file(src) == sha256_file(dst)
    return same, pair.target_rel


def sync_pair(pair: SyncPair) -> tuple[bool, str]:
    src = os.path.join(SOURCE_ROOT, pair.source_rel)
    dst = os.path.join(TARGET_ROOT, pair.target_rel)
    ensure_exists(src, "source")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    changed = True
    if os.path.exists(dst):
        changed = sha256_file(src) != sha256_file(dst)
    if changed:
        shutil.copy2(src, dst)
    return changed, pair.target_rel


def run_check() -> int:
    mismatches = []
    for pair in SYNC_PAIRS:
        same, rel = check_pair(pair)
        print(f"[check] {rel}: {'OK' if same else 'DRIFT'}")
        if not same:
            mismatches.append(rel)
    if mismatches:
        print(f"[check] drift_count={len(mismatches)}")
        return 1
    print("[check] all static assets in sync")
    return 0


def run_sync() -> int:
    changed_count = 0
    for pair in SYNC_PAIRS:
        changed, rel = sync_pair(pair)
        print(f"[sync] {rel}: {'UPDATED' if changed else 'UNCHANGED'}")
        if changed:
            changed_count += 1
    print(f"[sync] changed_count={changed_count}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync frontend static assets to backend/static (single source: frontend)."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check drift only; exit 1 if any file differs.",
    )
    args = parser.parse_args()

    try:
        if args.check:
            return run_check()
        return run_sync()
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
