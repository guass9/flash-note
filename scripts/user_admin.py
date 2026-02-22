#!/usr/bin/env python3
import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime


DEFAULT_DATA_DIR = os.path.expanduser("~/flash-note/data")
DEFAULT_USERS_FILE = os.path.join(DEFAULT_DATA_DIR, "users.json")
DEFAULT_HASH_ITERATIONS = int(os.getenv("APP_PASSWORD_HASH_ITERATIONS", "210000"))
VALID_STATUS = {"active", "disabled", "locked"}
VALID_ROLE = {"user", "admin"}


def now_utc_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def b64url_encode_no_pad(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def b64url_decode_no_pad(raw_text):
    padded = raw_text + ("=" * (-len(raw_text) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def hash_password_pbkdf2(password, iterations):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        str(password).encode("utf-8"),
        salt,
        int(iterations),
    )
    return "pbkdf2_sha256${}${}${}".format(
        int(iterations),
        b64url_encode_no_pad(salt),
        b64url_encode_no_pad(digest),
    )


def verify_password_pbkdf2(password, password_hash):
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = str(password_hash).split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        if iterations <= 0:
            return False
        salt = b64url_decode_no_pad(salt_raw)
        expected = b64url_decode_no_pad(digest_raw)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            str(password).encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def normalize_user_status(raw_status):
    status = str(raw_status or "active").strip().lower()
    if status in {"active", "enabled"}:
        return "active"
    if status in {"locked", "blocked"}:
        return "locked"
    return "disabled"


def normalize_user_role(raw_role, username=""):
    role = str(raw_role or "").strip().lower()
    if role in VALID_ROLE:
        return role
    if role == "":
        return ""
    return "user"


def normalize_users_payload(payload, iterations):
    if isinstance(payload, dict):
        users_raw = payload.get("users", [])
    elif isinstance(payload, list):
        users_raw = payload
    else:
        users_raw = []

    changed = not (isinstance(payload, dict) and int(payload.get("version", 0) or 0) == 1)
    users = []
    seen = set()
    now_iso = now_utc_iso()

    for item in users_raw:
        if not isinstance(item, dict):
            changed = True
            continue

        username = str(item.get("username", "")).strip()
        if not username:
            changed = True
            continue

        user_key = username.lower()
        if user_key in seen:
            changed = True
            continue
        seen.add(user_key)

        password_hash = str(item.get("passwordHash", "")).strip()
        if not password_hash and str(item.get("password", "")).strip():
            password_hash = hash_password_pbkdf2(item.get("password"), iterations)
            changed = True

        if not password_hash:
            changed = True
            continue

        status = normalize_user_status(item.get("status", "active"))
        role_raw = str(item.get("role", "")).strip().lower()
        role = normalize_user_role(role_raw, username=username)
        if role != role_raw:
            changed = True
        created_at = str(item.get("createdAt", "")).strip() or now_iso
        updated_at = str(item.get("updatedAt", "")).strip() or created_at

        users.append(
            {
                "username": username,
                "passwordHash": password_hash,
                "status": status,
                "role": role,
                "createdAt": created_at,
                "updatedAt": updated_at,
            }
        )

        if "password" in item:
            changed = True

    return {"version": 1, "users": users}, changed


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def load_users_file(users_file, iterations):
    if not os.path.exists(users_file):
        return {"version": 1, "users": []}
    with open(users_file, "r", encoding="utf-8") as f:
        payload = json.load(f)
    normalized, _ = normalize_users_payload(payload, iterations)
    return normalized


def save_users_file(users_file, payload):
    ensure_parent_dir(users_file)
    dir_path = os.path.dirname(users_file) or "."
    tmp_path = os.path.join(
        dir_path,
        f".{os.path.basename(users_file)}.tmp.{os.getpid()}.{time.time_ns()}",
    )
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, users_file)
    try:
        dir_fd = os.open(dir_path, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def with_locked_users(users_file, iterations, op):
    ensure_parent_dir(users_file)
    lock_path = f"{users_file}.lock"
    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        payload = load_users_file(users_file, iterations)
        normalized, changed = normalize_users_payload(payload, iterations)
        result = op(normalized)
        if changed or result.get("changed"):
            save_users_file(users_file, normalized)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return result


def find_user(users_payload, username):
    key = username.strip().lower()
    for user in users_payload.get("users", []):
        if str(user.get("username", "")).strip().lower() == key:
            return user
    return None


def require_username(username):
    normalized = str(username or "").strip()
    if not normalized:
        raise ValueError("username 不能为空")
    if len(normalized) > 64:
        raise ValueError("username 长度不能超过 64")
    return normalized


def require_password(password):
    raw = str(password or "")
    if not raw:
        raise ValueError("password 不能为空")
    if len(raw) < 4:
        raise ValueError("password 长度至少 4")
    return raw


def cmd_list(args):
    def op(payload):
        return {"changed": False, "users": payload.get("users", [])}

    result = with_locked_users(args.users_file, args.iterations, op)
    users = result["users"]
    if not users:
        print("no users")
        return 0

    print("username\tstatus\trole\tcreatedAt\tupdatedAt")
    for user in users:
        print(
            "{}\t{}\t{}\t{}\t{}".format(
                user.get("username", ""),
                user.get("status", ""),
                user.get("role", ""),
                user.get("createdAt", ""),
                user.get("updatedAt", ""),
            )
        )
    return 0


def cmd_add(args):
    username = require_username(args.username)
    password = require_password(args.password)
    status = normalize_user_status(args.status)
    role = normalize_user_role(args.role, username=username)
    if status not in VALID_STATUS:
        raise ValueError("status 仅支持: active/disabled/locked")
    if role not in VALID_ROLE:
        raise ValueError("role 仅支持: user/admin")

    def op(payload):
        users = payload.get("users", [])
        existing = find_user(payload, username)
        now_iso = now_utc_iso()
        if existing and not args.upsert:
            raise ValueError(f"user 已存在: {username}")
        if existing and args.upsert:
            existing["passwordHash"] = hash_password_pbkdf2(password, args.iterations)
            existing["status"] = status
            existing["role"] = role
            existing["updatedAt"] = now_iso
            return {"changed": True, "message": f"user 已更新: {existing['username']}"}

        users.append(
            {
                "username": username,
                "passwordHash": hash_password_pbkdf2(password, args.iterations),
                "status": status,
                "role": role,
                "createdAt": now_iso,
                "updatedAt": now_iso,
            }
        )
        return {"changed": True, "message": f"user 已创建: {username}"}

    result = with_locked_users(args.users_file, args.iterations, op)
    print(result["message"])
    return 0


def cmd_passwd(args):
    username = require_username(args.username)
    password = require_password(args.password)

    def op(payload):
        user = find_user(payload, username)
        if not user:
            raise ValueError(f"user 不存在: {username}")
        old_hash = str(user.get("passwordHash", ""))
        if verify_password_pbkdf2(password, old_hash):
            return {"changed": False, "message": f"user 密码未变化: {user['username']}"}
        user["passwordHash"] = hash_password_pbkdf2(password, args.iterations)
        user["updatedAt"] = now_utc_iso()
        return {"changed": True, "message": f"user 密码已更新: {user['username']}"}

    result = with_locked_users(args.users_file, args.iterations, op)
    print(result["message"])
    return 0


def cmd_status(args):
    username = require_username(args.username)
    status = normalize_user_status(args.status)
    if status not in VALID_STATUS:
        raise ValueError("status 仅支持: active/disabled/locked")

    def op(payload):
        user = find_user(payload, username)
        if not user:
            raise ValueError(f"user 不存在: {username}")
        if user.get("status") == status:
            return {"changed": False, "message": f"user 状态未变化: {user['username']}={status}"}
        user["status"] = status
        user["updatedAt"] = now_utc_iso()
        return {"changed": True, "message": f"user 状态已更新: {user['username']}={status}"}

    result = with_locked_users(args.users_file, args.iterations, op)
    print(result["message"])
    return 0


def cmd_role(args):
    username = require_username(args.username)
    role = normalize_user_role(args.role, username=username)
    if role not in VALID_ROLE:
        raise ValueError("role 仅支持: user/admin")

    def op(payload):
        user = find_user(payload, username)
        if not user:
            raise ValueError(f"user 不存在: {username}")
        if str(user.get("role", "")).strip().lower() == role:
            return {"changed": False, "message": f"user 角色未变化: {user['username']}={role}"}
        user["role"] = role
        user["updatedAt"] = now_utc_iso()
        return {"changed": True, "message": f"user 角色已更新: {user['username']}={role}"}

    result = with_locked_users(args.users_file, args.iterations, op)
    print(result["message"])
    return 0


def cmd_delete(args):
    username = require_username(args.username)

    def op(payload):
        users = payload.get("users", [])
        before = len(users)
        target = username.strip().lower()
        users[:] = [
            u for u in users if str(u.get("username", "")).strip().lower() != target
        ]
        if len(users) == before:
            raise ValueError(f"user 不存在: {username}")
        return {"changed": True, "message": f"user 已删除: {username}"}

    result = with_locked_users(args.users_file, args.iterations, op)
    print(result["message"])
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="瞬念笔记用户管理（users.json）"
    )
    parser.add_argument(
        "--users-file",
        default=DEFAULT_USERS_FILE,
        help=f"users.json path (default: {DEFAULT_USERS_FILE})",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_HASH_ITERATIONS,
        help=f"PBKDF2 iterations (default: {DEFAULT_HASH_ITERATIONS})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list users").set_defaults(func=cmd_list)

    p_add = sub.add_parser("add", help="add user")
    p_add.add_argument("--username", required=True)
    p_add.add_argument("--password", required=True)
    p_add.add_argument("--status", default="active", choices=sorted(VALID_STATUS))
    p_add.add_argument("--role", default="user", choices=sorted(VALID_ROLE))
    p_add.add_argument("--upsert", action="store_true", help="update if exists")
    p_add.set_defaults(func=cmd_add)

    p_passwd = sub.add_parser("passwd", help="reset password")
    p_passwd.add_argument("--username", required=True)
    p_passwd.add_argument("--password", required=True)
    p_passwd.set_defaults(func=cmd_passwd)

    p_status = sub.add_parser("status", help="set account status")
    p_status.add_argument("--username", required=True)
    p_status.add_argument("--status", required=True, choices=sorted(VALID_STATUS))
    p_status.set_defaults(func=cmd_status)

    p_role = sub.add_parser("role", help="set account role")
    p_role.add_argument("--username", required=True)
    p_role.add_argument("--role", required=True, choices=sorted(VALID_ROLE))
    p_role.set_defaults(func=cmd_role)

    p_delete = sub.add_parser("delete", help="delete user")
    p_delete.add_argument("--username", required=True)
    p_delete.set_defaults(func=cmd_delete)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.iterations < 100000:
        raise ValueError("iterations 不能小于 100000")
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
