from flask import Flask, request, jsonify, redirect, session, g, has_request_context
import base64
import copy
import threading
import fcntl
import hmac
import html
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import time
from collections import OrderedDict
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urlparse

try:
    import redis
except Exception:
    redis = None


APP_ENV = os.getenv('APP_ENV', 'dev').strip().lower()
IS_PROD = APP_ENV in {'prod', 'production'}
APP_START_TS = time.time()


def get_env(name, default=None, required_in_prod=False):
    value = os.getenv(name)
    if value is None or str(value).strip() == "":
        if IS_PROD and required_in_prod:
            raise RuntimeError(
                f"APP_ENV={APP_ENV} 时必须设置环境变量: {name}"
            )
        return default
    return value


def get_env_bool(name, default=False):
    raw = str(get_env(name, '1' if default else '0')).strip().lower()
    return raw in {'1', 'true', 'yes', 'on'}


def parse_csv_env(name, default=''):
    raw = str(get_env(name, default)).strip()
    if not raw:
        return set()
    return {item.strip() for item in raw.split(',') if item.strip()}


def build_vary_header(existing, value):
    parts = [p.strip() for p in str(existing or '').split(',') if p.strip()]
    if value not in parts:
        parts.append(value)
    return ', '.join(parts)


REQUEST_ID_HEADER = 'X-Request-ID'
REQUEST_ID_MAX_LEN = 64
REQUEST_ID_PATTERN = re.compile(r'^[A-Za-z0-9._:-]+$')


def generate_request_id():
    return secrets.token_hex(8)


def normalize_request_id(raw_value):
    candidate = str(raw_value or '').strip()
    if not candidate:
        return generate_request_id()
    if len(candidate) > REQUEST_ID_MAX_LEN:
        candidate = candidate[:REQUEST_ID_MAX_LEN]
    if not REQUEST_ID_PATTERN.match(candidate):
        return generate_request_id()
    return candidate


def get_request_id():
    if not has_request_context():
        return '-'
    value = getattr(g, 'request_id', '')
    return str(value) if value else '-'


def get_request_actor():
    if not has_request_context():
        return 'system'
    username = str(session.get('username', '')).strip()
    return username or 'anonymous'


def audit_log(level, event, **fields):
    record = OrderedDict()
    record["event"] = event
    if has_request_context():
        record["request_id"] = get_request_id()
        record["ip"] = get_client_ip()
        record["actor"] = get_request_actor()
        record["method"] = request.method
        record["path"] = request.path
    for key, value in fields.items():
        if value is None:
            continue
        record[key] = value

    kv_pairs = []
    for key, value in record.items():
        text = str(value).replace('\n', ' ').replace('\r', ' ')
        if len(text) > 256:
            text = text[:256] + '...'
        kv_pairs.append(f"{key}={text}")
    app.logger.log(level, "audit %s", " ".join(kv_pairs))


def setup_logging():
    level_name = str(get_env('APP_LOG_LEVEL', 'INFO')).strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    root_logger = logging.getLogger()
    if root_logger.handlers:
        for handler in root_logger.handlers:
            handler.setFormatter(formatter)
    else:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)

    root_logger.setLevel(level)
    app.logger.setLevel(level)


# 初始化 Flask 应用
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=os.path.join(BASE_DIR, 'static'))
SESSION_COOKIE_SAMESITE = str(get_env('SESSION_COOKIE_SAMESITE', 'Lax')).strip().capitalize()
if SESSION_COOKIE_SAMESITE not in {'Lax', 'Strict', 'None'}:
    raise RuntimeError("SESSION_COOKIE_SAMESITE 仅支持: Lax / Strict / None")
SESSION_COOKIE_SECURE = get_env_bool(
    'SESSION_COOKIE_SECURE',
    default=IS_PROD
)
if SESSION_COOKIE_SAMESITE == 'None' and not SESSION_COOKIE_SECURE:
    raise RuntimeError("SESSION_COOKIE_SAMESITE=None 时必须设置 SESSION_COOKIE_SECURE=1")

ALLOWED_CORS_ORIGINS = parse_csv_env('APP_CORS_ALLOW_ORIGINS', '')
APP_CORS_ALLOW_CREDENTIALS = get_env_bool('APP_CORS_ALLOW_CREDENTIALS', default=True)

app.config['SECRET_KEY'] = get_env(
    'APP_SECRET_KEY',
    default='flash-note-local-secret',
    required_in_prod=True
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = SESSION_COOKIE_SAMESITE
app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
setup_logging()

# 配置本地数据文件路径（Ubuntu 本地目录）
DATA_DIR = os.path.expanduser("~/flash-note/data")
NOTES_FILE = os.path.join(DATA_DIR, "notes.json")
CATEGORIES_FILE = os.path.join(DATA_DIR, "categories.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SQLITE_DB_FILE = str(get_env('APP_SQLITE_DB_FILE', os.path.join(DATA_DIR, "flash_note.db"))).strip()
APP_STORAGE_BACKEND = str(get_env('APP_STORAGE_BACKEND', 'sqlite')).strip().lower()
APP_SQLITE_TIMEOUT_SEC = float(get_env('APP_SQLITE_TIMEOUT_SEC', '5.0'))
APP_NOTES_LIST_MAX_LIMIT = int(get_env('APP_NOTES_LIST_MAX_LIMIT', '200'))
APP_SQLITE_ENABLE_FTS = get_env_bool('APP_SQLITE_ENABLE_FTS', default=True)
APP_NOTES_QUERY_CACHE_TTL_SEC = float(get_env('APP_NOTES_QUERY_CACHE_TTL_SEC', '8'))
APP_NOTES_QUERY_CACHE_MAX_ENTRIES = int(get_env('APP_NOTES_QUERY_CACHE_MAX_ENTRIES', '256'))
APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC = float(
    get_env('APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC', '60')
)
APP_AUTH_BOOTSTRAP_SYNC_MODE = str(
    get_env('APP_AUTH_BOOTSTRAP_SYNC_MODE', 'sync')
).strip().lower()
if APP_AUTH_BOOTSTRAP_SYNC_MODE not in {'sync', 'create_only', 'disabled'}:
    raise RuntimeError("APP_AUTH_BOOTSTRAP_SYNC_MODE 仅支持: sync / create_only / disabled")

REQUIRE_BOOTSTRAP_CREDENTIALS = APP_AUTH_BOOTSTRAP_SYNC_MODE != 'disabled'
bootstrap_default_username = '909020' if REQUIRE_BOOTSTRAP_CREDENTIALS else ''
bootstrap_default_password = '909020' if REQUIRE_BOOTSTRAP_CREDENTIALS else ''
AUTH_BOOTSTRAP_USERNAME = get_env(
    'APP_LOGIN_USERNAME',
    default=bootstrap_default_username,
    required_in_prod=REQUIRE_BOOTSTRAP_CREDENTIALS
)
AUTH_BOOTSTRAP_PASSWORD = get_env(
    'APP_LOGIN_PASSWORD',
    default=bootstrap_default_password,
    required_in_prod=REQUIRE_BOOTSTRAP_CREDENTIALS
)
APP_PASSWORD_HASH_ITERATIONS = int(get_env('APP_PASSWORD_HASH_ITERATIONS', '210000'))
APP_LOGIN_RATE_LIMIT_WINDOW_SEC = int(get_env('APP_LOGIN_RATE_LIMIT_WINDOW_SEC', '300'))
APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS = int(get_env('APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS', '8'))
APP_LOGIN_RATE_LIMIT_BLOCK_SEC = int(get_env('APP_LOGIN_RATE_LIMIT_BLOCK_SEC', '600'))
APP_LOGIN_RATE_LIMIT_BACKEND = str(get_env('APP_LOGIN_RATE_LIMIT_BACKEND', 'memory')).strip().lower()
APP_LOGIN_RATE_LIMIT_KEY_PREFIX = str(
    get_env('APP_LOGIN_RATE_LIMIT_KEY_PREFIX', 'shunnian:login_rl')
).strip()
APP_REDIS_URL = str(get_env('APP_REDIS_URL', 'redis://127.0.0.1:6379/0')).strip()
APP_REDIS_SOCKET_TIMEOUT_SEC = float(get_env('APP_REDIS_SOCKET_TIMEOUT_SEC', '1.0'))
APP_SESSION_IDLE_TIMEOUT_SEC = int(get_env('APP_SESSION_IDLE_TIMEOUT_SEC', '3600'))

if APP_LOGIN_RATE_LIMIT_WINDOW_SEC <= 0:
    raise RuntimeError("APP_LOGIN_RATE_LIMIT_WINDOW_SEC 必须大于 0")
if APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS <= 0:
    raise RuntimeError("APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS 必须大于 0")
if APP_LOGIN_RATE_LIMIT_BLOCK_SEC <= 0:
    raise RuntimeError("APP_LOGIN_RATE_LIMIT_BLOCK_SEC 必须大于 0")
if APP_PASSWORD_HASH_ITERATIONS < 100000:
    raise RuntimeError("APP_PASSWORD_HASH_ITERATIONS 不能小于 100000")
if APP_STORAGE_BACKEND not in {'json', 'sqlite'}:
    raise RuntimeError("APP_STORAGE_BACKEND 仅支持: json / sqlite")
if APP_SQLITE_TIMEOUT_SEC <= 0:
    raise RuntimeError("APP_SQLITE_TIMEOUT_SEC 必须大于 0")
if APP_NOTES_LIST_MAX_LIMIT <= 0:
    raise RuntimeError("APP_NOTES_LIST_MAX_LIMIT 必须大于 0")
if APP_NOTES_QUERY_CACHE_TTL_SEC < 0:
    raise RuntimeError("APP_NOTES_QUERY_CACHE_TTL_SEC 不能小于 0")
if APP_NOTES_QUERY_CACHE_MAX_ENTRIES <= 0:
    raise RuntimeError("APP_NOTES_QUERY_CACHE_MAX_ENTRIES 必须大于 0")
if APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC < 0:
    raise RuntimeError("APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC 不能小于 0")
if APP_LOGIN_RATE_LIMIT_BACKEND not in {'memory', 'redis'}:
    raise RuntimeError("APP_LOGIN_RATE_LIMIT_BACKEND 仅支持: memory / redis")
if APP_LOGIN_RATE_LIMIT_BACKEND == 'redis' and redis is None:
    raise RuntimeError("启用 Redis 限速需要安装 redis Python 包")
if not APP_LOGIN_RATE_LIMIT_KEY_PREFIX:
    raise RuntimeError("APP_LOGIN_RATE_LIMIT_KEY_PREFIX 不能为空")
if APP_SESSION_IDLE_TIMEOUT_SEC <= 0:
    raise RuntimeError("APP_SESSION_IDLE_TIMEOUT_SEC 必须大于 0")

LOGIN_RATE_STATE = {}
LOGIN_RATE_LOCK = threading.Lock()
LOGIN_RATE_STATE_CLEANUP_INTERVAL_SEC = 60
LOGIN_RATE_LAST_CLEANUP = 0.0
LOGIN_RATE_REDIS_CLIENT = None
SQLITE_FTS_ACTIVE = False
NOTES_QUERY_CACHE = OrderedDict()
NOTES_QUERY_CACHE_LOCK = threading.Lock()
NOTES_QUERY_CACHE_LAST_SWEEP_TS = 0.0
NOTES_QUERY_CACHE_STATS = {
    "hits": 0,
    "misses": 0,
    "stores": 0,
    "evictions": 0,
    "invalidations": 0,
    "invalidated_entries": 0,
    "expired": 0,
    "sweeps": 0,
    "swept_entries": 0,
}

app.logger.info(
    "app_boot env=%s cookie_secure=%s samesite=%s cors_allowlist=%s storage=%s sqlite_fts_enabled=%s notes_cache_ttl=%ss notes_cache_max=%s notes_cache_sweep_interval=%ss login_rate_limit=%s/%ss block=%ss backend=%s session_idle_timeout=%ss auth_store=users.json hash_iter=%s bootstrap_sync_mode=%s",
    APP_ENV,
    app.config['SESSION_COOKIE_SECURE'],
    app.config['SESSION_COOKIE_SAMESITE'],
    sorted(ALLOWED_CORS_ORIGINS),
    APP_STORAGE_BACKEND,
    APP_SQLITE_ENABLE_FTS,
    APP_NOTES_QUERY_CACHE_TTL_SEC,
    APP_NOTES_QUERY_CACHE_MAX_ENTRIES,
    APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC,
    APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    APP_LOGIN_RATE_LIMIT_WINDOW_SEC,
    APP_LOGIN_RATE_LIMIT_BLOCK_SEC,
    APP_LOGIN_RATE_LIMIT_BACKEND,
    APP_SESSION_IDLE_TIMEOUT_SEC,
    APP_PASSWORD_HASH_ITERATIONS,
    APP_AUTH_BOOTSTRAP_SYNC_MODE
)

ALLOWED_RICH_TAGS = {
    "p", "br", "strong", "b", "em", "i", "u", "s", "ul", "ol", "li",
    "blockquote", "code", "pre", "h1", "h2", "h3", "h4", "a", "span", "div"
}

ALLOWED_LINK_SCHEMES = {"http", "https", "mailto", "tel"}
VOID_RICH_TAGS = {"br"}


class SafeHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []
        self.open_tags = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag not in ALLOWED_RICH_TAGS:
            return

        filtered_attrs = []
        if tag == "a":
            for key, value in attrs:
                if key not in {"href", "target", "rel"}:
                    continue
                safe_value = (value or "").strip()
                if key == "href":
                    if not safe_value:
                        continue
                    parsed = urlparse(safe_value)
                    if parsed.scheme and parsed.scheme.lower() not in ALLOWED_LINK_SCHEMES:
                        continue
                if key == "target":
                    if safe_value != "_blank":
                        continue
                if key == "rel":
                    safe_value = "noopener noreferrer"
                filtered_attrs.append((key, safe_value))
            if not any(key == "rel" for key, _ in filtered_attrs):
                filtered_attrs.append(("rel", "noopener noreferrer"))
        attr_text = "".join(
            f' {k}="{html.escape(v, quote=True)}"' for k, v in filtered_attrs
        )

        if tag in VOID_RICH_TAGS:
            self.result.append(f"<{tag}{attr_text}>")
            return

        self.result.append(f"<{tag}{attr_text}>")
        self.open_tags.append(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag not in ALLOWED_RICH_TAGS or tag in VOID_RICH_TAGS:
            return
        if tag in self.open_tags:
            for idx in range(len(self.open_tags) - 1, -1, -1):
                opened_tag = self.open_tags[idx]
                self.result.append(f"</{opened_tag}>")
                del self.open_tags[idx]
                if opened_tag == tag:
                    break

    def handle_data(self, data):
        self.result.append(html.escape(data))

    def handle_entityref(self, name):
        self.result.append(f"&{name};")

    def handle_charref(self, name):
        self.result.append(f"&#{name};")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() in ALLOWED_RICH_TAGS and tag.lower() not in VOID_RICH_TAGS:
            self.handle_endtag(tag)

    def close_open_tags(self):
        while self.open_tags:
            self.result.append(f"</{self.open_tags.pop()}>")


def sanitize_rich_html(raw_html):
    if not raw_html:
        return ""
    parser = SafeHTMLParser()
    parser.feed(raw_html)
    parser.close_open_tags()
    return "".join(parser.result).strip()


def rich_html_to_plain_text(raw_html):
    if not raw_html:
        return ""
    text = re.sub(r"<[^>]+>", " ", raw_html)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_tags(raw_tags):
    if isinstance(raw_tags, str):
        tokens = re.split(r"[,\uFF0C\n]+", raw_tags)
    elif isinstance(raw_tags, list):
        tokens = raw_tags
    else:
        tokens = []

    cleaned = []
    seen = set()
    for tag in tokens:
        t = str(tag).strip()
        if not t:
            continue
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(t[:30])
    return cleaned


def build_note_payload(data, current_note=None):
    has_rich = "richContent" in data
    has_content = "content" in data
    has_category = "categoryId" in data
    has_tags = "tags" in data

    rich_raw = data.get("richContent", "")
    rich_content = sanitize_rich_html(rich_raw)
    plain_content = (data.get("content") or "").strip()
    if rich_content:
        plain_content = rich_html_to_plain_text(rich_content)

    payload = {
        "title": (data.get("title") or "").strip(),
        "content": plain_content,
        "richContent": rich_content,
        "categoryId": (data.get("categoryId") or "").strip(),
        "tags": normalize_tags(data.get("tags")),
    }
    if current_note:
        if not has_category:
            payload["categoryId"] = current_note.get("categoryId", "")
        if not has_tags:
            payload["tags"] = current_note.get("tags", [])
        if not has_rich and not has_content:
            payload["richContent"] = current_note.get("richContent", "")
            payload["content"] = current_note.get("content", "")
    return payload


def now_utc_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def b64url_encode_no_pad(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).decode('ascii').rstrip('=')


def b64url_decode_no_pad(raw_text):
    padded = raw_text + ('=' * (-len(raw_text) % 4))
    return base64.urlsafe_b64decode(padded.encode('ascii'))


def hash_password_pbkdf2(password, iterations=APP_PASSWORD_HASH_ITERATIONS):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256',
        str(password).encode('utf-8'),
        salt,
        int(iterations)
    )
    return "pbkdf2_sha256${}${}${}".format(
        int(iterations),
        b64url_encode_no_pad(salt),
        b64url_encode_no_pad(digest)
    )


def verify_password_pbkdf2(password, password_hash):
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = str(password_hash).split('$', 3)
        if algorithm != 'pbkdf2_sha256':
            return False
        iterations = int(iterations_raw)
        if iterations <= 0:
            return False
        salt = b64url_decode_no_pad(salt_raw)
        expected_digest = b64url_decode_no_pad(digest_raw)
        actual_digest = hashlib.pbkdf2_hmac(
            'sha256',
            str(password).encode('utf-8'),
            salt,
            iterations
        )
        return hmac.compare_digest(actual_digest, expected_digest)
    except Exception:
        return False


def normalize_user_status(raw_status):
    status = str(raw_status or 'active').strip().lower()
    if status in {'active', 'enabled'}:
        return 'active'
    if status in {'locked', 'blocked'}:
        return 'locked'
    return 'disabled'


VALID_USER_ROLES = {'admin', 'user'}


def normalize_user_role(raw_role, username=''):
    role = str(raw_role or '').strip().lower()
    if role in VALID_USER_ROLES:
        return role
    bootstrap_key = str(AUTH_BOOTSTRAP_USERNAME or '').strip().lower()
    username_key = str(username or '').strip().lower()
    if bootstrap_key and username_key == bootstrap_key:
        return 'admin'
    return 'user'


def normalize_users_payload(payload):
    if isinstance(payload, dict):
        users_raw = payload.get('users', [])
    elif isinstance(payload, list):
        users_raw = payload
    else:
        users_raw = []

    changed = not (isinstance(payload, dict) and int(payload.get('version', 0) or 0) == 1)
    users = []
    seen_usernames = set()
    now_iso = now_utc_iso()

    for item in users_raw:
        if not isinstance(item, dict):
            changed = True
            continue

        username = str(item.get('username', '')).strip()
        if not username:
            changed = True
            continue

        username_key = username.lower()
        if username_key in seen_usernames:
            changed = True
            continue
        seen_usernames.add(username_key)

        password_hash = str(item.get('passwordHash', '')).strip()
        if not password_hash and str(item.get('password', '')).strip():
            password_hash = hash_password_pbkdf2(str(item.get('password')))
            changed = True

        if not password_hash:
            changed = True
            continue

        status = normalize_user_status(item.get('status', 'active'))
        if status != str(item.get('status', 'active')).strip().lower():
            changed = True

        role = normalize_user_role(item.get('role', ''), username=username)
        if role != str(item.get('role', '')).strip().lower():
            changed = True

        created_at = str(item.get('createdAt', '')).strip() or now_iso
        updated_at = str(item.get('updatedAt', '')).strip() or created_at

        users.append({
            "username": username,
            "passwordHash": password_hash,
            "status": status,
            "role": role,
            "createdAt": created_at,
            "updatedAt": updated_at,
        })

        if 'password' in item:
            changed = True

    return {"version": 1, "users": users}, changed


def read_users_store():
    payload = read_json_file(USERS_FILE)
    normalized_payload, changed = normalize_users_payload(payload)
    if changed:
        write_json_file(USERS_FILE, normalized_payload)
    return normalized_payload


def ensure_bootstrap_user():
    if APP_AUTH_BOOTSTRAP_SYNC_MODE == 'disabled':
        return

    users_payload = read_users_store()
    users = users_payload.get('users', [])
    target_key = AUTH_BOOTSTRAP_USERNAME.lower()
    now_iso = now_utc_iso()
    existing = next((u for u in users if str(u.get('username', '')).strip().lower() == target_key), None)

    if existing is None:
        users.append({
            "username": AUTH_BOOTSTRAP_USERNAME,
            "passwordHash": hash_password_pbkdf2(AUTH_BOOTSTRAP_PASSWORD),
            "status": "active",
            "role": "admin",
            "createdAt": now_iso,
            "updatedAt": now_iso,
        })
        write_json_file(USERS_FILE, {"version": 1, "users": users})
        app.logger.info("auth_bootstrap_user_created username=%s", AUTH_BOOTSTRAP_USERNAME)
        return

    if APP_AUTH_BOOTSTRAP_SYNC_MODE == 'create_only':
        return

    needs_sync = (
        existing.get('status') != 'active'
        or existing.get('role') != 'admin'
        or not verify_password_pbkdf2(AUTH_BOOTSTRAP_PASSWORD, existing.get('passwordHash', ''))
    )
    if not needs_sync:
        return

    existing['passwordHash'] = hash_password_pbkdf2(AUTH_BOOTSTRAP_PASSWORD)
    existing['status'] = 'active'
    existing['role'] = 'admin'
    existing['updatedAt'] = now_iso
    write_json_file(USERS_FILE, {"version": 1, "users": users})
    app.logger.info("auth_bootstrap_user_synced username=%s", AUTH_BOOTSTRAP_USERNAME)


def authenticate_user(username, password):
    username_key = str(username).strip().lower()
    if not username_key:
        return False, None, "empty_username"

    users_payload = read_users_store()
    users = users_payload.get('users', [])
    user = next(
        (u for u in users if str(u.get('username', '')).strip().lower() == username_key),
        None
    )
    if user is None:
        return False, None, "user_not_found"

    status = str(user.get('status', 'disabled')).strip().lower()
    if status != 'active':
        return False, user, f"user_{status}"

    if verify_password_pbkdf2(password, user.get('passwordHash', '')):
        return True, user, "ok"
    return False, user, "bad_password"


# 初始化数据文件（首次运行自动创建）
def init_data_files():
    # 创建数据目录（如果不存在）
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    init_storage_backend()

    # 初始化用户文件（密码哈希 + 多用户）
    if not os.path.exists(USERS_FILE):
        write_json_file(USERS_FILE, {"version": 1, "users": []})

    ensure_bootstrap_user()

# 读取 JSON 文件
def read_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# 写入 JSON 文件
def write_json_file(file_path, data):
    dir_path = os.path.dirname(file_path) or '.'
    lock_path = f"{file_path}.lock"
    tmp_path = os.path.join(
        dir_path,
        f".{os.path.basename(file_path)}.tmp.{os.getpid()}.{time.time_ns()}"
    )

    lock_file = open(lock_path, 'a+', encoding='utf-8')
    try:
        # Cross-process serialization: Gunicorn workers will queue writes here.
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, file_path)

        # Best-effort directory fsync to reduce metadata loss risk on sudden crash.
        try:
            dir_fd = os.open(dir_path, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def safe_read_json_list(file_path):
    if not os.path.exists(file_path):
        return []
    try:
        payload = read_json_file(file_path)
    except Exception as exc:
        app.logger.warning("json_read_failed file=%s err=%s", file_path, exc)
        return []
    if isinstance(payload, list):
        return payload
    return []


def sqlite_connect():
    conn = sqlite3.connect(SQLITE_DB_FILE, timeout=APP_SQLITE_TIMEOUT_SEC)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_sqlite_schema(conn):
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
        """
        CREATE INDEX IF NOT EXISTS idx_notes_category_update
        ON notes (category_id, update_time DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_notes_update_time
        ON notes (update_time DESC)
        """
    )


def init_sqlite_fts(conn):
    global SQLITE_FTS_ACTIVE
    if not APP_SQLITE_ENABLE_FTS:
        SQLITE_FTS_ACTIVE = False
        return

    try:
        columns = [
            str(row[1]) for row in conn.execute("PRAGMA table_info(notes_fts)").fetchall()
        ]
        expected_columns = ['title', 'content', 'tags_json']
        if columns and columns != expected_columns:
            app.logger.warning(
                "sqlite_fts_schema_mismatch columns=%s expected=%s; recreate",
                columns,
                expected_columns,
            )
            conn.execute("DROP TRIGGER IF EXISTS notes_fts_ai")
            conn.execute("DROP TRIGGER IF EXISTS notes_fts_ad")
            conn.execute("DROP TRIGGER IF EXISTS notes_fts_au")
            conn.execute("DROP TABLE IF EXISTS notes_fts")

        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts
            USING fts5(
                title,
                content,
                tags_json,
                content='notes',
                content_rowid='rowid'
            )
            """
        )
        conn.execute(
            """
                CREATE TRIGGER IF NOT EXISTS notes_fts_ai
            AFTER INSERT ON notes
            BEGIN
                INSERT INTO notes_fts(rowid, title, content, tags_json)
                VALUES (new.rowid, new.title, new.content, new.tags_json);
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS notes_fts_ad
            AFTER DELETE ON notes
            BEGIN
                INSERT INTO notes_fts(notes_fts, rowid, title, content, tags_json)
                VALUES ('delete', old.rowid, old.title, old.content, old.tags_json);
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS notes_fts_au
            AFTER UPDATE ON notes
            BEGIN
                INSERT INTO notes_fts(notes_fts, rowid, title, content, tags_json)
                VALUES ('delete', old.rowid, old.title, old.content, old.tags_json);
                INSERT INTO notes_fts(rowid, title, content, tags_json)
                VALUES (new.rowid, new.title, new.content, new.tags_json);
            END
            """
        )

        note_count = int(conn.execute("SELECT COUNT(1) FROM notes").fetchone()[0])
        fts_count = int(conn.execute("SELECT COUNT(1) FROM notes_fts").fetchone()[0])
        if note_count != fts_count:
            conn.execute("INSERT INTO notes_fts(notes_fts) VALUES ('rebuild')")
            app.logger.info("sqlite_fts_rebuild done notes=%s fts_rows=%s", note_count, fts_count)
        SQLITE_FTS_ACTIVE = True
    except sqlite3.OperationalError as exc:
        SQLITE_FTS_ACTIVE = False
        app.logger.warning("sqlite_fts_disabled reason=%s", exc)


def normalize_category_item(raw):
    if not isinstance(raw, dict):
        return None
    name = str(raw.get('name', '')).strip()
    if not name:
        return None
    category_id = str(raw.get('id', '')).strip() or f"cate_{time.time()}_{secrets.token_hex(3)}"
    return {"id": category_id, "name": name}


def normalize_note_item(raw):
    if not isinstance(raw, dict):
        return None
    rich_content = sanitize_rich_html(raw.get('richContent', ''))
    plain_content = str(raw.get('content', '') or '').strip()
    if rich_content:
        plain_content = rich_html_to_plain_text(rich_content)
    create_time_raw = raw.get('createTime', raw.get('updateTime', time.time()))
    update_time_raw = raw.get('updateTime', create_time_raw)
    try:
        create_time = float(create_time_raw)
    except Exception:
        create_time = float(time.time())
    try:
        update_time = float(update_time_raw)
    except Exception:
        update_time = create_time

    return {
        "id": str(raw.get('id', '')).strip() or f"note_{time.time()}_{secrets.token_hex(3)}",
        "title": str(raw.get('title', '')).strip(),
        "content": plain_content,
        "richContent": rich_content,
        "categoryId": str(raw.get('categoryId', '')).strip(),
        "tags": normalize_tags(raw.get('tags')),
        "createTime": create_time,
        "updateTime": update_time,
    }


def backup_json_for_sqlite_migration():
    backup_root = os.path.join(DATA_DIR, "backup")
    os.makedirs(backup_root, exist_ok=True)
    snapshot_dir = os.path.join(
        backup_root,
        f"json-pre-sqlite-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
    copied = 0
    os.makedirs(snapshot_dir, exist_ok=True)
    for src in (CATEGORIES_FILE, NOTES_FILE):
        if not os.path.exists(src):
            continue
        shutil.copy2(src, os.path.join(snapshot_dir, os.path.basename(src)))
        copied += 1
    if copied == 0:
        try:
            os.rmdir(snapshot_dir)
        except OSError:
            pass
        return ''
    return snapshot_dir


def migrate_json_to_sqlite_if_needed():
    lock_path = f"{SQLITE_DB_FILE}.migrate.lock"
    lock_dir = os.path.dirname(lock_path) or '.'
    os.makedirs(lock_dir, exist_ok=True)

    lock_file = open(lock_path, 'a+', encoding='utf-8')
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        with sqlite_connect() as conn:
            init_sqlite_schema(conn)
            category_count = int(conn.execute("SELECT COUNT(1) FROM categories").fetchone()[0])
            note_count = int(conn.execute("SELECT COUNT(1) FROM notes").fetchone()[0])
            if category_count > 0 or note_count > 0:
                return

            raw_categories = safe_read_json_list(CATEGORIES_FILE)
            raw_notes = safe_read_json_list(NOTES_FILE)
            categories = [c for c in (normalize_category_item(x) for x in raw_categories) if c]
            notes = [n for n in (normalize_note_item(x) for x in raw_notes) if n]
            if not categories and not notes:
                return

            backup_dir = backup_json_for_sqlite_migration()
            for category in categories:
                conn.execute(
                    "INSERT OR IGNORE INTO categories (id, name) VALUES (?, ?)",
                    (category['id'], category['name'])
                )
            for note in notes:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO notes
                    (id, title, content, rich_content, category_id, tags_json, create_time, update_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        note['id'],
                        note['title'],
                        note['content'],
                        note['richContent'],
                        note['categoryId'],
                        json.dumps(note['tags'], ensure_ascii=False),
                        float(note['createTime']),
                        float(note['updateTime']),
                    ),
                )
            conn.commit()
            app.logger.info(
                "sqlite_migration_completed categories=%s notes=%s backup_dir=%s",
                len(categories),
                len(notes),
                backup_dir,
            )
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


def init_storage_backend():
    if APP_STORAGE_BACKEND == 'json':
        if not os.path.exists(NOTES_FILE):
            write_json_file(NOTES_FILE, [])
        if not os.path.exists(CATEGORIES_FILE):
            write_json_file(CATEGORIES_FILE, [])
        return

    db_dir = os.path.dirname(SQLITE_DB_FILE) or '.'
    os.makedirs(db_dir, exist_ok=True)
    with sqlite_connect() as conn:
        init_sqlite_schema(conn)
    migrate_json_to_sqlite_if_needed()
    with sqlite_connect() as conn:
        init_sqlite_fts(conn)
        conn.commit()
    app.logger.info("sqlite_search backend=%s fts_active=%s", "fts5", SQLITE_FTS_ACTIVE)


def parse_tags_json(raw_tags):
    try:
        parsed = json.loads(raw_tags or "[]")
    except Exception:
        parsed = []
    return normalize_tags(parsed)


def sqlite_note_row_to_payload(row):
    return {
        "id": row["id"],
        "title": row["title"] or "",
        "content": row["content"] or "",
        "richContent": row["rich_content"] or "",
        "categoryId": row["category_id"] or "",
        "tags": parse_tags_json(row["tags_json"]),
        "createTime": float(row["create_time"]),
        "updateTime": float(row["update_time"]),
    }


def build_fts5_query(search_key):
    tokens = re.findall(r"[0-9A-Za-z_\u4e00-\u9fff]+", str(search_key or ""))
    if not tokens:
        return ""
    return " AND ".join(f"{token}*" for token in tokens[:8])


def build_notes_query_cache_key(category_id, search_key, limit, offset):
    return (
        APP_STORAGE_BACKEND,
        bool(SQLITE_FTS_ACTIVE),
        str(category_id or 'all'),
        str(search_key or ''),
        int(limit) if limit is not None else None,
        int(offset or 0),
    )


def sweep_notes_query_cache(force=False):
    global NOTES_QUERY_CACHE_LAST_SWEEP_TS
    if APP_NOTES_QUERY_CACHE_TTL_SEC <= 0:
        return 0

    now_ts = time.time()
    with NOTES_QUERY_CACHE_LOCK:
        if not force and APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC > 0:
            if (now_ts - NOTES_QUERY_CACHE_LAST_SWEEP_TS) < APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC:
                return 0

        removed = 0
        expire_before = now_ts - APP_NOTES_QUERY_CACHE_TTL_SEC
        stale_keys = [
            key for key, payload in NOTES_QUERY_CACHE.items()
            if float(payload.get('ts', 0)) <= expire_before
        ]
        for key in stale_keys:
            NOTES_QUERY_CACHE.pop(key, None)
            removed += 1

        NOTES_QUERY_CACHE_LAST_SWEEP_TS = now_ts
        NOTES_QUERY_CACHE_STATS["sweeps"] += 1
        NOTES_QUERY_CACHE_STATS["swept_entries"] += removed
        NOTES_QUERY_CACHE_STATS["expired"] += removed
        return removed


def get_notes_query_cache(key):
    if APP_NOTES_QUERY_CACHE_TTL_SEC <= 0:
        return None
    sweep_notes_query_cache(force=False)
    now_ts = time.time()
    with NOTES_QUERY_CACHE_LOCK:
        cached = NOTES_QUERY_CACHE.get(key)
        if not cached:
            NOTES_QUERY_CACHE_STATS["misses"] += 1
            return None
        if (now_ts - float(cached.get('ts', 0))) > APP_NOTES_QUERY_CACHE_TTL_SEC:
            NOTES_QUERY_CACHE.pop(key, None)
            NOTES_QUERY_CACHE_STATS["misses"] += 1
            NOTES_QUERY_CACHE_STATS["expired"] += 1
            return None
        NOTES_QUERY_CACHE.move_to_end(key)
        NOTES_QUERY_CACHE_STATS["hits"] += 1
        return copy.deepcopy(cached.get('value', []))


def set_notes_query_cache(key, value):
    if APP_NOTES_QUERY_CACHE_TTL_SEC <= 0:
        return
    sweep_notes_query_cache(force=False)
    with NOTES_QUERY_CACHE_LOCK:
        if key in NOTES_QUERY_CACHE:
            NOTES_QUERY_CACHE.pop(key, None)
        while len(NOTES_QUERY_CACHE) >= APP_NOTES_QUERY_CACHE_MAX_ENTRIES:
            NOTES_QUERY_CACHE.popitem(last=False)
            NOTES_QUERY_CACHE_STATS["evictions"] += 1
        NOTES_QUERY_CACHE[key] = {
            'ts': time.time(),
            'value': copy.deepcopy(value),
        }
        NOTES_QUERY_CACHE_STATS["stores"] += 1


def clear_notes_query_cache():
    with NOTES_QUERY_CACHE_LOCK:
        cache_size = len(NOTES_QUERY_CACHE)
        NOTES_QUERY_CACHE.clear()
        NOTES_QUERY_CACHE_STATS["invalidations"] += 1
        NOTES_QUERY_CACHE_STATS["invalidated_entries"] += cache_size


def reset_notes_query_cache_stats():
    global NOTES_QUERY_CACHE_LAST_SWEEP_TS
    with NOTES_QUERY_CACHE_LOCK:
        for key in NOTES_QUERY_CACHE_STATS.keys():
            NOTES_QUERY_CACHE_STATS[key] = 0
        NOTES_QUERY_CACHE_LAST_SWEEP_TS = 0.0


def get_notes_query_cache_snapshot():
    with NOTES_QUERY_CACHE_LOCK:
        hits = int(NOTES_QUERY_CACHE_STATS["hits"])
        misses = int(NOTES_QUERY_CACHE_STATS["misses"])
        total = hits + misses
        hit_rate = (hits / total) if total > 0 else 0.0
        return {
            "enabled": APP_NOTES_QUERY_CACHE_TTL_SEC > 0,
            "ttlSec": APP_NOTES_QUERY_CACHE_TTL_SEC,
            "maxEntries": APP_NOTES_QUERY_CACHE_MAX_ENTRIES,
            "sweepIntervalSec": APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC,
            "size": len(NOTES_QUERY_CACHE),
            "hits": hits,
            "misses": misses,
            "stores": int(NOTES_QUERY_CACHE_STATS["stores"]),
            "evictions": int(NOTES_QUERY_CACHE_STATS["evictions"]),
            "expired": int(NOTES_QUERY_CACHE_STATS["expired"]),
            "sweeps": int(NOTES_QUERY_CACHE_STATS["sweeps"]),
            "sweptEntries": int(NOTES_QUERY_CACHE_STATS["swept_entries"]),
            "invalidations": int(NOTES_QUERY_CACHE_STATS["invalidations"]),
            "invalidatedEntries": int(NOTES_QUERY_CACHE_STATS["invalidated_entries"]),
            "hitRate": round(hit_rate, 4),
        }


def storage_get_categories():
    if APP_STORAGE_BACKEND == 'json':
        return read_json_file(CATEGORIES_FILE)

    with sqlite_connect() as conn:
        rows = conn.execute(
            "SELECT id, name FROM categories ORDER BY rowid ASC"
        ).fetchall()
    return [{"id": row["id"], "name": row["name"]} for row in rows]


def storage_add_category(name):
    category_name = str(name or '').strip()
    if APP_STORAGE_BACKEND == 'json':
        categories = read_json_file(CATEGORIES_FILE)
        if any(c.get('name') == category_name for c in categories):
            return None
        new_category = {
            "id": f"cate_{datetime.now().timestamp()}",
            "name": category_name
        }
        categories.append(new_category)
        write_json_file(CATEGORIES_FILE, categories)
        clear_notes_query_cache()
        return new_category

    new_category = {
        "id": f"cate_{datetime.now().timestamp()}",
        "name": category_name
    }
    try:
        with sqlite_connect() as conn:
            conn.execute(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                (new_category["id"], new_category["name"])
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return None
    clear_notes_query_cache()
    return new_category


def storage_get_notes(category_id='all', search_key='', limit=None, offset=0):
    cache_key = build_notes_query_cache_key(category_id, search_key, limit, offset)
    cached_notes = get_notes_query_cache(cache_key)
    if cached_notes is not None:
        return cached_notes

    if APP_STORAGE_BACKEND == 'json':
        notes = read_json_file(NOTES_FILE)
        if category_id != 'all':
            notes = [n for n in notes if n.get('categoryId') == category_id]
        if search_key:
            lowered = str(search_key).lower()
            notes = [
                n for n in notes
                if lowered in n.get('title', '').lower()
                or lowered in n.get('content', '').lower()
                or lowered in " ".join(n.get('tags', [])).lower()
            ]
        notes.sort(
            key=lambda n: float(n.get('updateTime') or n.get('createTime') or 0),
            reverse=True
        )
        if offset > 0:
            notes = notes[int(offset):]
        if limit is not None:
            notes = notes[:int(limit)]
        set_notes_query_cache(cache_key, notes)
        return notes

    sql_parts = [
        """
        SELECT id, title, content, rich_content, category_id, tags_json, create_time, update_time
        FROM notes
        WHERE 1=1
        """
    ]
    params = []
    if category_id != 'all':
        sql_parts.append("AND category_id = ?")
        params.append(category_id)
    if search_key:
        if SQLITE_FTS_ACTIVE:
            fts_query = build_fts5_query(search_key)
            if fts_query:
                sql_parts.append(
                    "AND rowid IN (SELECT rowid FROM notes_fts WHERE notes_fts MATCH ?)"
                )
                params.append(fts_query)
            else:
                like_value = f"%{str(search_key).lower()}%"
                sql_parts.append("AND (lower(title) LIKE ? OR lower(content) LIKE ? OR lower(tags_json) LIKE ?)")
                params.extend([like_value, like_value, like_value])
        else:
            like_value = f"%{str(search_key).lower()}%"
            sql_parts.append("AND (lower(title) LIKE ? OR lower(content) LIKE ? OR lower(tags_json) LIKE ?)")
            params.extend([like_value, like_value, like_value])
    sql_parts.append("ORDER BY update_time DESC")
    if limit is not None:
        sql_parts.append("LIMIT ?")
        params.append(int(limit))
        if offset > 0:
            sql_parts.append("OFFSET ?")
            params.append(int(offset))
    elif offset > 0:
        sql_parts.append("LIMIT -1 OFFSET ?")
        params.append(int(offset))

    with sqlite_connect() as conn:
        rows = conn.execute(" ".join(sql_parts), params).fetchall()
    notes = [sqlite_note_row_to_payload(row) for row in rows]
    set_notes_query_cache(cache_key, notes)
    return notes


def parse_notes_limit_arg(raw_limit):
    text = str(raw_limit or '').strip()
    if not text:
        return None
    try:
        value = int(text)
    except ValueError as exc:
        raise ValueError("limit must be an integer") from exc
    if value <= 0:
        raise ValueError("limit must be greater than 0")
    return min(value, APP_NOTES_LIST_MAX_LIMIT)


def parse_notes_offset_arg(raw_offset):
    text = str(raw_offset or '').strip()
    if not text:
        return 0
    try:
        value = int(text)
    except ValueError as exc:
        raise ValueError("offset must be an integer") from exc
    if value < 0:
        raise ValueError("offset must be greater than or equal to 0")
    return value


def storage_get_note_by_id(note_id):
    if APP_STORAGE_BACKEND == 'json':
        notes = read_json_file(NOTES_FILE)
        return next((n for n in notes if n.get('id') == note_id), None)

    with sqlite_connect() as conn:
        row = conn.execute(
            """
            SELECT id, title, content, rich_content, category_id, tags_json, create_time, update_time
            FROM notes
            WHERE id = ?
            """,
            (note_id,),
        ).fetchone()
    if not row:
        return None
    return sqlite_note_row_to_payload(row)


def storage_update_note(note_id, payload):
    if APP_STORAGE_BACKEND == 'json':
        notes = read_json_file(NOTES_FILE)
        index = next((i for i, n in enumerate(notes) if n.get('id') == note_id), None)
        if index is None:
            return False
        notes[index]['title'] = payload['title']
        notes[index]['content'] = payload['content']
        notes[index]['richContent'] = payload['richContent']
        notes[index]['categoryId'] = payload['categoryId']
        notes[index]['tags'] = payload['tags']
        notes[index]['updateTime'] = float(payload['updateTime'])
        write_json_file(NOTES_FILE, notes)
        clear_notes_query_cache()
        return True

    with sqlite_connect() as conn:
        cursor = conn.execute(
            """
            UPDATE notes
            SET title = ?, content = ?, rich_content = ?, category_id = ?, tags_json = ?, update_time = ?
            WHERE id = ?
            """,
            (
                payload['title'],
                payload['content'],
                payload['richContent'],
                payload['categoryId'],
                json.dumps(payload['tags'], ensure_ascii=False),
                float(payload['updateTime']),
                note_id,
            ),
        )
        conn.commit()
        updated = cursor.rowcount > 0
    if updated:
        clear_notes_query_cache()
    return updated


def storage_create_note(payload):
    if APP_STORAGE_BACKEND == 'json':
        notes = read_json_file(NOTES_FILE)
        notes.append(payload)
        write_json_file(NOTES_FILE, notes)
        clear_notes_query_cache()
        return payload['id']

    with sqlite_connect() as conn:
        conn.execute(
            """
            INSERT INTO notes
            (id, title, content, rich_content, category_id, tags_json, create_time, update_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload['id'],
                payload['title'],
                payload['content'],
                payload['richContent'],
                payload['categoryId'],
                json.dumps(payload['tags'], ensure_ascii=False),
                float(payload['createTime']),
                float(payload['updateTime']),
            ),
        )
        conn.commit()
    clear_notes_query_cache()
    return payload['id']


def storage_delete_note(note_id):
    if APP_STORAGE_BACKEND == 'json':
        notes = read_json_file(NOTES_FILE)
        new_notes = [n for n in notes if n.get('id') != note_id]
        deleted = len(new_notes) != len(notes)
        if deleted:
            write_json_file(NOTES_FILE, new_notes)
            clear_notes_query_cache()
        return deleted

    with sqlite_connect() as conn:
        cursor = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
    if deleted:
        clear_notes_query_cache()
    return deleted


def storage_health_check():
    if APP_STORAGE_BACKEND == 'json':
        read_json_file(CATEGORIES_FILE)
        read_json_file(NOTES_FILE)
        return

    with sqlite_connect() as conn:
        init_sqlite_schema(conn)
        conn.execute("SELECT 1").fetchone()


def is_logged_in():
    return bool(session.get('logged_in'))


def _read_session_last_activity_ts():
    try:
        return float(session.get('last_activity_ts', 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def touch_session_activity(now_ts=None):
    if not is_logged_in():
        return
    if now_ts is None:
        now_ts = time.time()
    session['last_activity_ts'] = float(now_ts)


def expire_session_if_idle(now_ts=None):
    if not is_logged_in():
        return False
    if now_ts is None:
        now_ts = time.time()

    last_activity_ts = _read_session_last_activity_ts()
    if last_activity_ts <= 0:
        touch_session_activity(now_ts)
        return False

    idle_seconds = now_ts - last_activity_ts
    if idle_seconds < APP_SESSION_IDLE_TIMEOUT_SEC:
        touch_session_activity(now_ts)
        return False

    username = str(session.get('username', '')).strip()
    role = str(session.get('role', '')).strip()
    audit_log(
        logging.INFO,
        "auth_session_idle_timeout",
        username=username,
        role=role,
        idle_sec=int(max(0, idle_seconds)),
        timeout_sec=APP_SESSION_IDLE_TIMEOUT_SEC,
    )
    session.clear()
    return True


def auth_required_response():
    return jsonify({"error": "未登录或登录已过期，请先登录"}), 401


def get_current_user_role():
    if not is_logged_in():
        return 'anonymous'

    role = str(session.get('role', '')).strip().lower()
    if role in VALID_USER_ROLES:
        return role

    username = str(session.get('username', '')).strip().lower()
    if not username:
        return 'user'

    try:
        users_payload = read_users_store()
        user = next(
            (u for u in users_payload.get('users', [])
             if str(u.get('username', '')).strip().lower() == username),
            None
        )
        role = normalize_user_role((user or {}).get('role', ''), username=username)
    except Exception:
        role = 'user'

    session['role'] = role
    return role


def is_current_user_admin():
    return get_current_user_role() == 'admin'


def get_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        first = forwarded_for.split(',')[0].strip()
        if first:
            return first
    return request.remote_addr or 'unknown'


def get_rate_limit_redis_client():
    global LOGIN_RATE_REDIS_CLIENT
    if APP_LOGIN_RATE_LIMIT_BACKEND != 'redis':
        return None
    if LOGIN_RATE_REDIS_CLIENT is None:
        LOGIN_RATE_REDIS_CLIENT = redis.Redis.from_url(
            APP_REDIS_URL,
            decode_responses=True,
            socket_timeout=APP_REDIS_SOCKET_TIMEOUT_SEC,
        )
    return LOGIN_RATE_REDIS_CLIENT


def get_rate_limit_ip_token(ip):
    return hashlib.sha256(ip.encode('utf-8')).hexdigest()[:32]


def get_rate_limit_keys(ip):
    ip_token = get_rate_limit_ip_token(ip)
    fail_key = f"{APP_LOGIN_RATE_LIMIT_KEY_PREFIX}:fail:{ip_token}"
    block_key = f"{APP_LOGIN_RATE_LIMIT_KEY_PREFIX}:block:{ip_token}"
    return fail_key, block_key


def get_login_retry_after_redis(ip):
    client = get_rate_limit_redis_client()
    fail_key, block_key = get_rate_limit_keys(ip)
    ttl = client.ttl(block_key)
    if ttl is None or ttl < 0:
        return 0
    return int(ttl)


def register_login_failure_redis(ip):
    client = get_rate_limit_redis_client()
    fail_key, block_key = get_rate_limit_keys(ip)

    block_ttl = client.ttl(block_key)
    if block_ttl is not None and block_ttl > 0:
        return {"blocked": True, "retry_after": int(block_ttl), "attempts": APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS}

    pipe = client.pipeline()
    pipe.incr(fail_key)
    pipe.ttl(fail_key)
    attempts, ttl = pipe.execute()
    attempts = int(attempts)

    if ttl is None or int(ttl) < 0:
        client.expire(fail_key, APP_LOGIN_RATE_LIMIT_WINDOW_SEC)

    if attempts >= APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        pipe = client.pipeline()
        pipe.setex(block_key, APP_LOGIN_RATE_LIMIT_BLOCK_SEC, '1')
        pipe.delete(fail_key)
        pipe.execute()
        return {
            "blocked": True,
            "retry_after": APP_LOGIN_RATE_LIMIT_BLOCK_SEC,
            "attempts": attempts,
        }

    return {"blocked": False, "retry_after": 0, "attempts": attempts}


def clear_login_failures_redis(ip):
    client = get_rate_limit_redis_client()
    fail_key, block_key = get_rate_limit_keys(ip)
    client.delete(fail_key, block_key)


def _cleanup_rate_state(now_ts):
    global LOGIN_RATE_LAST_CLEANUP
    if now_ts - LOGIN_RATE_LAST_CLEANUP < LOGIN_RATE_STATE_CLEANUP_INTERVAL_SEC:
        return

    stale_after = APP_LOGIN_RATE_LIMIT_WINDOW_SEC + APP_LOGIN_RATE_LIMIT_BLOCK_SEC + 60
    remove_keys = []
    for ip, state in LOGIN_RATE_STATE.items():
        blocked_until = state.get('blocked_until', 0)
        last_seen = state.get('last_seen', 0)
        if blocked_until <= now_ts and (now_ts - last_seen) > stale_after:
            remove_keys.append(ip)
    for ip in remove_keys:
        LOGIN_RATE_STATE.pop(ip, None)
    LOGIN_RATE_LAST_CLEANUP = now_ts


def get_login_retry_after(ip):
    if APP_LOGIN_RATE_LIMIT_BACKEND == 'redis':
        return get_login_retry_after_redis(ip)

    now_ts = time.time()
    with LOGIN_RATE_LOCK:
        _cleanup_rate_state(now_ts)
        state = LOGIN_RATE_STATE.get(ip)
        if not state:
            return 0
        blocked_until = state.get('blocked_until', 0)
        if blocked_until <= now_ts:
            return 0
        return int(blocked_until - now_ts) + 1


def register_login_failure(ip):
    if APP_LOGIN_RATE_LIMIT_BACKEND == 'redis':
        return register_login_failure_redis(ip)

    now_ts = time.time()
    with LOGIN_RATE_LOCK:
        _cleanup_rate_state(now_ts)
        state = LOGIN_RATE_STATE.setdefault(ip, {"fails": [], "blocked_until": 0, "last_seen": now_ts})
        state["last_seen"] = now_ts

        if state.get("blocked_until", 0) > now_ts:
            retry_after = int(state["blocked_until"] - now_ts) + 1
            return {"blocked": True, "retry_after": retry_after, "attempts": len(state["fails"])}

        valid_after = now_ts - APP_LOGIN_RATE_LIMIT_WINDOW_SEC
        state["fails"] = [ts for ts in state["fails"] if ts >= valid_after]
        state["fails"].append(now_ts)
        attempts = len(state["fails"])

        if attempts >= APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
            state["blocked_until"] = now_ts + APP_LOGIN_RATE_LIMIT_BLOCK_SEC
            state["fails"] = []
            return {
                "blocked": True,
                "retry_after": APP_LOGIN_RATE_LIMIT_BLOCK_SEC,
                "attempts": attempts
            }

        return {"blocked": False, "retry_after": 0, "attempts": attempts}


def clear_login_failures(ip):
    if APP_LOGIN_RATE_LIMIT_BACKEND == 'redis':
        clear_login_failures_redis(ip)
        return

    with LOGIN_RATE_LOCK:
        LOGIN_RATE_STATE.pop(ip, None)


def verify_rate_limit_backend():
    if APP_LOGIN_RATE_LIMIT_BACKEND != 'redis':
        return
    client = get_rate_limit_redis_client()
    try:
        client.ping()
    except Exception as exc:
        raise RuntimeError(f"Redis 限速后端不可用: {exc}")


def is_origin_allowed(origin):
    if not origin:
        return True
    if origin in ALLOWED_CORS_ORIGINS:
        return True
    expected_origin = f"{request.scheme}://{request.host}"
    return origin == expected_origin


verify_rate_limit_backend()


@app.before_request
def protect_routes():
    g.request_start = time.time()
    g.request_origin = request.headers.get('Origin')
    g.request_id = normalize_request_id(request.headers.get(REQUEST_ID_HEADER, ''))

    if g.request_origin and not is_origin_allowed(g.request_origin):
        audit_log(
            logging.WARNING,
            "cors_blocked",
            origin=g.request_origin
        )
        return jsonify({"error": "跨域来源不被允许"}), 403

    if request.method == 'OPTIONS':
        return None

    path = request.path or ''
    if expire_session_if_idle():
        if path.startswith('/api/'):
            return auth_required_response()
        return redirect('/login')

    open_api_paths = {
        '/api/auth/login',
        '/api/auth/status',
    }

    if path.startswith('/api/'):
        if path in open_api_paths:
            return None
        if not is_logged_in():
            return auth_required_response()
        if path.startswith('/api/admin/') and not is_current_user_admin():
            audit_log(logging.WARNING, "admin_access_denied")
            return jsonify({"error": "需要管理员权限"}), 403
        return None

    if path in {'/', '/index.html', '/static/index.html'} and not is_logged_in():
        return redirect('/login')

    if path == '/login' and is_logged_in():
        return redirect('/')
    return None


# ------------------- 接口：鉴权 -------------------
@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    return jsonify({
        "loggedIn": is_logged_in(),
        "username": session.get('username', '') if is_logged_in() else '',
        "role": get_current_user_role() if is_logged_in() else '',
    })


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    client_ip = get_client_ip()

    try:
        retry_after = get_login_retry_after(client_ip)
    except Exception as exc:
        app.logger.exception(
            "auth_login_rate_backend_error request_id=%s stage=check backend=%s ip=%s err=%s",
            get_request_id(),
            APP_LOGIN_RATE_LIMIT_BACKEND,
            client_ip,
            exc,
        )
        return jsonify({"error": "登录服务暂不可用，请稍后再试"}), 503

    if retry_after > 0:
        audit_log(
            logging.WARNING,
            "auth_login_rate_limited",
            username=username,
            retry_after=retry_after
        )
        return jsonify({"error": "尝试次数过多，请稍后再试", "retryAfter": retry_after}), 429

    try:
        auth_ok, auth_user, auth_reason = authenticate_user(username, password)
    except Exception as exc:
        app.logger.exception(
            "auth_login_user_store_error request_id=%s stage=auth ip=%s err=%s",
            get_request_id(),
            client_ip,
            exc,
        )
        return jsonify({"error": "登录服务暂不可用，请稍后再试"}), 503

    if auth_ok:
        session['logged_in'] = True
        session['username'] = str(auth_user.get('username', username))
        session['role'] = normalize_user_role(
            auth_user.get('role', ''),
            username=session['username'],
        )
        session['last_activity_ts'] = time.time()
        try:
            clear_login_failures(client_ip)
        except Exception as exc:
            app.logger.exception(
                "auth_login_rate_backend_error request_id=%s stage=clear backend=%s ip=%s err=%s",
                get_request_id(),
                APP_LOGIN_RATE_LIMIT_BACKEND,
                client_ip,
                exc,
            )
        audit_log(
            logging.INFO,
            "auth_login_success",
            username=session['username'],
            role=session['role'],
        )
        return jsonify({
            "success": True,
            "username": session['username'],
            "role": session['role'],
        }), 200

    try:
        failed = register_login_failure(client_ip)
    except Exception as exc:
        app.logger.exception(
            "auth_login_rate_backend_error request_id=%s stage=register backend=%s ip=%s err=%s",
            get_request_id(),
            APP_LOGIN_RATE_LIMIT_BACKEND,
            client_ip,
            exc,
        )
        return jsonify({"error": "登录服务暂不可用，请稍后再试"}), 503

    if failed["blocked"]:
        audit_log(
            logging.WARNING,
            "auth_login_blocked",
            username=username,
            attempts=failed["attempts"],
            retry_after=failed["retry_after"]
        )
        return jsonify({"error": "尝试次数过多，请稍后再试", "retryAfter": failed["retry_after"]}), 429

    audit_log(
        logging.WARNING,
        "auth_login_failed",
        username=username,
        attempts=failed["attempts"],
        reason=auth_reason
    )
    return jsonify({"error": "用户名或密码错误"}), 401


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    username = session.get('username', '')
    audit_log(
        logging.INFO,
        "auth_logout",
        actor=(str(username).strip() or 'anonymous'),
        username=username
    )
    session.clear()
    return jsonify({"success": True}), 200


@app.route('/healthz', methods=['GET'])
def healthz():
    try:
        storage_health_check()
        read_users_store()
    except Exception as exc:
        app.logger.exception("healthz_failed reason=%s", exc)
        return jsonify({"status": "degraded"}), 503

    return jsonify({"status": "ok"}), 200


@app.route('/api/admin/healthz/internal', methods=['GET'])
def healthz_internal():
    try:
        storage_health_check()
        users_payload = read_users_store()
    except Exception as exc:
        app.logger.exception("healthz_internal_failed reason=%s", exc)
        return jsonify({
            "status": "degraded",
            "env": APP_ENV,
            "uptimeSec": int(time.time() - APP_START_TS),
            "error": str(exc),
        }), 503

    return jsonify({
        "status": "ok",
        "env": APP_ENV,
        "uptimeSec": int(time.time() - APP_START_TS),
        "storageBackend": APP_STORAGE_BACKEND,
        "authStore": {
            "type": "users.json",
            "users": len(users_payload.get('users', [])),
            "bootstrapSyncMode": APP_AUTH_BOOTSTRAP_SYNC_MODE,
        },
        "notesCache": get_notes_query_cache_snapshot(),
    }), 200


@app.route('/api/admin/cache/notes', methods=['GET'])
def get_notes_cache_stats():
    return jsonify({
        "success": True,
        "notesCache": get_notes_query_cache_snapshot(),
    }), 200


@app.route('/api/admin/cache/notes/clear', methods=['POST'])
def clear_notes_cache():
    data = request.get_json(silent=True) or {}
    reset_stats = bool(data.get('resetStats', False))

    before = get_notes_query_cache_snapshot()
    clear_notes_query_cache()
    if reset_stats:
        reset_notes_query_cache_stats()
    after = get_notes_query_cache_snapshot()

    audit_log(
        logging.INFO,
        "notes_cache_admin_clear",
        reset_stats=reset_stats,
        before_size=before.get("size"),
        after_size=after.get("size"),
        before_hits=before.get("hits"),
        after_hits=after.get("hits"),
    )
    return jsonify({
        "success": True,
        "resetStats": reset_stats,
        "before": before,
        "after": after,
    }), 200


@app.route('/api/admin/cache/notes/sweep', methods=['POST'])
def sweep_notes_cache():
    before = get_notes_query_cache_snapshot()
    removed = sweep_notes_query_cache(force=True)
    after = get_notes_query_cache_snapshot()
    audit_log(
        logging.INFO,
        "notes_cache_admin_sweep",
        removed=removed,
        before_size=before.get("size"),
        after_size=after.get("size"),
    )
    return jsonify({
        "success": True,
        "removed": int(removed),
        "before": before,
        "after": after,
    }), 200

# ------------------- 接口：分类管理 -------------------
# 获取所有分类
@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = storage_get_categories()
    return jsonify(categories)

# 添加分类
@app.route('/api/categories', methods=['POST'])
def add_category():
    data = request.get_json()
    if not data or not data.get('name'):
        audit_log(logging.WARNING, "category_add_invalid_payload")
        return jsonify({"error": "分类名称不能为空"}), 400

    new_category = storage_add_category(data.get('name'))
    if new_category is None:
        audit_log(
            logging.WARNING,
            "category_add_conflict",
            category_name=str(data.get('name', '')).strip()
        )
        return jsonify({"error": "分类已存在"}), 400

    audit_log(
        logging.INFO,
        "category_add_success",
        category_id=new_category.get('id'),
        category_name=new_category.get('name')
    )
    return jsonify(new_category), 201

# ------------------- 接口：笔记管理 -------------------
# 获取所有笔记（支持分类/搜索筛选）
@app.route('/api/notes', methods=['GET'])
def get_notes():
    # 获取筛选参数
    category_id = request.args.get('category_id', 'all')
    search_key = request.args.get('search', '').lower()
    try:
        limit = parse_notes_limit_arg(request.args.get('limit', ''))
        offset = parse_notes_offset_arg(request.args.get('offset', ''))
    except ValueError:
        return jsonify({
            "error": (
                f"分页参数无效：limit 必须是 1 到 {APP_NOTES_LIST_MAX_LIMIT} 的整数，"
                "offset 必须是大于等于 0 的整数"
            )
        }), 400
    notes = storage_get_notes(
        category_id=category_id,
        search_key=search_key,
        limit=limit,
        offset=offset
    )
    return jsonify(notes)

# 添加/编辑笔记
@app.route('/api/notes', methods=['POST'])
def save_note():
    data = request.get_json()
    if not data:
        audit_log(logging.WARNING, "note_save_invalid_payload")
        return jsonify({"error": "请求数据不能为空"}), 400

    rich_preview = rich_html_to_plain_text(data.get("richContent", ""))
    if not data.get('title') and not data.get('content') and not rich_preview:
        audit_log(logging.WARNING, "note_save_empty_content")
        return jsonify({"error": "标题和内容不能都为空"}), 400
    
    note_id = data.get('id')

    if note_id:
        current_note = storage_get_note_by_id(note_id)
        if current_note is None:
            audit_log(logging.WARNING, "note_update_not_found", note_id=note_id)
            return jsonify({"error": "笔记不存在"}), 404
        payload = build_note_payload(data, current_note)
        payload['updateTime'] = datetime.now().timestamp()
        ok = storage_update_note(note_id, payload)
        if not ok:
            audit_log(logging.WARNING, "note_update_not_found", note_id=note_id)
            return jsonify({"error": "笔记不存在"}), 404
        audit_log(
            logging.INFO,
            "note_update_success",
            note_id=note_id,
            category_id=payload.get('categoryId'),
            title_len=len(str(payload.get('title', ''))),
            tags_count=len(payload.get('tags') or [])
        )
        return jsonify({"success": True, "noteId": note_id}), 200
    else:
        # 创建新笔记
        payload = build_note_payload(data)
        new_note = {
            "id": f"note_{datetime.now().timestamp()}",
            "title": payload['title'],
            "content": payload['content'],
            "richContent": payload['richContent'],
            "categoryId": payload['categoryId'],
            "tags": payload['tags'],
            "createTime": datetime.now().timestamp(),
            "updateTime": datetime.now().timestamp()
        }
        storage_create_note(new_note)
        audit_log(
            logging.INFO,
            "note_create_success",
            note_id=new_note['id'],
            category_id=new_note.get('categoryId'),
            title_len=len(str(new_note.get('title', ''))),
            tags_count=len(new_note.get('tags') or [])
        )
        return jsonify({"success": True, "noteId": new_note['id']}), 201

# 删除笔记
@app.route('/api/notes/<note_id>', methods=['DELETE'])
def delete_note(note_id):
    deleted = storage_delete_note(note_id)
    audit_log(
        logging.INFO,
        "note_delete",
        note_id=note_id,
        deleted=bool(deleted)
    )
    return jsonify({"success": True})

# 初始化数据文件
init_data_files()

# 新增路由：访问 / 或 /index.html 直接返回前端页面
@app.route('/')
@app.route('/index.html')
def serve_index():
    return app.send_static_file('index.html')


@app.route('/login')
def serve_login():
    return app.send_static_file('login.html')

# 允许跨域（前端和后端同端口，可省略，仅作兼容）
@app.after_request
def add_cors_headers(response):
    origin = getattr(g, 'request_origin', request.headers.get('Origin'))
    if origin and is_origin_allowed(origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = build_vary_header(response.headers.get('Vary'), 'Origin')
        if APP_CORS_ALLOW_CREDENTIALS:
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = f'Content-Type, {REQUEST_ID_HEADER}'
    response.headers[REQUEST_ID_HEADER] = get_request_id()

    start = getattr(g, 'request_start', None)
    duration_ms = int((time.time() - start) * 1000) if start else -1
    app.logger.info(
        "request request_id=%s method=%s path=%s status=%s duration_ms=%s ip=%s actor=%s",
        get_request_id(),
        request.method,
        request.path,
        response.status_code,
        duration_ms,
        get_client_ip(),
        get_request_actor()
    )
    return response

if __name__ == '__main__':
    # 生产默认关闭 debug，可通过 FLASK_DEBUG=1 显式开启
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    port = int(os.getenv('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=debug)
