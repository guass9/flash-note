# Gunicorn + systemd (Minimal Migration)

## 1) Install dependencies

```bash
cd /root/flash-note
python3 -m pip install -r requirements.txt
```

## 2) Prepare environment file

```bash
cp /root/flash-note/.env.example /root/flash-note/.env
```

For production, set at least:
- `APP_ENV=prod`
- `APP_SECRET_KEY=...`
- `APP_LOGIN_USERNAME=...`
- `APP_LOGIN_PASSWORD=...`
- `SESSION_COOKIE_SECURE=1` (when using HTTPS)

Security defaults:
- `SESSION_COOKIE_SAMESITE=Lax` (or `Strict` / `None`)
- `APP_SESSION_IDLE_TIMEOUT_SEC=3600` (1 hour no interaction auto logout)
- `APP_CORS_ALLOW_ORIGINS=` keeps CORS same-origin only
- set `APP_CORS_ALLOW_ORIGINS=https://your.domain` only when cross-origin is required
- storage backend defaults to `sqlite` (`APP_STORAGE_BACKEND=sqlite`)
- SQLite DB file: `APP_SQLITE_DB_FILE=/root/flash-note/data/flash_note.db`
- SQLite timeout: `APP_SQLITE_TIMEOUT_SEC=5.0`
- SQLite full-text search (FTS5): `APP_SQLITE_ENABLE_FTS=1` (auto-fallback to LIKE when unavailable)
- SQLite optimize task options:
  - `APP_SQLITE_OPTIMIZE_WITH_ANALYZE=0` (`1` means run `ANALYZE` together)
  - `APP_SQLITE_OPTIMIZE_BUSY_TIMEOUT_MS=5000`
  - `APP_SQLITE_VACUUM_ENABLED=0` (`1` means allow threshold-based VACUUM when running with `--with-vacuum`)
  - `APP_SQLITE_VACUUM_MIN_DB_SIZE_MB=128`
  - `APP_SQLITE_VACUUM_MIN_RECLAIM_MB=16`
  - `APP_SQLITE_VACUUM_FRAGMENTATION_RATIO_THRESHOLD=0.20`
- notes query cache options (backend in-memory):
  - `APP_NOTES_QUERY_CACHE_TTL_SEC=8` (`0` to disable)
  - `APP_NOTES_QUERY_CACHE_MAX_ENTRIES=256`
  - `APP_NOTES_QUERY_CACHE_SWEEP_INTERVAL_SEC=60` (`0` means only force sweep)
  - admin APIs:
    - `GET /api/admin/cache/notes`
    - `POST /api/admin/cache/notes/clear` (`{"resetStats":true}` optional)
    - `POST /api/admin/cache/notes/sweep` (force remove expired entries)
- notes list API max limit cap: `APP_NOTES_LIST_MAX_LIMIT=200`
  - API pagination params: `GET /api/notes?limit=<n>&offset=<m>`
- backup dir: `APP_BACKUP_DIR=/root/flash-note/backups`
- backup retention: `APP_BACKUP_RETAIN_DAYS=30` + `APP_BACKUP_RETAIN_COUNT=30`
- include redacted `.env` in backups: `APP_BACKUP_INCLUDE_ENV=1`
- data lifecycle defaults (safe/report-only):
  - `APP_LIFECYCLE_APPLY=0` (report-only; set `1` to allow archive execution)
  - `APP_LIFECYCLE_ARCHIVE_DAYS=365`
  - `APP_LIFECYCLE_ARCHIVE_BATCH_SIZE=500`
  - `APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0` (set `1` only after archive verification)
  - `APP_LIFECYCLE_ARCHIVE_DIR=/root/flash-note/data/archive`
  - `APP_LIFECYCLE_ARCHIVE_RETAIN_DAYS=365`
  - `APP_LIFECYCLE_ARCHIVE_RETAIN_COUNT=24`
  - `APP_LIFECYCLE_DATA_WARN_MB=2048`
  - `APP_LIFECYCLE_BACKUP_WARN_MB=4096`
- login anti-bruteforce defaults: `APP_LOGIN_RATE_LIMIT_MAX_ATTEMPTS=8` in `300s`, block `600s`
- login rate-limit backend defaults to `memory` (per worker)
- auth store: `/root/flash-note/data/users.json` (password hash only, no plaintext)
- bootstrap account comes from `APP_LOGIN_USERNAME` / `APP_LOGIN_PASSWORD`
- bootstrap sync mode: `APP_AUTH_BOOTSTRAP_SYNC_MODE`
  - `sync`: startup always syncs `APP_LOGIN_*` to bootstrap user
  - `create_only`: only create missing bootstrap user (recommended)
  - `disabled`: do not auto-manage bootstrap user
- password hashing iterations: `APP_PASSWORD_HASH_ITERATIONS` (default `210000`)

Enable global login rate limit (Redis, optional):
- set `APP_LOGIN_RATE_LIMIT_BACKEND=redis`
- set `APP_REDIS_URL=redis://127.0.0.1:6379/0` (adjust host/db as needed)
- optional tuning:
  - `APP_LOGIN_RATE_LIMIT_KEY_PREFIX=shunnian:login_rl`
  - `APP_REDIS_SOCKET_TIMEOUT_SEC=1.0`
- when `APP_LOGIN_RATE_LIMIT_BACKEND=redis`, service startup will fail fast if Redis is unreachable

## 3) Install and start systemd service

```bash
cp /root/flash-note/deploy/systemd/flash-note.service /etc/systemd/system/flash-note.service
systemctl daemon-reload
systemctl enable --now flash-note.service
```

## 3.5) Enable log rotation (recommended)

```bash
cp /root/flash-note/deploy/logrotate/flash-note.conf /etc/logrotate.d/flash-note
logrotate -d /etc/logrotate.d/flash-note
```

## 3.8) Nginx + TLS reverse proxy (recommended for production)

```bash
# 1) install nginx
dnf install -y nginx

# 2) install nginx vhost config
mkdir -p /etc/nginx/ssl
cp /root/flash-note/deploy/nginx/flash-note.conf /etc/nginx/conf.d/flash-note.conf

# 3) create certificate (self-signed example)
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout /etc/nginx/ssl/flash-note.key \
  -out /etc/nginx/ssl/flash-note.crt \
  -subj "/CN=flash-note.local"

# 4) tighten gunicorn bind to localhost
echo "GUNICORN_BIND=127.0.0.1:5000" >> /root/flash-note/.env
systemctl restart flash-note.service

# 5) start nginx
nginx -t
systemctl enable --now nginx
```

Nginx baseline in `deploy/nginx/flash-note.conf` now includes:
- login path rate limiting (`/api/auth/login`)
- gzip response compression for common text/json/js content-types
- `/static/` cache headers (`Cache-Control` + `expires`)

## 3.9) Login protection with fail2ban (optional, recommended)

```bash
# 1) enable nginx login rate limiting (works on all hosts)
cp /root/flash-note/deploy/nginx/flash-note-rate-limit.conf /etc/nginx/conf.d/flash-note-rate-limit.conf
cp /root/flash-note/deploy/nginx/flash-note.conf /etc/nginx/conf.d/flash-note.conf
nginx -t && systemctl reload nginx

# 2) fail2ban (optional; if package is available in your repo)
dnf install -y fail2ban
mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
cp /root/flash-note/deploy/fail2ban/filter.d/nginx-flashnote-login.conf /etc/fail2ban/filter.d/
cp /root/flash-note/deploy/fail2ban/jail.d/flash-note.local /etc/fail2ban/jail.d/
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status nginx-flashnote-login
```

## 3.10) Static single-source sync (item 9)

Use `frontend/` as the single source of truth, then sync to `backend/static/`:

```bash
# check drift (exit 1 if drift exists)
python3 /root/flash-note/scripts/sync_static_assets.py --check

# sync files to runtime static directory
python3 /root/flash-note/scripts/sync_static_assets.py
```

Synced files:
- `frontend/index.html` -> `backend/static/index.html`
- `frontend/login.html` -> `backend/static/login.html`
- `frontend/vendor/marked.min.js` -> `backend/static/vendor/marked.min.js`
- `frontend/vendor/purify.min.js` -> `backend/static/vendor/purify.min.js`

## 3.11) Standard release + rollback (item 9)

Use the standardized release script:

```bash
# standard release: sync static -> backup snapshot -> restart -> release gate
bash /root/flash-note/scripts/release_deploy.sh

# if release gate fails, auto restore pre-release snapshot
bash /root/flash-note/scripts/release_deploy.sh --auto-rollback-on-fail
```

Manual rollback checklist:

```bash
cat /root/flash-note/RELEASE_ROLLBACK_CHECKLIST.md
```

## 4) Verify

```bash
systemctl status flash-note.service --no-pager
ss -ltnp | grep ':5000'
curl -I http://127.0.0.1:5000/login
curl http://127.0.0.1:5000/healthz
curl -kI https://127.0.0.1/login
curl -ks https://127.0.0.1/healthz
```

## 5) Daily operations

```bash
systemctl restart flash-note.service
systemctl stop flash-note.service
journalctl -u flash-note.service -n 100 --no-pager
tail -n 100 /root/flash-note/backend/app.log
/root/flash-note/scripts/smoke.sh
python3 /root/flash-note/scripts/sync_static_assets.py --check
/root/flash-note/scripts/release_gate.sh
bash /root/flash-note/scripts/release_deploy.sh
```

CI gate (GitHub Actions):
- workflow file: `.github/workflows/ci-gate.yml`
- checks included: static drift check + syntax check + API integration tests

## 6) User management (item 10 enhanced)

```bash
# list users
python3 /root/flash-note/scripts/user_admin.py list

# add a new active user
python3 /root/flash-note/scripts/user_admin.py add --username alice --password 'StrongPass123' --role user
# or add admin
python3 /root/flash-note/scripts/user_admin.py add --username bob --password 'StrongPass123' --role admin

# reset password
python3 /root/flash-note/scripts/user_admin.py passwd --username alice --password 'NewStrongPass123'

# lock / unlock
python3 /root/flash-note/scripts/user_admin.py status --username alice --status locked
python3 /root/flash-note/scripts/user_admin.py status --username alice --status active

# role switch
python3 /root/flash-note/scripts/user_admin.py role --username alice --role admin
python3 /root/flash-note/scripts/user_admin.py role --username alice --role user

# delete user
python3 /root/flash-note/scripts/user_admin.py delete --username alice
```

## 7) Storage migration / rollback (item 11)

```bash
# manual migration: notes.json/categories.json -> SQLite
python3 /root/flash-note/scripts/migrate_json_to_sqlite.py

# export back (rollback helper): SQLite -> notes.json/categories.json
python3 /root/flash-note/scripts/export_sqlite_to_json.py

# if needed, temporarily switch back to JSON backend
# APP_STORAGE_BACKEND=json
```

## 8) Backup / restore (item 12)

```bash
# one-shot backup
python3 /root/flash-note/scripts/backup_snapshot.py

# restore drill validation (read-only)
python3 /root/flash-note/scripts/restore_drill.py

# dry-run restore from latest backup archive
python3 /root/flash-note/scripts/restore_snapshot.py --dry-run

# actual restore (will stop/start flash-note.service by default)
python3 /root/flash-note/scripts/restore_snapshot.py --yes
```

Enable scheduled backup + monthly restore drill:

```bash
cp /root/flash-note/deploy/systemd/flash-note-backup.service /etc/systemd/system/flash-note-backup.service
cp /root/flash-note/deploy/systemd/flash-note-backup.timer /etc/systemd/system/flash-note-backup.timer
cp /root/flash-note/deploy/systemd/flash-note-restore-drill.service /etc/systemd/system/flash-note-restore-drill.service
cp /root/flash-note/deploy/systemd/flash-note-restore-drill.timer /etc/systemd/system/flash-note-restore-drill.timer
cp /root/flash-note/deploy/systemd/flash-note-sqlite-optimize.service /etc/systemd/system/flash-note-sqlite-optimize.service
cp /root/flash-note/deploy/systemd/flash-note-sqlite-optimize.timer /etc/systemd/system/flash-note-sqlite-optimize.timer
cp /root/flash-note/deploy/systemd/flash-note-sqlite-vacuum.service /etc/systemd/system/flash-note-sqlite-vacuum.service
cp /root/flash-note/deploy/systemd/flash-note-sqlite-vacuum.timer /etc/systemd/system/flash-note-sqlite-vacuum.timer
cp /root/flash-note/deploy/systemd/flash-note-data-lifecycle.service /etc/systemd/system/flash-note-data-lifecycle.service
cp /root/flash-note/deploy/systemd/flash-note-data-lifecycle.timer /etc/systemd/system/flash-note-data-lifecycle.timer
systemctl daemon-reload
systemctl enable --now flash-note-backup.timer flash-note-restore-drill.timer flash-note-sqlite-optimize.timer flash-note-sqlite-vacuum.timer flash-note-data-lifecycle.timer
systemctl list-timers | grep -E 'flash-note-backup|flash-note-restore-drill|flash-note-sqlite-optimize|flash-note-sqlite-vacuum|flash-note-data-lifecycle'
```

## 9) Data lifecycle / capacity policy (item 10)

```bash
# one-shot report (default, no data change)
python3 /root/flash-note/scripts/data_lifecycle.py

# apply archive action (use carefully; recommend validating archive first)
APP_LIFECYCLE_APPLY=1 \
APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=0 \
python3 /root/flash-note/scripts/data_lifecycle.py

# apply archive + delete old notes (only in maintenance window)
APP_LIFECYCLE_APPLY=1 \
APP_LIFECYCLE_DELETE_AFTER_ARCHIVE=1 \
python3 /root/flash-note/scripts/data_lifecycle.py
```

Enable monthly lifecycle timer:

```bash
cp /root/flash-note/deploy/systemd/flash-note-data-lifecycle.service /etc/systemd/system/flash-note-data-lifecycle.service
cp /root/flash-note/deploy/systemd/flash-note-data-lifecycle.timer /etc/systemd/system/flash-note-data-lifecycle.timer
systemctl daemon-reload
systemctl enable --now flash-note-data-lifecycle.timer
systemctl list-timers | grep -E 'flash-note-data-lifecycle'
```
