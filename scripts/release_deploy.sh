#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICE_NAME="${SERVICE_NAME:-flash-note.service}"
BASE_URL="${BASE_URL:-https://127.0.0.1}"
AUTO_ROLLBACK_ON_FAIL=0
SKIP_BACKUP=0
SKIP_RESTART=0
DRY_RUN=0
BACKUP_ARCHIVE=""

usage() {
  cat <<'EOF'
Usage: scripts/release_deploy.sh [options]

Options:
  --auto-rollback-on-fail   When release gate fails, auto restore the pre-release snapshot.
  --skip-backup             Do not create pre-release backup snapshot.
  --skip-restart            Do not restart flash-note.service before release gate.
  --dry-run                 Print planned actions only.
  -h, --help                Show this help.
EOF
}

log() {
  printf '[release] %s\n' "$1"
}

run_cmd() {
  log "$1"
  shift
  "$@"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --auto-rollback-on-fail)
        AUTO_ROLLBACK_ON_FAIL=1
        ;;
      --skip-backup)
        SKIP_BACKUP=1
        ;;
      --skip-restart)
        SKIP_RESTART=1
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        printf 'error: unknown option: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
}

capture_backup_archive() {
  local output
  output="$(python3 "$ROOT_DIR/scripts/backup_snapshot.py")"
  printf '%s\n' "$output"
  BACKUP_ARCHIVE="$(printf '%s\n' "$output" | awk -F= '/^backup_archive=/{print $2}' | tail -n 1)"
  if [[ -z "$BACKUP_ARCHIVE" ]]; then
    printf 'error: backup snapshot succeeded but backup_archive is empty\n' >&2
    exit 1
  fi
  if [[ ! -f "$BACKUP_ARCHIVE" ]]; then
    printf 'error: backup archive file not found: %s\n' "$BACKUP_ARCHIVE" >&2
    exit 1
  fi
}

auto_rollback() {
  local rollback_user rollback_pass
  if [[ -z "$BACKUP_ARCHIVE" ]]; then
    log "skip auto rollback: no backup archive available"
    return 1
  fi
  log "start auto rollback from $BACKUP_ARCHIVE"
  python3 "$ROOT_DIR/scripts/restore_snapshot.py" --archive "$BACKUP_ARCHIVE" --yes
  curl -ksS "$BASE_URL/healthz"
  echo
  rollback_user="${LOGIN_USERNAME:-${APP_LOGIN_USERNAME:-Guass}}"
  rollback_pass="${LOGIN_PASSWORD:-${APP_LOGIN_PASSWORD:-909020@aZ}}"
  env LOGIN_USERNAME="$rollback_user" LOGIN_PASSWORD="$rollback_pass" \
    "$ROOT_DIR/scripts/smoke.sh"
  log "auto rollback completed"
  return 0
}

main() {
  parse_args "$@"

  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run=1"
    log "plan: sync static assets -> optional backup -> optional restart -> release gate -> optional auto rollback on failure"
    exit 0
  fi

  run_cmd "sync static assets" python3 "$ROOT_DIR/scripts/sync_static_assets.py"

  if [[ "$SKIP_BACKUP" == "0" ]]; then
    log "create pre-release backup snapshot"
    capture_backup_archive
    log "pre-release backup: $BACKUP_ARCHIVE"
  else
    log "skip pre-release backup"
  fi

  if [[ "$SKIP_RESTART" == "0" ]]; then
    run_cmd "restart $SERVICE_NAME" systemctl restart "$SERVICE_NAME"
  else
    log "skip service restart"
  fi

  if "$ROOT_DIR/scripts/release_gate.sh"; then
    log "release gate passed"
    if [[ -n "$BACKUP_ARCHIVE" ]]; then
      log "rollback command (if needed): python3 $ROOT_DIR/scripts/restore_snapshot.py --archive $BACKUP_ARCHIVE --yes"
    fi
    exit 0
  fi

  printf '[release] release gate failed\n' >&2
  if [[ "$AUTO_ROLLBACK_ON_FAIL" == "1" ]]; then
    auto_rollback || true
  fi
  exit 1
}

main "$@"
