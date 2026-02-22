#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '[gate] %s\n' "$1"
}

run_cmd() {
  log "$1"
  shift
  "$@"
}

run_cmd "check static asset drift" python3 "$ROOT_DIR/scripts/sync_static_assets.py" --check
run_cmd "python syntax check" python3 -m py_compile "$ROOT_DIR/backend/app.py"
run_cmd "integration tests" python3 -m unittest discover -s "$ROOT_DIR/tests" -p "test_*.py" -v

if [[ "${SKIP_RUNTIME_CHECKS:-0}" != "1" ]]; then
  log "runtime health check"
  health_json="$(curl -ksS https://127.0.0.1/healthz)"
  if [[ "$health_json" != *'"status":"ok"'* ]]; then
    printf '[gate] FAILED: /healthz unexpected body: %s\n' "$health_json" >&2
    exit 1
  fi

  login_user="${LOGIN_USERNAME:-Guass}"
  login_pass="${LOGIN_PASSWORD:-909020@aZ}"
  run_cmd "smoke test" env LOGIN_USERNAME="$login_user" LOGIN_PASSWORD="$login_pass" "$ROOT_DIR/scripts/smoke.sh"
else
  log "skip runtime checks (SKIP_RUNTIME_CHECKS=1)"
fi

log "PASS: release gate checks passed"
