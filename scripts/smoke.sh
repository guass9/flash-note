#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://127.0.0.1}"
SMOKE_CURL_INSECURE="${SMOKE_CURL_INSECURE:-1}"
LOGIN_USERNAME="${LOGIN_USERNAME:-909020}"
LOGIN_PASSWORD="${LOGIN_PASSWORD:-909020}"

COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

log() {
  printf '[smoke] %s\n' "$1"
}

request_status() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local -a curl_args=()

  if [[ "$SMOKE_CURL_INSECURE" == "1" ]]; then
    curl_args+=("-k")
  fi

  if [[ -n "$data" ]]; then
    curl -sS "${curl_args[@]}" -o /tmp/smoke_body.txt -w '%{http_code}' \
      -X "$method" \
      -H 'Content-Type: application/json' \
      -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
      --data "$data" \
      "${BASE_URL}${path}"
  else
    curl -sS "${curl_args[@]}" -o /tmp/smoke_body.txt -w '%{http_code}' \
      -X "$method" \
      -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
      "${BASE_URL}${path}"
  fi
}

assert_status() {
  local actual="$1"
  local expected="$2"
  local step="$3"
  if [[ "$actual" != "$expected" ]]; then
    log "FAILED: ${step}, expected ${expected}, got ${actual}"
    log "Response body: $(cat /tmp/smoke_body.txt)"
    exit 1
  fi
  log "OK: ${step} (${actual})"
}

log "Base URL: ${BASE_URL}"
log "1) health check"
code="$(request_status GET /healthz)"
assert_status "$code" "200" "GET /healthz"

log "2) auth status (anonymous)"
code="$(request_status GET /api/auth/status)"
assert_status "$code" "200" "GET /api/auth/status"

log "3) protected API blocked before login"
code="$(request_status GET /api/categories)"
assert_status "$code" "401" "GET /api/categories (unauth)"

log "4) login"
code="$(request_status POST /api/auth/login "{\"username\":\"${LOGIN_USERNAME}\",\"password\":\"${LOGIN_PASSWORD}\"}")"
assert_status "$code" "200" "POST /api/auth/login"

log "5) protected APIs available after login"
code="$(request_status GET /api/categories)"
assert_status "$code" "200" "GET /api/categories (auth)"
code="$(request_status GET /api/notes)"
assert_status "$code" "200" "GET /api/notes (auth)"

log "6) logout"
code="$(request_status POST /api/auth/logout)"
assert_status "$code" "200" "POST /api/auth/logout"

log "7) protected API blocked after logout"
code="$(request_status GET /api/categories)"
assert_status "$code" "401" "GET /api/categories (after logout)"

log "PASS: all smoke checks passed"
