#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[secret-scan] %s\n' "$1"
}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  log "skip: not a git repository"
  exit 0
fi

staged_files="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "${staged_files}" ]]; then
  exit 0
fi

blocked_path_regex='(^|/)\.env($|\..+)|(^|/)data/|(^|/)backups/|(^|/)__pycache__/|\.db([._-].+)?$|(^|/)backend/app\.log$'
blocked_paths="$(
  printf '%s\n' "${staged_files}" \
    | rg "${blocked_path_regex}" \
    | rg -v '(^|/)\.env\.(example|template)$' \
    || true
)"
if [[ -n "${blocked_paths}" ]]; then
  log "blocked: sensitive/runtime files are staged"
  printf '%s\n' "${blocked_paths}"
  log "fix: git reset HEAD <file> && ensure .gitignore covers them"
  exit 1
fi

added_lines="$(git diff --cached --text --unified=0 --no-color | rg '^\+[^+]' || true)"
if [[ -z "${added_lines}" ]]; then
  exit 0
fi

high_confidence_secret_regex='BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|(redis|postgres(ql)?|mysql|mongodb(\+srv)?)://[^[:space:]]+:[^[:space:]]+@'
secret_hits="$(printf '%s\n' "${added_lines}" | rg -n -i "${high_confidence_secret_regex}" || true)"
if [[ -n "${secret_hits}" ]]; then
  log "blocked: high-confidence secret pattern found in staged diff"
  printf '%s\n' "${secret_hits}"
  log "fix: remove/redact secret, then git add and commit again"
  exit 1
fi

exit 0
