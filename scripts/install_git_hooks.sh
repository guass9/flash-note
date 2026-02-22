#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[git-hook] current directory is not a git repository: ${ROOT_DIR}" >&2
  echo "[git-hook] run: git init" >&2
  exit 1
fi

hook_dir="$(git rev-parse --git-path hooks)"
hook_file="${hook_dir}/pre-commit"

mkdir -p "${hook_dir}"
cp scripts/precommit_secret_scan.sh "${hook_file}"
chmod 0755 "${hook_file}"

echo "[git-hook] installed: ${hook_file}"
