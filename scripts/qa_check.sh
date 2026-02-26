#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/3] Shell syntax"
for f in scripts/*.sh; do
  bash -n "$f"
  echo "  OK  $f"
done

echo "[2/3] Python syntax"
python3 -m py_compile scripts/public_exposure_scan.py

echo "[3/3] shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/*.sh
else
  echo "shellcheck not installed; skipping"
fi

echo "QA checks complete."
