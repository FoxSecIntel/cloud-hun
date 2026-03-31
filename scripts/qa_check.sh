#!/usr/bin/env bash
if [[ "${1:-}" == "-a" || "${1:-}" == "--author" ]]; then
  echo "Author: FoxSecIntel"
  echo "Repository: https://github.com/FoxSecIntel/cloud-hun
  echo "Tool: qa_check.sh"
  exit 0
fi

set -euo pipefail

__r17q_blob="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$__r17q_blob" | base64 --decode
  exit 0
fi


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
