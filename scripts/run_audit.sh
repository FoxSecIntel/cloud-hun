#!/usr/bin/env bash
if [[ "${1:-}" == "-a" || "${1:-}" == "--author" ]]; then
  echo "Author: FoxSecIntel"
  echo "Repository: https://github.com/FoxSecIntel/cloud-hun
  echo "Tool: run_audit.sh"
  exit 0
fi

set -euo pipefail

__r17q_blob="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$__r17q_blob" | base64 --decode
  exit 0
fi


usage() {
  cat <<'EOF'
Usage:
  run_audit.sh --provider aws|gcp [--project GCP_PROJECT_ID] [--json]
EOF
}

provider=""
project=""
json=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider) shift; provider="${1:-}"; shift ;;
    --project) shift; project="${1:-}"; shift ;;
    --json) json=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

[[ -n "$provider" ]] || { usage; exit 1; }

case "$provider" in
  aws)
    ./scripts/aws_iam_audit.sh
    if $json; then
      python3 ./scripts/public_exposure_scan.py --json
    else
      python3 ./scripts/public_exposure_scan.py
    fi
    ;;
  gcp)
    if [[ -n "$project" ]]; then
      ./scripts/gcp_iam_audit.sh "$project"
    else
      ./scripts/gcp_iam_audit.sh
    fi
    ;;
  *)
    echo "Unsupported provider: $provider"
    exit 1
    ;;
esac
