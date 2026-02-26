#!/usr/bin/env bash
set -euo pipefail

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
