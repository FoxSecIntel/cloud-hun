#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: fix.sh --plan | --apply

--plan   Show what would be changed
--apply  Execute hardening actions
EOF
}

MODE=""
case "${1:-}" in
  --plan) MODE="plan" ;;
  --apply) MODE="apply" ;;
  -h|--help) usage; exit 0 ;;
  *) usage; exit 1 ;;
esac

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-1}}

do_or_print() {
  local cmd="$1"
  if [[ "$MODE" == "plan" ]]; then
    echo "[PLAN] $cmd"
  else
    echo "[APPLY] $cmd"
    eval "$cmd"
  fi
}

echo "=== cloud-hun: quick hygiene hardening (${MODE}) ==="

do_or_print "aws s3control put-public-access-block --account-id ${ACCOUNT_ID} --public-access-block-configuration '{\"BlockPublicAcls\":true,\"IgnorePublicAcls\":true,\"BlockPublicPolicy\":true,\"RestrictPublicBuckets\":true}'"

do_or_print "aws guardduty list-detectors --region ${REGION} --query 'DetectorIds' --output text"
if [[ "$MODE" == "apply" ]]; then
  ids=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds' --output text || true)
  if [[ -z "$ids" || "$ids" == "None" ]]; then
    aws guardduty create-detector --region "$REGION" --enable >/dev/null
    echo "[APPLY] GuardDuty detector created"
  else
    echo "[APPLY] GuardDuty already enabled"
  fi
fi

do_or_print "aws securityhub describe-hub --region ${REGION}"
if [[ "$MODE" == "apply" ]]; then
  if ! aws securityhub describe-hub --region "$REGION" >/dev/null 2>&1; then
    aws securityhub enable-security-hub --region "$REGION" >/dev/null
    echo "[APPLY] Security Hub enabled"
  else
    echo "[APPLY] Security Hub already enabled"
  fi
fi

echo "Done. Review costs for GuardDuty and Security Hub if left enabled long-term."
