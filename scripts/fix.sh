#!/usr/bin/env bash
set -euo pipefail

echo "=== cloud-hun: quick hygiene hardening ==="

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-1}}

echo "[+] Enforcing S3 public access block at account level"
aws s3control put-public-access-block \
  --account-id "$ACCOUNT_ID" \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

echo "[+] Enabling GuardDuty (if not already enabled)"
aws guardduty list-detectors --region "$REGION" --query 'DetectorIds' --output text | grep . || \
  DETECTOR_ID=$(aws guardduty create-detector --region "$REGION" --enable --query 'DetectorId' --output text)

echo "[+] Enabling Security Hub (if not already enabled)"
if ! aws securityhub describe-hub --region "$REGION" >/dev/null 2>&1; then
  aws securityhub enable-security-hub --region "$REGION"
fi

echo "Done. Review costs for GuardDuty/Security Hub if you keep them on long-term."
