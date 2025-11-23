#!/usr/bin/env bash
set -euo pipefail

if ! command -v aws >/dev/null 2>&1; then
  echo "[!] aws CLI not found. Install and configure AWS CLI v2." >&2
  exit 1
fi

echo "=== cloud-hun: IAM / account hygiene audit ==="
echo

echo "[+] AWS identity:"
aws sts get-caller-identity
echo

echo "[+] Account alias (if set):"
aws iam list-account-aliases
echo

echo "[+] Account summary:"
aws iam get-account-summary
echo

echo "[+] Password policy (if any):"
if aws iam get-account-password-policy >/dev/null 2>&1; then
  aws iam get-account-password-policy
else
  echo "No password policy configured."
fi
echo

echo "[+] IAM users without console password:"
aws iam list-users --output json | jq -r '
  .Users[].UserName
' | while read -r u; do
  # returns NoSuchEntity if no login profile
  if ! aws iam get-login-profile --user-name "$u" >/dev/null 2>&1; then
    echo "$u"
  fi
done
echo

echo "[+] IAM users and attached managed policies:"
aws iam list-users --output json | jq -r '.Users[].UserName' | while read -r u; do
  echo "User: $u"
  aws iam list-attached-user-policies --user-name "$u"
  aws iam list-user-policies --user-name "$u"
  echo
done

