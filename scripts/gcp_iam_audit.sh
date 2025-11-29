#!/usr/bin/env bash
# gcp_iam_audit.sh - Lightweight GCP IAM hygiene / exposure audit
# Requires: gcloud CLI configured with read access to IAM + service accounts

set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null || true)}"

if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "Usage: $0 <GCP_PROJECT_ID>"
  echo "Or set a default project with: gcloud config set project YOUR_PROJECT_ID"
  exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
  echo "ERROR: gcloud command not found. Install Google Cloud SDK first."
  exit 1
fi

section() {
  printf '\n\n============================================\n'
  printf '%s\n' "$1"
  printf '============================================\n'
}

info() {
  printf '[*] %s\n' "$1"
}

section "Context"
info "Active project: ${PROJECT_ID}"
info "Active gcloud account: $(gcloud config get-value account 2>/dev/null || echo 'unknown')"

section "Project IAM summary (roles & members)"

gcloud projects get-iam-policy "${PROJECT_ID}" \
  --format="table(bindings.role, bindings.members)" \
  --flatten="bindings[].members"

section "Primitive owner/editor roles on project"

info "Owners (roles/owner)"
gcloud projects get-iam-policy "${PROJECT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/owner" \
  --format="table(bindings.members)"

info "Editors (roles/editor)"
gcloud projects get-iam-policy "${PROJECT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/editor" \
  --format="table(bindings.members)"

info "Viewers (roles/viewer)"
gcloud projects get-iam-policy "${PROJECT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/viewer" \
  --format="table(bindings.members)"

section "Public access (allUsers / allAuthenticatedUsers) on project IAM policy"

gcloud projects get-iam-policy "${PROJECT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.members:allUsers OR bindings.members:allAuthenticatedUsers" \
  --format="table(bindings.role, bindings.members)"

section "Highly-privileged roles on project (security / org / IAM heavy)"

HIGH_PRIV_ROLES=(
  roles/owner
  roles/editor
  roles/resourcemanager.organizationAdmin
  roles/resourcemanager.projectIamAdmin
  roles/iam.securityAdmin
  roles/iam.roleAdmin
  roles/iam.serviceAccountAdmin
  roles/iam.serviceAccountUser
  roles/iam.serviceAccountTokenCreator
  roles/iam.workloadIdentityPoolAdmin
  roles/iam.workloadIdentityPoolManager
)

for ROLE in "${HIGH_PRIV_ROLES[@]}"; do
  info "Members with ${ROLE}"
  gcloud projects get-iam-policy "${PROJECT_ID}" \
    --flatten="bindings[].members" \
    --filter="bindings.role:${ROLE}" \
    --format="table(bindings.members)" || true
  echo
done

section "Service accounts in project"

gcloud iam service-accounts list \
  --project "${PROJECT_ID}" \
  --format="table(name, email, disabled)"

section "Service accounts with user-managed keys"

SA_LIST=$(gcloud iam service-accounts list \
  --project "${PROJECT_ID}" \
  --format="value(email)" || true)

if [[ -z "${SA_LIST}" ]]; then
  info "No service accounts found."
else
  while IFS= read -r SA_EMAIL; do
    [[ -z "${SA_EMAIL}" ]] && continue
    info "User-managed keys for ${SA_EMAIL}"

    # --managed-by=user filters out Google-managed keys
    gcloud iam service-accounts keys list \
      --iam-account="${SA_EMAIL}" \
      --managed-by=user \
      --format="table(name, keyOrigin, validAfterTime, validBeforeTime)" || true

    echo
  done <<< "${SA_LIST}"
fi

section "Service accounts with token-creation / impersonation capabilities"

SA_SENSITIVE_ROLES=(
  roles/iam.serviceAccountUser
  roles/iam.serviceAccountTokenCreator
  roles/iam.serviceAccountKeyAdmin
)

for ROLE in "${SA_SENSITIVE_ROLES[@]}"; do
  info "Members with ${ROLE}"
  gcloud projects get-iam-policy "${PROJECT_ID}" \
    --flatten="bindings[].members" \
    --filter="bindings.role:${ROLE}" \
    --format="table(bindings.members)" || true
  echo
done

section "Custom roles defined at project level"

gcloud iam roles list \
  --project "${PROJECT_ID}" \
  --format="table(name, title, stage)" || true

section "Members granted custom roles at project level"

gcloud iam roles list \
  --project "${PROJECT_ID}" \
  --format="value(name)" 2>/dev/null | while read -r ROLE_NAME; do
    [[ -z "${ROLE_NAME}" ]] && continue
    info "Members with custom role ${ROLE_NAME}"
    gcloud projects get-iam-policy "${PROJECT_ID}" \
      --flatten="bindings[].members" \
      --filter="bindings.role:${ROLE_NAME}" \
      --format="table(bindings.members)" || true
    echo
  done

section "Finished"

info "GCP IAM audit for project ${PROJECT_ID} completed."
echo
