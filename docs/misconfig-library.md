# Misconfiguration Library

This document lists the issues `cloud-hun` looks for and why they matter.

## IAM / Account

- **No password policy**
  - Risk: weak / reused passwords for console logins.
  - Signal: `iam_audit.sh` shows "No password policy configured."

- **Users without console password**
  - Not a risk by itself – just indicates programmatic-only users.
  - Context: useful to understand which identities are human vs machine.

## Public exposure

- **Public S3 buckets**
  - Risk: data leakage, malware hosting, supply-chain attacks.
  - Checks:
    - Bucket ACL grants to `AllUsers` or `AuthenticatedUsers`.
    - Public access block configuration.

- **EC2 with public IP**
  - Risk: direct attack surface (SSH/RDP/web) from the internet.
  - Next step: review security groups and OS patching.

- **API Gateway APIs**
  - Risk: exposed APIs with auth / rate limiting / logging gaps.
  - Next step: map to business functions and threat models.

