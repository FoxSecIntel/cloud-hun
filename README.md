# cloud-hun

`cloud-hun` is a lightweight AWS cloud exposure & misconfiguration hunter.

It focuses on three things:

1. **Account hygiene** – IAM, MFA, root usage, password policy
2. **External attack surface** – internet-exposed services & public S3
3. **Misconfiguration patterns** – things a Tier-1/2 SOC or VM team actually cares about

The design principles:

- Use **AWS free tier** only
- Use **CLI + simple scripts** (bash + Python)
- Focus on **exploitability and attack paths**, not just raw config

---

## Components

- `scripts/iam_audit.sh` – basic account hygiene checks
- `scripts/public_exposure_scan.py` – enumerates internet-exposed assets
- `scripts/fix.sh` – opinionated "quick hygiene" hardening commands (optional)
- `docs/attack-paths.md` – examples of chained misconfigurations
- `docs/misconfig-library.md` – catalogue of checks & what they mean

---

## Quick start

```bash
# clone
git clone https://github.com/<your-username>/cloud-hun.git
cd cloud-hun

# run IAM audit
chmod +x scripts/iam_audit.sh
./scripts/iam_audit.sh

You need AWS CLI configured (aws configure) with an IAM user that has permission to read IAM, S3, EC2, etc.
