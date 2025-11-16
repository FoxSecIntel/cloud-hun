
# Example Attack Paths

These are illustrative chains that cloud-hun is designed to highlight.

## Path 1 – Public bucket → Credentials → Database

1. S3 bucket is public.
2. Bucket contains application `.env` file.
3. `.env` contains database credentials.
4. Database is reachable from an EC2 instance with a public IP.
5. Attacker:
   - Lists bucket contents.
   - Downloads `.env`.
   - Reuses credentials on the database.

## Path 2 – Over-permissive IAM → Data exfil

1. IAM user has `Action: "*"`, `Resource: "*"`.
2. Access key leaks (phishing, git, CI logs).
3. Attacker:
   - Enumerates all S3 buckets.
   - Copies data to attacker-owned bucket.
   - Disables CloudTrail / GuardDuty (if allowed).

## Path 3 – API Gateway → Lambda → Privilege escalation

1. Public API Gateway exposes a Lambda function.
2. Lambda role has wide permissions (`*` on critical services).
3. Attacker discovers API, triggers specific payload.
4. Lambda executes privileged API calls on behalf of attacker.
