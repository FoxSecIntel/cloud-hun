#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any, Dict, List


RISKY_PORTS = {22, 3389, 5432, 3306, 6379, 9200, 5601, 27017}


def run_aws(args: List[str]) -> dict:
    proc = subprocess.run(
        ["aws", *args, "--output", "json"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "aws command failed")
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def is_policy_public(policy_text: str) -> bool:
    try:
        policy = json.loads(policy_text)
    except Exception:
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for st in statements:
        principal = st.get("Principal")
        effect = str(st.get("Effect", "")).lower()
        if effect != "allow":
            continue

        if principal == "*":
            return True

        if isinstance(principal, dict):
            for v in principal.values():
                if v == "*":
                    return True
                if isinstance(v, list) and "*" in v:
                    return True

    return False


def list_public_s3_buckets() -> List[Dict[str, Any]]:
    buckets = run_aws(["s3api", "list-buckets"]).get("Buckets", [])
    out = []

    for b in buckets:
        name = b["Name"]

        public_access_block = None
        block_conf = {}
        block_all = False
        block_state = "unknown"

        public_acl = False
        policy_public = False

        # Public access block assessment
        try:
            public_access_block = run_aws(["s3api", "get-public-access-block", "--bucket", name])
            conf = ((public_access_block.get("PublicAccessBlockConfiguration") or {}))
            block_conf = conf
            flags = [
                bool(conf.get("BlockPublicAcls")),
                bool(conf.get("IgnorePublicAcls")),
                bool(conf.get("BlockPublicPolicy")),
                bool(conf.get("RestrictPublicBuckets")),
            ]
            block_all = all(flags)
            block_state = "strict" if block_all else "partial"
        except Exception:
            block_state = "missing"

        # ACL exposure assessment
        try:
            acl = run_aws(["s3api", "get-bucket-acl", "--bucket", name])
            for grant in acl.get("Grants", []):
                uri = ((grant.get("Grantee") or {}).get("URI", ""))
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_acl = True
                    break
        except Exception:
            pass

        # Bucket policy public principal assessment
        try:
            pol = run_aws(["s3api", "get-bucket-policy", "--bucket", name])
            policy_text = pol.get("Policy", "")
            if policy_text:
                policy_public = is_policy_public(policy_text)
        except Exception:
            pass

        status = "pass"
        severity = "info"
        confidence = "high"

        if public_acl or policy_public:
            status = "fail"
            severity = "high"
        elif block_state in {"missing", "partial"}:
            status = "warn"
            severity = "medium"

        out.append(
            {
                "service": "s3",
                "resource": name,
                "status": status,
                "severity": severity,
                "confidence": confidence,
                "data_source": "aws:s3api",
                "details": {
                    "public_acl": public_acl,
                    "policy_public": policy_public,
                    "public_access_block_state": block_state,
                    "public_access_block": block_conf,
                },
            }
        )

    return out


def list_public_ec2() -> List[Dict[str, Any]]:
    out = []
    try:
        res = run_aws(["ec2", "describe-instances"])
    except Exception as exc:
        return [{
            "service": "ec2",
            "resource": "-",
            "status": "unknown",
            "severity": "warn",
            "confidence": "low",
            "data_source": "aws:ec2",
            "details": {"error": str(exc)},
        }]

    for r in res.get("Reservations", []):
        for inst in r.get("Instances", []):
            pub_ip = inst.get("PublicIpAddress")
            if not pub_ip:
                continue
            iid = inst.get("InstanceId")
            state = ((inst.get("State") or {}).get("Name"))
            name = ""
            for tag in inst.get("Tags", []):
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
                    break

            out.append(
                {
                    "service": "ec2",
                    "resource": iid,
                    "status": "warn",
                    "severity": "medium",
                    "confidence": "high",
                    "data_source": "aws:ec2",
                    "details": {
                        "name": name,
                        "public_ip": pub_ip,
                        "state": state,
                    },
                }
            )
    return out


def list_security_group_exposure() -> List[Dict[str, Any]]:
    out = []
    try:
        res = run_aws(["ec2", "describe-security-groups"])
    except Exception as exc:
        return [{
            "service": "security-group",
            "resource": "-",
            "status": "unknown",
            "severity": "warn",
            "confidence": "low",
            "data_source": "aws:ec2",
            "details": {"error": str(exc)},
        }]

    for sg in res.get("SecurityGroups", []):
        sg_id = sg.get("GroupId")
        sg_name = sg.get("GroupName")

        risky_rules = []
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            ip_proto = perm.get("IpProtocol")

            cidrs = [x.get("CidrIp") for x in perm.get("IpRanges", []) if x.get("CidrIp")]
            cidrs += [x.get("CidrIpv6") for x in perm.get("Ipv6Ranges", []) if x.get("CidrIpv6")]

            is_world = any(c in {"0.0.0.0/0", "::/0"} for c in cidrs)
            if not is_world:
                continue

            if from_port is None or to_port is None:
                # all ports or protocol-specific without ports
                risky_rules.append({
                    "protocol": ip_proto,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidrs": cidrs,
                    "reason": "world-open rule",
                })
                continue

            for port in range(int(from_port), int(to_port) + 1):
                if port in RISKY_PORTS:
                    risky_rules.append({
                        "protocol": ip_proto,
                        "from_port": from_port,
                        "to_port": to_port,
                        "cidrs": cidrs,
                        "reason": f"world-open risky port {port}",
                    })
                    break

        if risky_rules:
            out.append(
                {
                    "service": "security-group",
                    "resource": sg_id,
                    "status": "fail",
                    "severity": "high",
                    "confidence": "high",
                    "data_source": "aws:ec2",
                    "details": {
                        "group_name": sg_name,
                        "risky_rules": risky_rules,
                    },
                }
            )

    return out


def list_api_gateways() -> List[Dict[str, Any]]:
    out = []
    try:
        res = run_aws(["apigateway", "get-rest-apis"])
    except Exception as exc:
        return [{
            "service": "apigateway",
            "resource": "-",
            "status": "unknown",
            "severity": "warn",
            "confidence": "low",
            "data_source": "aws:apigateway",
            "details": {"error": str(exc)},
        }]

    for api in res.get("items", []):
        out.append(
            {
                "service": "apigateway",
                "resource": api.get("id"),
                "status": "warn",
                "severity": "info",
                "confidence": "medium",
                "data_source": "aws:apigateway",
                "details": {
                    "name": api.get("name"),
                },
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="AWS public exposure scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []
    findings.extend(list_public_s3_buckets())
    findings.extend(list_public_ec2())
    findings.extend(list_security_group_exposure())
    findings.extend(list_api_gateways())

    if args.json:
        print(json.dumps(findings, indent=2))
        return 0

    print("cloud-hun: public exposure scan")
    print("SERVICE\tRESOURCE\tSTATUS\tSEVERITY\tCONFIDENCE\tDETAIL")
    for f in findings:
        details = f.get("details", {})
        detail_str = ""
        if f.get("service") == "s3":
            detail_str = (
                f"public_acl={details.get('public_acl')} "
                f"policy_public={details.get('policy_public')} "
                f"block_state={details.get('public_access_block_state')}"
            )
        elif f.get("service") == "ec2":
            detail_str = f"public_ip={details.get('public_ip')} state={details.get('state')}"
        elif f.get("service") == "security-group":
            rules = details.get("risky_rules", [])
            detail_str = f"group={details.get('group_name')} risky_rules={len(rules)}"
        elif f.get("service") == "apigateway":
            detail_str = f"name={details.get('name')}"
        elif details.get("error"):
            detail_str = f"error={details.get('error')}"

        print(
            f"{f.get('service')}\t{f.get('resource', '-')}\t{f.get('status', 'unknown')}\t"
            f"{f.get('severity', 'info')}\t{f.get('confidence', 'low')}\t{detail_str}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
