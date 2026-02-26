#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any, Dict, List


def run_aws(args: List[str]) -> dict:
    proc = subprocess.run(
        ["aws", *args, "--output", "json"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "aws command failed")
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def list_public_s3_buckets() -> List[Dict[str, Any]]:
    buckets = run_aws(["s3api", "list-buckets"]).get("Buckets", [])
    out = []

    for b in buckets:
        name = b["Name"]
        public_access_block = None
        acl_grants = []
        is_public_acl = False

        try:
            public_access_block = run_aws(["s3api", "get-public-access-block", "--bucket", name])
        except Exception:
            public_access_block = {"error": "unavailable"}

        try:
            acl = run_aws(["s3api", "get-bucket-acl", "--bucket", name])
            acl_grants = acl.get("Grants", [])
            for grant in acl_grants:
                uri = (grant.get("Grantee", {}) or {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public_acl = True
                    break
        except Exception:
            pass

        out.append(
            {
                "service": "s3",
                "resource": name,
                "public_acl": is_public_acl,
                "public_access_block": public_access_block,
                "severity": "high" if is_public_acl else "info",
            }
        )

    return out


def list_public_ec2() -> List[Dict[str, Any]]:
    out = []
    try:
        res = run_aws(["ec2", "describe-instances"])
    except Exception as exc:
        return [{"service": "ec2", "error": str(exc), "severity": "warn"}]

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
                    "name": name,
                    "public_ip": pub_ip,
                    "state": state,
                    "severity": "medium",
                }
            )
    return out


def list_api_gateways() -> List[Dict[str, Any]]:
    out = []
    try:
        res = run_aws(["apigateway", "get-rest-apis"])
    except Exception as exc:
        return [{"service": "apigateway", "error": str(exc), "severity": "warn"}]

    for api in res.get("items", []):
        out.append(
            {
                "service": "apigateway",
                "resource": api.get("id"),
                "name": api.get("name"),
                "severity": "info",
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="AWS public exposure scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    findings = []
    findings.extend(list_public_s3_buckets())
    findings.extend(list_public_ec2())
    findings.extend(list_api_gateways())

    if args.json:
        print(json.dumps(findings, indent=2))
        return 0

    print("cloud-hun: public exposure scan")
    print("SERVICE\tRESOURCE\tSEVERITY\tDETAIL")
    for f in findings:
        detail = ""
        if f.get("service") == "s3":
            detail = f"public_acl={f.get('public_acl')}"
        elif f.get("service") == "ec2":
            detail = f"public_ip={f.get('public_ip')} state={f.get('state')}"
        elif f.get("service") == "apigateway":
            detail = f"name={f.get('name')}"
        elif f.get("error"):
            detail = f"error={f.get('error')}"

        print(f"{f.get('service')}\t{f.get('resource','-')}\t{f.get('severity','info')}\t{detail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
