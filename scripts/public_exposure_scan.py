#!/usr/bin/env python3
import json
import subprocess


def aws_cli(cmd):
    """Run an aws cli command and return parsed JSON."""
    result = subprocess.run(
        ["aws"] + cmd.split(),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else {}


def list_public_s3_buckets():
    print("=== Public S3 buckets (ACL / policy) ===")
    buckets = aws_cli("s3api list-buckets").get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        # Public access block
        try:
            pab = aws_cli(f"s3api get-public-access-block --bucket {name}")
        except subprocess.CalledProcessError:
            pab = {}

        # Bucket ACL
        try:
            acl = aws_cli(f"s3api get-bucket-acl --bucket {name}")
        except subprocess.CalledProcessError:
            acl = {}

        is_public = False

        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                is_public = True

        print(f"- {name}: public={is_public}, public_access_block={json.dumps(pab)}")


def list_public_ec2():
    print("\n=== EC2 instances with public IPs ===")
    try:
        res = aws_cli("ec2 describe-instances")
    except subprocess.CalledProcessError:
        print("No EC2 permissions or no instances.")
        return

    for r in res.get("Reservations", []):
        for inst in r.get("Instances", []):
            pub_ip = inst.get("PublicIpAddress")
            if pub_ip:
                iid = inst["InstanceId"]
                state = inst["State"]["Name"]
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                print(f"- {iid} ({name}) public_ip={pub_ip} state={state}")


def list_api_gateways():
    print("\n=== API Gateway REST APIs ===")
    try:
        res = aws_cli("apigateway get-rest-apis")
    except subprocess.CalledProcessError:
        print("No API Gateway permissions or no APIs.")
        return

    for api in res.get("items", []):
        print(f"- id={api['id']} name={api.get('name')}")


if __name__ == "__main__":
    print("cloud-hun: public exposure scan\n")
    list_public_s3_buckets()
    list_public_ec2()
    list_api_gateways()
