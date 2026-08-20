import contextlib
import io
import unittest
from unittest.mock import patch

from scripts.public_exposure_scan import (
    RISKY_PORTS,
    exclude_findings_by_service,
    filter_findings_by_min_severity,
    filter_findings_by_service,
    filter_findings_by_status,
    is_policy_public,
    main,
    sanitize_aws_error,
    summarize_findings,
)


class PolicyPublicTests(unittest.TestCase):
    def test_detects_public_principal_string(self):
        policy = '{"Statement": {"Effect": "Allow", "Principal": "*"}}'

        self.assertTrue(is_policy_public(policy))

    def test_ignores_deny_public_principal(self):
        policy = '{"Statement": {"Effect": "Deny", "Principal": "*"}}'

        self.assertFalse(is_policy_public(policy))

    def test_detects_allow_not_principal(self):
        policy = '{"Statement": {"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"}}}'

        self.assertTrue(is_policy_public(policy))

    def test_detects_public_principal_list(self):
        policy = '{"Statement": {"Effect": "Allow", "Principal": ["*"]}}'

        self.assertTrue(is_policy_public(policy))


class SeverityFilterTests(unittest.TestCase):
    def test_filters_findings_below_minimum_severity(self):
        findings = [
            {"resource": "api", "severity": "info"},
            {"resource": "bucket", "severity": "medium"},
            {"resource": "sg", "severity": "high"},
        ]

        filtered = filter_findings_by_min_severity(findings, "medium")

        self.assertEqual(["bucket", "sg"], [finding["resource"] for finding in filtered])


class StatusFilterTests(unittest.TestCase):
    def test_filters_findings_by_status(self):
        findings = [
            {"resource": "bucket-a", "status": "pass"},
            {"resource": "bucket-b", "status": "fail"},
            {"resource": "api", "status": "warn"},
        ]

        filtered = filter_findings_by_status(findings, "fail")

        self.assertEqual(["bucket-b"], [finding["resource"] for finding in filtered])

    def test_returns_all_findings_without_status_filter(self):
        findings = [{"resource": "bucket-a", "status": "pass"}]

        self.assertEqual(findings, filter_findings_by_status(findings, None))


class ServiceFilterTests(unittest.TestCase):
    def test_filters_findings_by_service(self):
        findings = [
            {"resource": "bucket-a", "service": "s3"},
            {"resource": "sg-1", "service": "security-group"},
            {"resource": "api", "service": "apigateway"},
        ]

        filtered = filter_findings_by_service(findings, "security-group")

        self.assertEqual(["sg-1"], [finding["resource"] for finding in filtered])

    def test_returns_all_findings_without_service_filter(self):
        findings = [{"resource": "bucket-a", "service": "s3"}]

        self.assertEqual(findings, filter_findings_by_service(findings, None))

    def test_excludes_findings_by_service(self):
        findings = [
            {"resource": "bucket-a", "service": "s3"},
            {"resource": "sg-1", "service": "security-group"},
            {"resource": "api", "service": "apigateway"},
        ]

        filtered = exclude_findings_by_service(findings, "apigateway")

        self.assertEqual(["bucket-a", "sg-1"], [finding["resource"] for finding in filtered])

    def test_returns_all_findings_without_exclude_service_filter(self):
        findings = [{"resource": "bucket-a", "service": "s3"}]

        self.assertEqual(findings, exclude_findings_by_service(findings, None))


class RiskyPortsTests(unittest.TestCase):
    def test_includes_smb_and_netbios_ports(self):
        self.assertTrue({139, 445}.issubset(RISKY_PORTS))

    def test_includes_winrm_and_memcached_ports(self):
        self.assertTrue({5985, 5986, 11211}.issubset(RISKY_PORTS))

    def test_includes_public_nfs_port(self):
        self.assertIn(2049, RISKY_PORTS)


class ErrorSanitizationTests(unittest.TestCase):
    def test_redacts_aws_credential_values_from_errors(self):
        message = (
            "failed for AKIAIOSFODNN7EXAMPLE with "
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        sanitized = sanitize_aws_error(message)

        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)
        self.assertNotIn("wJalrXUtnFEMI", sanitized)
        self.assertIn("[REDACTED_AWS_ACCESS_KEY]", sanitized)


class SummaryTests(unittest.TestCase):
    def test_summarizes_findings_by_status_severity_and_service(self):
        findings = [
            {"resource": "bucket-a", "service": "s3", "status": "fail", "severity": "high"},
            {"resource": "sg-1", "service": "security-group", "status": "fail", "severity": "high"},
            {"resource": "api", "service": "apigateway", "status": "warn", "severity": "info"},
        ]

        summary = summarize_findings(findings)

        self.assertEqual(3, summary["total"])
        self.assertEqual({"fail": 2, "warn": 1}, summary["by_status"])
        self.assertEqual({"high": 2, "info": 1}, summary["by_severity"])
        self.assertEqual(
            {"s3": 1, "security-group": 1, "apigateway": 1},
            summary["by_service"],
        )


class CliTests(unittest.TestCase):
    def test_lists_risky_ports_without_scanning_aws(self):
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = main(["--list-risky-ports"])

        self.assertEqual(0, exit_code)
        self.assertIn("445\n", output.getvalue())

    def test_emits_empty_json_summary(self):
        output = io.StringIO()

        with (
            patch("scripts.public_exposure_scan.list_public_s3_buckets", return_value=[]),
            patch("scripts.public_exposure_scan.list_public_ec2", return_value=[]),
            patch("scripts.public_exposure_scan.list_security_group_exposure", return_value=[]),
            patch("scripts.public_exposure_scan.list_api_gateways", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            exit_code = main(["--json", "--summary", "--exclude-service", "s3"])

        self.assertEqual(0, exit_code)
        self.assertIn('"summary"', output.getvalue())
        self.assertIn('"total": 0', output.getvalue())

    def test_fail_on_findings_returns_nonzero_after_filters(self):
        output = io.StringIO()
        finding = {
            "service": "security-group",
            "resource": "sg-1",
            "status": "fail",
            "severity": "high",
            "confidence": "high",
            "details": {"group_name": "web", "risky_rules": [{}]},
        }

        with (
            patch("scripts.public_exposure_scan.list_public_s3_buckets", return_value=[]),
            patch("scripts.public_exposure_scan.list_public_ec2", return_value=[]),
            patch("scripts.public_exposure_scan.list_security_group_exposure", return_value=[finding]),
            patch("scripts.public_exposure_scan.list_api_gateways", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            exit_code = main(["--fail-on-findings", "--service", "security-group"])

        self.assertEqual(2, exit_code)
        self.assertIn("sg-1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
