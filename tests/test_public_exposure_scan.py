import contextlib
import io
import unittest

from scripts.public_exposure_scan import (
    RISKY_PORTS,
    exclude_findings_by_service,
    filter_findings_by_min_severity,
    filter_findings_by_service,
    filter_findings_by_status,
    is_policy_public,
    main,
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


class CliTests(unittest.TestCase):
    def test_lists_risky_ports_without_scanning_aws(self):
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = main(["--list-risky-ports"])

        self.assertEqual(0, exit_code)
        self.assertIn("445\n", output.getvalue())


if __name__ == "__main__":
    unittest.main()
