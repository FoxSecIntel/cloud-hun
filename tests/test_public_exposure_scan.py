import unittest

from scripts.public_exposure_scan import (
    filter_findings_by_min_severity,
    filter_findings_by_status,
    is_policy_public,
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


if __name__ == "__main__":
    unittest.main()
