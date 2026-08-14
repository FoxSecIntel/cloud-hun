import unittest

from scripts.public_exposure_scan import filter_findings_by_min_severity, is_policy_public


class PolicyPublicTests(unittest.TestCase):
    def test_detects_public_principal_string(self):
        policy = '{"Statement": {"Effect": "Allow", "Principal": "*"}}'

        self.assertTrue(is_policy_public(policy))

    def test_ignores_deny_public_principal(self):
        policy = '{"Statement": {"Effect": "Deny", "Principal": "*"}}'

        self.assertFalse(is_policy_public(policy))


class SeverityFilterTests(unittest.TestCase):
    def test_filters_findings_below_minimum_severity(self):
        findings = [
            {"resource": "api", "severity": "info"},
            {"resource": "bucket", "severity": "medium"},
            {"resource": "sg", "severity": "high"},
        ]

        filtered = filter_findings_by_min_severity(findings, "medium")

        self.assertEqual(["bucket", "sg"], [finding["resource"] for finding in filtered])


if __name__ == "__main__":
    unittest.main()
