import unittest

from sbom_builder import cli
from sbom_builder.config import DEFAULT_SEVERITIES


class CliTests(unittest.TestCase):
    def test_defaults_are_simple(self):
        args = cli.build_parser().parse_args([])
        self.assertEqual(args.path, ".")
        self.assertEqual(args.severity, DEFAULT_SEVERITIES)
        self.assertEqual(args.trivy_db_update, "yes")
        self.assertIsNone(args.output)

    def test_three_user_options_are_supported(self):
        args = cli.build_parser().parse_args([
            "/tmp/project",
            "--severity", "critical,high,medium",
            "--trivy-db-update", "no",
            "--output", "/tmp/report",
        ])
        self.assertEqual(args.path, "/tmp/project")
        self.assertEqual(args.severity, ("CRITICAL", "HIGH", "MEDIUM"))
        self.assertEqual(args.trivy_db_update, "no")
        self.assertEqual(args.output, "/tmp/report")

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["--severity", "urgent"])


if __name__ == "__main__":
    unittest.main()
