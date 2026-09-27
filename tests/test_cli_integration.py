import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbom_builder import cli


class CliIntegrationTests(unittest.TestCase):
    def test_nested_lockfile_scan_creates_documented_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "project"
            frontend = root / "frontend"
            frontend.mkdir(parents=True)
            (frontend / "package.json").write_text(json.dumps({
                "name": "demo", "version": "1.0.0", "dependencies": {"a": "^1"},
            }), encoding="utf-8")
            (frontend / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0", "dependencies": {"a": "^1"}},
                    "node_modules/a": {"version": "1.2.0", "name": "a"},
                },
            }), encoding="utf-8")
            report = base / "report"
            trivy_result = {"Results": [{"Vulnerabilities": [{
                "PkgName": "a", "InstalledVersion": "1.2.0",
                "VulnerabilityID": "CVE-DEMO", "Severity": "HIGH", "FixedVersion": "1.2.1",
            }]}]}

            with patch("sbom_builder.cli.scan_trivy", return_value=trivy_result):
                rc = cli.main([
                    str(root), "--output", str(report),
                    "--severity", "CRITICAL,HIGH", "--trivy-db-update", "no",
                ])

            self.assertEqual(rc, 0)
            result = report / "result"
            for name in (
                "summary.json", "discovery.json", "bom.cdx.json",
                "vulnerabilities.json", "unresolved.json", "dependency-graph.html",
            ):
                self.assertTrue((result / name).exists(), name)

            discovery = json.loads((result / "discovery.json").read_text(encoding="utf-8"))
            self.assertEqual(discovery["modules"][0]["path"], "frontend")
            self.assertEqual(discovery["modules"][0]["dependency_source"], "lockfile")
            self.assertIn("package-lock.json", discovery["modules"][0]["dependency_files"])

            summary = json.loads((result / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["dependencies"]["included"], 1)
            self.assertEqual(summary["vulnerabilities"]["high"], 1)


if __name__ == "__main__":
    unittest.main()
