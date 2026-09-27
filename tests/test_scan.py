import json
import tempfile
import unittest
from pathlib import Path

from sbom_builder.scan import findings_with_paths, normalized_unresolved, vulnerability_summary, write_vulnerabilities


class ScanReportTests(unittest.TestCase):
    def test_transitive_path_is_preserved_as_ordered_array(self):
        sbom = {
            "metadata": {"component": {"type": "application", "name": "repo", "version": "local", "bom-ref": "root"}},
            "components": [
                {"type": "application", "name": "mod", "version": "local", "bom-ref": "mod"},
                {"type": "library", "name": "a", "version": "1", "bom-ref": "a"},
                {"type": "library", "name": "b", "version": "2", "bom-ref": "b"},
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["mod"]},
                {"ref": "mod", "dependsOn": ["a"]},
                {"ref": "a", "dependsOn": ["b"]},
                {"ref": "b"},
            ],
        }
        trivy = {"Results": [{"Vulnerabilities": [{
            "PkgName": "b", "InstalledVersion": "2", "VulnerabilityID": "CVE-X",
            "Severity": "HIGH", "FixedVersion": "3"
        }]}]}
        vulns, _ = findings_with_paths(sbom, trivy)
        self.assertEqual(vulns[0]["path"], [
            {"library": "repo", "version": "local"},
            {"library": "mod", "version": "local"},
            {"library": "a", "version": "1"},
            {"library": "b", "version": "2"},
        ])
        self.assertEqual(vulnerability_summary(vulns)["transitive"], 1)

    def test_vulnerability_result_has_only_requested_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vulnerabilities.json"
            vuln = {
                "id": "GHSA-X", "severity": "CRITICAL", "service": "app", "library": "lib",
                "installed_version": "1", "fixed_version": "2", "relation": "direct",
                "path": [{"library": "app", "version": "local"}, {"library": "lib", "version": "1"}],
            }
            write_vulnerabilities(path, [vuln])
            data = json.loads(path.read_text())
            self.assertEqual(set(data[0]), {
                "id", "severity", "service", "library", "installed_version",
                "fixed_version", "relation", "path",
            })

    def test_unresolved_is_minimal_and_translated(self):
        rows = [{
            "module": ".", "source": "public-pypi", "name": "foo",
            "reason": "public PyPI resolution failed; package/version was not included in SBOM"
        }]
        out = normalized_unresolved(rows)
        self.assertEqual(set(out[0]), {"service", "library", "description"})
        self.assertIn("PyPI", out[0]["description"])


if __name__ == "__main__":
    unittest.main()

class TrivyCommandTests(unittest.TestCase):
    def test_scan_trivy_respects_severity_and_update_flag(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from sbom_builder.scan import scan_trivy

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sbom = root / "bom.json"
            report = root / "trivy.json"
            log = root / "trivy.log"
            sbom.write_text('{}', encoding='utf-8')
            commands = []

            def fake_run(cmd, cwd, log_path, check=False):
                commands.append(list(cmd))
                if "sbom" in cmd:
                    report.write_text('{"Results": []}', encoding='utf-8')
                return SimpleNamespace(returncode=0)

            with patch("sbom_builder.scan.ensure_command", return_value="/usr/bin/trivy"), \
                 patch("sbom_builder.scan.run_logged", side_effect=fake_run):
                data = scan_trivy(
                    sbom, report, log,
                    severities=("CRITICAL", "HIGH", "MEDIUM"),
                    update_db=True,
                    install=False,
                )

            self.assertEqual(data, {"Results": []})
            self.assertEqual(commands[0][1:3], ["image", "--download-db-only"])
            self.assertIn("CRITICAL,HIGH,MEDIUM", commands[1])
            self.assertIn("--skip-db-update", commands[1])

    def test_scan_trivy_can_skip_database_update(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from sbom_builder.scan import scan_trivy

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sbom = root / "bom.json"
            report = root / "trivy.json"
            log = root / "trivy.log"
            sbom.write_text('{}', encoding='utf-8')
            commands = []

            def fake_run(cmd, cwd, log_path, check=False):
                commands.append(list(cmd))
                report.write_text('{"Results": []}', encoding='utf-8')
                return SimpleNamespace(returncode=0)

            with patch("sbom_builder.scan.ensure_command", return_value="/usr/bin/trivy"), \
                 patch("sbom_builder.scan.run_logged", side_effect=fake_run):
                scan_trivy(sbom, report, log, update_db=False, install=False)

            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0][1], "sbom")
            self.assertIn("--skip-db-update", commands[0])
