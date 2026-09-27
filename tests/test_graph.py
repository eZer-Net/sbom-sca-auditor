import tempfile
import unittest
from pathlib import Path

from sbom_builder.graph import write_dependency_graph_html


class DependencyGraphTests(unittest.TestCase):
    def test_html_contains_graph_and_vulnerability_data(self):
        sbom = {
            "metadata": {"component": {"type": "application", "name": "repo", "version": "local", "bom-ref": "root"}},
            "components": [
                {"type": "library", "name": "a", "version": "1.0.0", "bom-ref": "a"},
                {"type": "library", "name": "b", "version": "2.0.0", "bom-ref": "b"},
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["a"]},
                {"ref": "a", "dependsOn": ["b"]},
                {"ref": "b"},
            ],
        }
        vulns = [{
            "id": "CVE-X", "library": "b", "path": [], "installed_version": "2.0.0",
            "fixed_version": "2.0.1", "severity": "HIGH",
        }]
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "dependency-graph.html"
            write_dependency_graph_html(out, sbom, vulns)
            text = out.read_text(encoding="utf-8")
            self.assertIn("CVE-X", text)
            self.assertIn("2.0.1", text)
            self.assertIn("vulnerable dependency", text)
            self.assertIn('"from": "a", "to": "b"', text)
            self.assertIn("Vulnerable paths only", text)
            self.assertIn("text += `\\nNo HIGH/CRITICAL vulnerability in this scan`", text)


if __name__ == "__main__":
    unittest.main()
