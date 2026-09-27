import json
import tempfile
import unittest
from pathlib import Path

from sbom_builder.detect import detect_projects
from sbom_builder.local_generate import generate_local_project


class FetchModeTests(unittest.TestCase):
    def test_yarn_classic_local_lockfile_sbom(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(json.dumps({
                "name": "demo", "version": "1.0.0", "dependencies": {"a": "^1.0.0"},
            }))
            (root / "yarn.lock").write_text('''# yarn lockfile v1\n\na@^1.0.0:\n  version "1.2.0"\n  resolved "https://example.invalid/a.tgz"\n  dependencies:\n    b "^2.0.0"\n\nb@^2.0.0:\n  version "2.1.0"\n  resolved "https://example.invalid/b.tgz"\n''')
            project = detect_projects(root)[0]
            out = root / "bom.json"
            count = generate_local_project(project, out)
            self.assertEqual(count, 2)
            data = json.loads(out.read_text())
            self.assertGreaterEqual(sum(len(x.get("dependsOn", [])) for x in data["dependencies"]), 2)

    def test_npm_package_lock_local_sbom(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(json.dumps({"name": "demo", "dependencies": {"a": "^1"}}))
            (root / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0", "dependencies": {"a": "^1"}},
                    "node_modules/a": {"version": "1.2.0", "dependencies": {"b": "^2"}, "name": "a"},
                    "node_modules/b": {"version": "2.0.0", "name": "b"},
                }
            }))
            project = detect_projects(root)[0]
            out = root / "bom.json"
            count = generate_local_project(project, out)
            self.assertEqual(count, 2)

    def test_unpinned_python_is_excluded_and_reported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("requests\nflask>=3\nprivatepkg @ git+ssh://git@example/private.git\n", encoding="utf-8")
            project = detect_projects(root)[0]
            out = root / "bom.json"
            unresolved = root / "unresolved.json"
            count = generate_local_project(project, out, unresolved)
            self.assertEqual(count, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["components"], [])
            rows = json.loads(unresolved.read_text())
            self.assertEqual(len(rows), 3)

    def test_exact_python_pin_is_included(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("requests==2.32.5\n", encoding="utf-8")
            project = detect_projects(root)[0]
            out = root / "bom.json"
            unresolved = root / "unresolved.json"
            count = generate_local_project(project, out, unresolved)
            self.assertEqual(count, 1)
            data = json.loads(out.read_text())
            self.assertEqual(data["components"][0]["version"], "2.32.5")

    def test_source_only_python_creates_synthetic_manifest_without_guessing_versions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("import requests\nfrom flask import Flask\n", encoding="utf-8")
            py = next(p for p in detect_projects(root) if p.ecosystem == "python")
            sbom_dir = root / ".sbom-work" / "sboms"
            sbom_dir.mkdir(parents=True)
            out = sbom_dir / "python.cdx.json"
            unresolved = root / ".sbom-work" / "unresolved" / "python.json"
            count = generate_local_project(py, out, unresolved)
            self.assertEqual(count, 0)
            self.assertTrue((root / ".sbom-work" / "generated-manifests" / "inferred-python-requirements.in").exists())
            rows = json.loads(unresolved.read_text())
            self.assertEqual({r["name"] for r in rows}, {"requests", "flask"})


if __name__ == "__main__":
    unittest.main()

class PythonImportAliasTests(unittest.TestCase):
    def test_common_import_names_map_to_distribution_names(self):
        from sbom_builder.local_generate import _python_imports
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text(
                "import dateutil\nimport yaml\nimport OpenSSL\nimport rest_framework\nimport django\n",
                encoding="utf-8",
            )
            names = _python_imports(root)
            self.assertIn("python-dateutil", names)
            self.assertIn("PyYAML", names)
            self.assertIn("pyOpenSSL", names)
            self.assertIn("djangorestframework", names)
            self.assertIn("django", names)
