import json
import tempfile
import unittest
from pathlib import Path

from sbom_builder.detect import detect_projects


class DetectTests(unittest.TestCase):
    def test_polyglot_and_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            backend = root / "backend"
            backend.mkdir()
            (backend / "pyproject.toml").write_text('[project]\ndependencies=["fastapi"]\n', encoding="utf-8")
            (backend / "uv.lock").write_text("version = 1\n", encoding="utf-8")

            frontend = root / "frontend"
            frontend.mkdir()
            (frontend / "package.json").write_text(json.dumps({"dependencies": {"react": "18"}, "workspaces": ["packages/*"]}), encoding="utf-8")
            (frontend / "package-lock.json").write_text("{}", encoding="utf-8")
            child = frontend / "packages" / "ui"
            child.mkdir(parents=True)
            (child / "package.json").write_text(json.dumps({"dependencies": {"react": "18"}}), encoding="utf-8")

            projects = detect_projects(root)
            keys = {(p.ecosystem, p.manager, p.root.name) for p in projects}
            self.assertIn(("python", "uv", "backend"), keys)
            self.assertIn(("node", "npm", "frontend"), keys)
            self.assertNotIn(("node", "npm", "ui"), keys)
            py = next(p for p in projects if p.ecosystem == "python")
            self.assertIn("FastAPI", py.frameworks)
            node = next(p for p in projects if p.ecosystem == "node")
            self.assertIn("React", node.frameworks)


if __name__ == "__main__":
    unittest.main()

class NodeManagerTests(unittest.TestCase):
    def test_package_manager_field_wins_over_stale_lockfile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(json.dumps({
                "packageManager": "npm@11.0.0",
                "dependencies": {"react": "18"}
            }), encoding="utf-8")
            (root / "yarn.lock").write_text("# stale yarn lock\n", encoding="utf-8")
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            projects = detect_projects(root)
            node = next(p for p in projects if p.ecosystem == "node")
            self.assertEqual(node.manager, "npm")
            self.assertTrue(any("multiple Node lockfiles" in w for w in node.warnings))

class NestedManifestCoverageTests(unittest.TestCase):
    def test_nested_python_manifest_does_not_hide_root_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("import django\nimport six\n", encoding="utf-8")
            qa = root / "tests" / "qa"
            qa.mkdir(parents=True)
            (qa / "pyproject.toml").write_text('[project]\nname="qa"\n', encoding="utf-8")
            (qa / "test_x.py").write_text("import pytest\n", encoding="utf-8")
            projects = detect_projects(root)
            py = {(p.manager, p.root) for p in projects if p.ecosystem == "python"}
            self.assertIn(("pyproject", qa), py)
            self.assertIn(("source", root), py)
            source = next(p for p in projects if p.ecosystem == "python" and p.manager == "source")
            self.assertIn(qa.resolve(), source.exclude_roots)

class SourceExtensionEvidenceTests(unittest.TestCase):
    def test_source_extensions_are_counted_for_detection_evidence(self):
        from sbom_builder.detect import source_extension_counts
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("import os\n", encoding="utf-8")
            (root / "worker.py").write_text("import sys\n", encoding="utf-8")
            (root / "frontend.ts").write_text("export const x = 1\n", encoding="utf-8")
            self.assertEqual(source_extension_counts(root, "python"), {".py": 2})
            self.assertEqual(source_extension_counts(root, "node"), {".ts": 1})
