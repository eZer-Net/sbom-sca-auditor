import tempfile
import unittest
from pathlib import Path

from sbom_builder.detect import detect_projects
from sbom_builder.public_resolve import _node_specs, _python_specs


class ResolutionPolicyTests(unittest.TestCase):
    def test_python_only_exact_pin_is_download_eligible(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("requests==2.32.5\nflask>=3\nsix\n", encoding="utf-8")
            project = detect_projects(root)[0]
            exact, unresolved = _python_specs(project)
            self.assertEqual(exact, [("requests", "2.32.5")])
            self.assertEqual({r.get("name") for r in unresolved}, {"flask", "six"})

    def test_node_only_exact_semver_is_download_eligible(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(json.dumps({"dependencies": {"a": "1.2.3", "b": "^2.0.0", "c": "latest"}}), encoding="utf-8")
            project = detect_projects(root)[0]
            exact, unresolved = _node_specs(project)
            self.assertEqual(exact, {"a": "1.2.3"})
            self.assertEqual({r.get("name") for r in unresolved}, {"b", "c"})


if __name__ == "__main__":
    unittest.main()
