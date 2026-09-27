import json
import tempfile
import unittest
from pathlib import Path

from sbom_builder.local_generate import generate_local_project
from sbom_builder.model import Project


class YarnClassicTests(unittest.TestCase):
    def test_lockfile_generates_transitive_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(json.dumps({
                "name": "app", "version": "1.0.0", "dependencies": {"a": "^1.0.0"},
            }), encoding="utf-8")
            (root / "yarn.lock").write_text('''# yarn lockfile v1

a@^1.0.0:
  version "1.0.0"
  dependencies:
    b "^2.0.0"

b@^2.0.0:
  version "2.0.0"
''', encoding="utf-8")

            out = root / "bom.cdx.json"
            project = Project("node", "yarn", root, root / "package.json")
            count = generate_local_project(project, out)
            self.assertEqual(count, 2)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["bomFormat"], "CycloneDX")
            depmap = {d["ref"]: set(d.get("dependsOn", [])) for d in data["dependencies"]}
            self.assertIn("pkg:npm/a@1.0.0", depmap)
            self.assertEqual(depmap["pkg:npm/a@1.0.0"], {"pkg:npm/b@2.0.0"})


if __name__ == "__main__":
    unittest.main()
