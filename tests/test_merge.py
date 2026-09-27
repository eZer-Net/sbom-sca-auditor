import json
import tempfile
import unittest
from pathlib import Path

from sbom_builder.merge import merge_sboms, stats


class MergeTests(unittest.TestCase):
    def test_merge_preserves_dependency_edges(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.json"
            b = root / "b.json"
            out = root / "merged.json"
            a.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": {"type": "application", "name": "a", "bom-ref": "a-root"}},
                "components": [{"type": "library", "name": "libx", "version": "1", "bom-ref": "x", "purl": "pkg:npm/libx@1"}],
                "dependencies": [{"ref": "a-root", "dependsOn": ["x"]}, {"ref": "x"}],
            }), encoding="utf-8")
            b.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": {"type": "application", "name": "b", "bom-ref": "b-root"}},
                "components": [{"type": "library", "name": "liby", "version": "2", "bom-ref": "y", "purl": "pkg:pypi/liby@2"}],
                "dependencies": [{"ref": "b-root", "dependsOn": ["y"]}, {"ref": "y"}],
            }), encoding="utf-8")
            merged = merge_sboms([("a", a), ("b", b)], out, "repo")
            s = stats(merged)
            self.assertEqual(s["components"], 4)  # two module roots + two libraries
            self.assertGreaterEqual(s["dependency_edges"], 4)  # aggregate->2 roots and each root->lib
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
