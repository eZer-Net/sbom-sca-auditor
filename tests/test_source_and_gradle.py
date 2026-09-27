import json
import tempfile
import unittest
from pathlib import Path

from sbom_builder.model import Project
from sbom_builder.public_resolve import _parse_gradle_dependencies, generate_public_project


class SourceAndGradleTests(unittest.TestCase):
    def test_source_only_node_stays_unresolved_without_latest_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            (root / "app.js").write_text("const axios = require('axios');", encoding="utf-8")
            project = Project("node", "source", root, root, [])
            out = Path(td) / "work" / "module-sboms" / "node.cdx.json"
            unresolved = Path(td) / "work" / "unresolved.json"
            log = Path(td) / "work" / "cmd.log"

            count = generate_public_project(project, out, Path(td) / "work", log, False, unresolved)

            self.assertEqual(count, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data.get("components"), [])
            rows = json.loads(unresolved.read_text(encoding="utf-8"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["name"], "axios")
            self.assertIsNone(rows[0]["declared"])
            self.assertIn("no exact package/version", rows[0]["reason"])

    def test_gradle_tree_becomes_transitive_cyclonedx_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest = root / "build.gradle"
            manifest.write_text("plugins { id 'java' }", encoding="utf-8")
            project = Project("java", "gradle", root, manifest, [])
            report = """runtimeClasspath - Runtime classpath\n+--- org.springframework:spring-core:6.1.0\n|    \\--- org.springframework:spring-jcl:6.1.0\n\\--- com.fasterxml.jackson.core:jackson-databind:2.17.0\n     +--- com.fasterxml.jackson.core:jackson-annotations:2.17.0\n     \\--- com.fasterxml.jackson.core:jackson-core:2.17.0\n"""
            out = root / "bom.json"
            count = _parse_gradle_dependencies(report, project, out)
            self.assertEqual(count, 5)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(data["components"]), 5)
            edges = {d["ref"]: d.get("dependsOn", []) for d in data["dependencies"]}
            spring = next(c["bom-ref"] for c in data["components"] if c["name"] == "spring-core")
            spring_jcl = next(c["bom-ref"] for c in data["components"] if c["name"] == "spring-jcl")
            self.assertIn(spring_jcl, edges[spring])


if __name__ == "__main__":
    unittest.main()
