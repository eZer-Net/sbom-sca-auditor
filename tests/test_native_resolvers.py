import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

from sbom_builder.detect import detect_projects
from sbom_builder.model import Project
from sbom_builder.native_resolve import _asset_target_graph, resolve_go, resolve_maven, resolve_conan, resolve_vcpkg


class NativeResolverTests(unittest.TestCase):
    def test_python_manifest_range_is_resolver_input_not_latest_guess(self):
        from sbom_builder.public_resolve import _python_resolver_specs
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("requests>=2.31\nflask\n")
            project = Project("python", "pip", root, root / "requirements.txt")
            specs, direct, unresolved = _python_resolver_specs(project)
            self.assertIn("requests>=2.31", specs)
            self.assertIn("requests", direct)
            self.assertNotIn("flask", direct)
            self.assertTrue(any(row.get("name") == "flask" for row in unresolved))

    def test_detects_conan_cpp_project(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "conanfile.txt").write_text("[requires]\nzlib/1.3.1\n")
            (root / "main.cpp").write_text("#include <zlib.h>\n")
            projects = detect_projects(root)
            self.assertTrue(any(p.ecosystem == "cpp" and p.manager == "conan" for p in projects))

    def test_dotnet_assets_preserve_transitive_edge(self):
        data = {
            "targets": {
                "net8.0": {
                    "A/1.0.0": {"dependencies": {"B": "2.0.0"}},
                    "B/2.0.0": {}
                }
            },
            "libraries": {"A/1.0.0": {"type": "package"}, "B/2.0.0": {"type": "package"}},
            "project": {"frameworks": {"net8.0": {"dependencies": {"A": {"target": "Package", "version": "[1.0.0, )"}}}}}
        }
        components, edges = _asset_target_graph(data, "dotnet-restore")
        a = next(ref for ref in components if "/A@1.0.0" in ref)
        b = next(ref for ref in components if "/B@2.0.0" in ref)
        self.assertIn(a, edges["__root__"])
        self.assertIn(b, edges[a])

    def test_go_mod_graph_becomes_transitive_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"; root.mkdir()
            (root / "go.mod").write_text("module example.com/app\n\ngo 1.22\n")
            project = Project("go", "gomod", root, root / "go.mod")
            out = Path(td) / "bom.json"
            def fake_run(cmd, cwd, log, **kwargs):
                if kwargs.get("stdout_file"):
                    kwargs["stdout_file"].write_text(
                        "example.com/app example.com/a@v1.0.0\nexample.com/a@v1.0.0 example.com/b@v2.0.0\n"
                    )
                return CompletedProcess(cmd, 0)
            with patch("sbom_builder.native_resolve.ensure_command", return_value="go"), patch("sbom_builder.native_resolve.run_logged", side_effect=fake_run):
                resolve_go(project, out, Path(td) / "work", Path(td) / "log", False)
            bom = json.loads(out.read_text())
            deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
            a = next(c["bom-ref"] for c in bom["components"] if c["name"] == "example.com/a")
            b = next(c["bom-ref"] for c in bom["components"] if c["name"] == "example.com/b")
            self.assertIn(b, deps[a])

    def test_maven_tree_becomes_transitive_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"; root.mkdir()
            (root / "pom.xml").write_text("<project/>")
            project = Project("java", "maven", root, root / "pom.xml")
            out = Path(td) / "bom.json"
            def fake_run(cmd, cwd, log, **kwargs):
                output_arg = next((x for x in cmd if str(x).startswith("-DoutputFile=")), None)
                if output_arg:
                    Path(str(output_arg).split("=", 1)[1]).write_text(
                        "+- org.example:a:jar:1.0.0:compile\n"
                        "|  \\- org.example:b:jar:2.0.0:compile\n"
                    )
                return CompletedProcess(cmd, 0)
            with patch("sbom_builder.native_resolve.ensure_command", return_value="mvn"), patch("sbom_builder.native_resolve.run_logged", side_effect=fake_run):
                resolve_maven(project, out, Path(td) / "work", Path(td) / "log", False)
            bom = json.loads(out.read_text())
            deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
            a = next(c["bom-ref"] for c in bom["components"] if c["name"] == "a")
            b = next(c["bom-ref"] for c in bom["components"] if c["name"] == "b")
            self.assertIn(b, deps[a])

    def test_conan_graph_json_becomes_transitive_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"; root.mkdir()
            (root / "conanfile.txt").write_text("[requires]\nzlib/1.3.1\n")
            project = Project("cpp", "conan", root, root / "conanfile.txt")
            out = Path(td) / "bom.json"
            graph = {"graph": {"nodes": {
                "0": {"ref": "conanfile", "dependencies": {"1": {}}},
                "1": {"ref": "a/1.0#r", "dependencies": {"2": {}}},
                "2": {"ref": "b/2.0#r", "dependencies": {}}
            }}}
            def fake_run(cmd, cwd, log, **kwargs):
                kwargs["stdout_file"].write_text(json.dumps(graph))
                return CompletedProcess(cmd, 0)
            with patch("sbom_builder.native_resolve.ensure_command", return_value="conan"), patch("sbom_builder.native_resolve.run_logged", side_effect=fake_run):
                resolve_conan(project, out, Path(td) / "work", Path(td) / "log", False)
            bom = json.loads(out.read_text())
            deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
            a = next(c["bom-ref"] for c in bom["components"] if c["name"] == "a")
            b = next(c["bom-ref"] for c in bom["components"] if c["name"] == "b")
            self.assertIn(b, deps[a])

    def test_vcpkg_status_becomes_transitive_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"; root.mkdir()
            (root / "vcpkg.json").write_text(json.dumps({"dependencies": ["a"]}))
            project = Project("cpp", "vcpkg", root, root / "vcpkg.json")
            out = Path(td) / "bom.json"
            def fake_run(cmd, cwd, log, **kwargs):
                install_root = Path(next(x for x in cmd if str(x).startswith("--x-install-root=")).split("=", 1)[1])
                status = install_root / "vcpkg" / "status"; status.parent.mkdir(parents=True)
                status.write_text("Package: a\nVersion: 1.0\nDepends: b\n\nPackage: b\nVersion: 2.0\n\n")
                return CompletedProcess(cmd, 0)
            with patch("sbom_builder.native_resolve.ensure_command", return_value="vcpkg"), patch("sbom_builder.native_resolve.run_logged", side_effect=fake_run):
                resolve_vcpkg(project, out, Path(td) / "work", Path(td) / "log", False)
            bom = json.loads(out.read_text())
            deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
            a = next(c["bom-ref"] for c in bom["components"] if c["name"] == "a")
            b = next(c["bom-ref"] for c in bom["components"] if c["name"] == "b")
            self.assertIn(b, deps[a])


if __name__ == "__main__":
    unittest.main()
