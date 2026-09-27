from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Dict, Iterable
from urllib.parse import quote

from .model import Project
from .tools import ensure_command, run_logged
from .local_generate import _component, _purl, _write_bom


def _copy_project(project: Project, work: Path, name: str) -> tuple[Project, Path]:
    dst = work / "native-resolution" / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        project.root,
        dst,
        ignore=shutil.ignore_patterns(
            ".git", ".scan-sca_osa", ".gradle", "build", "target", "node_modules",
            "__pycache__", ".venv", "venv", "bin", "obj", "vcpkg_installed",
        ),
    )
    try:
        rel = project.manifest.relative_to(project.root)
        manifest = dst / rel
    except ValueError:
        manifest = dst / project.manifest.name
    return Project(project.ecosystem, project.manager, dst, manifest, project.frameworks, project.warnings), dst


def _resolved_component(name: str, version: str, purl: str, source: str) -> dict:
    return _component(name, version, purl, properties=[
        {"name": "sbom-sca-auditor:version-source", "value": source},
    ])


def resolve_maven(project: Project, out: Path, work: Path, log: Path, install: bool) -> int:
    temp_project, cwd = _copy_project(project, work, out.stem + "-maven")
    mvn = ensure_command("mvn", ["maven"], log, install)
    tree_file = work / "native-resolution" / f"{out.stem}-maven-tree.txt"
    cp = run_logged([
        mvn, "-q", "-DskipTests", "dependency:tree",
        f"-DoutputFile={tree_file}", "-DappendOutput=false",
    ], cwd, log, check=False)
    if cp.returncode != 0 or not tree_file.exists():
        raise RuntimeError("Maven dependency resolution failed")

    coord = re.compile(r"^(?P<indent>(?:[| ]{3})*)(?P<branch>\+-|\\-)\s*(?P<g>[^:\s]+):(?P<a>[^:\s]+):(?P<t>[^:\s]+)(?::(?P<c>[^:\s]+))?:(?P<v>[^:\s]+):(?P<s>[^:\s]+)")
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    stack: list[str] = []
    for raw in tree_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip("\n")
        m = coord.search(line)
        if not m:
            continue
        group, name, version = m.group("g"), m.group("a"), m.group("v")
        if version in {"omitted", "FAILED"}:
            continue
        ref = _purl("maven", name, version, group)
        components.setdefault(ref, _resolved_component(name, version, ref, "maven-resolved"))
        edges.setdefault(ref, set())
        depth = len(m.group("indent")) // 3
        if depth == 0:
            edges["__root__"].add(ref)
        elif depth - 1 < len(stack):
            edges.setdefault(stack[depth - 1], set()).add(ref)
        if len(stack) <= depth:
            stack.extend([ref] * (depth + 1 - len(stack)))
        stack[depth] = ref
        del stack[depth + 1:]
    return _write_bom(temp_project, out, components.values(), edges, coverage="maven-resolved-direct-and-transitive", notes=["Dependency graph resolved by Maven dependency:tree."], allow_empty=False)


def _asset_target_graph(data: dict, source: str) -> tuple[Dict[str, dict], Dict[str, set[str]]]:
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    libraries = data.get("libraries") or {}
    targets = data.get("targets") or {}
    project = data.get("project") or {}
    frameworks = project.get("frameworks") or {}

    by_target_name: dict[tuple[str, str], str] = {}
    for tfm, entries in targets.items():
        if not isinstance(entries, dict):
            continue
        for key, meta in entries.items():
            if "/" not in key or not isinstance(meta, dict):
                continue
            name, version = key.rsplit("/", 1)
            lib_meta = libraries.get(key) if isinstance(libraries, dict) else None
            if isinstance(lib_meta, dict) and str(lib_meta.get("type") or "").lower() == "project":
                continue
            ref = _purl("nuget", name, version)
            components.setdefault(ref, _resolved_component(name, version, ref, source))
            edges.setdefault(ref, set())
            by_target_name[(str(tfm), name.lower())] = ref

    for tfm, entries in targets.items():
        if not isinstance(entries, dict):
            continue
        for key, meta in entries.items():
            if "/" not in key or not isinstance(meta, dict):
                continue
            name, _ = key.rsplit("/", 1)
            parent = by_target_name.get((str(tfm), name.lower()))
            if not parent:
                continue
            deps = meta.get("dependencies") or {}
            if isinstance(deps, dict):
                for child_name in deps:
                    child = by_target_name.get((str(tfm), str(child_name).lower()))
                    if child:
                        edges[parent].add(child)

    for tfm, fw in frameworks.items():
        if not isinstance(fw, dict):
            continue
        deps = fw.get("dependencies") or {}
        if isinstance(deps, dict):
            for name in deps:
                child = by_target_name.get((str(tfm), str(name).lower()))
                if child:
                    edges["__root__"].add(child)
    if not edges["__root__"]:
        incoming = {x for children in edges.values() for x in children}
        edges["__root__"].update(ref for ref in components if ref not in incoming)
    return components, edges


def resolve_dotnet(project: Project, out: Path, work: Path, log: Path, install: bool) -> int:
    temp_project, cwd = _copy_project(project, work, out.stem + "-dotnet")
    dotnet = ensure_command("dotnet", ["dotnet-sdk"], log, install)
    target = temp_project.manifest
    cp = run_logged([dotnet, "restore", str(target), "--nologo"], cwd, log, check=False)
    if cp.returncode != 0:
        raise RuntimeError("dotnet restore failed")
    assets = sorted(cwd.rglob("obj/project.assets.json"))
    if not assets:
        raise RuntimeError("dotnet restore produced no project.assets.json")
    all_components: Dict[str, dict] = {}
    all_edges: Dict[str, set[str]] = {"__root__": set()}
    for path in assets:
        data = json.loads(path.read_text(encoding="utf-8"))
        comps, edges = _asset_target_graph(data, "dotnet-restore")
        all_components.update(comps)
        for parent, children in edges.items():
            all_edges.setdefault(parent, set()).update(children)
    return _write_bom(temp_project, out, all_components.values(), all_edges, coverage="dotnet-restore-direct-and-transitive", notes=["Dependency graph resolved from NuGet project.assets.json generated by dotnet restore."], allow_empty=False)


def _split_go_vertex(value: str) -> tuple[str, str | None]:
    if "@" not in value:
        return value, None
    return value.rsplit("@", 1)[0], value.rsplit("@", 1)[1]


def resolve_go(project: Project, out: Path, work: Path, log: Path, install: bool) -> int:
    temp_project, cwd = _copy_project(project, work, out.stem + "-go")
    go = ensure_command("go", ["go"], log, install)
    cp = run_logged([go, "mod", "download"], cwd, log, check=False)
    if cp.returncode != 0:
        raise RuntimeError("go mod download failed")
    graph_file = work / "native-resolution" / f"{out.stem}-go-graph.txt"
    cp = run_logged([go, "mod", "graph"], cwd, log, stdout_file=graph_file, check=False)
    if cp.returncode != 0 or not graph_file.exists():
        raise RuntimeError("go mod graph failed")

    module_line = next((x.strip() for x in (cwd / "go.mod").read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip().startswith("module ")), "")
    root_module = module_line.split(None, 1)[1].strip() if module_line else ""
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}

    def ref_for(vertex: str) -> str | None:
        name, version = _split_go_vertex(vertex)
        if not version:
            return None
        ref = _purl("golang", name, version)
        components.setdefault(ref, _resolved_component(name, version, ref, "go-mod-resolved"))
        edges.setdefault(ref, set())
        return ref

    for raw in graph_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = raw.split()
        if len(parts) != 2:
            continue
        parent_v, child_v = parts
        child = ref_for(child_v)
        if not child:
            continue
        p_name, p_ver = _split_go_vertex(parent_v)
        if not p_ver or (root_module and p_name == root_module):
            edges["__root__"].add(child)
        else:
            parent = ref_for(parent_v)
            if parent:
                edges[parent].add(child)
    return _write_bom(temp_project, out, components.values(), edges, coverage="go-mod-direct-and-transitive", notes=["Dependency graph resolved by go mod graph."], allow_empty=True)


def _conan_ref_parts(ref: str) -> tuple[str, str] | None:
    clean = ref.split("#", 1)[0]
    clean = clean.split("@", 1)[0]
    if "/" not in clean or clean in {"conanfile", "cli"}:
        return None
    name, version = clean.split("/", 1)
    return name, version


def resolve_conan(project: Project, out: Path, work: Path, log: Path, install: bool) -> int:
    temp_project, cwd = _copy_project(project, work, out.stem + "-conan")
    conan = ensure_command("conan", ["conan"], log, install)
    graph_file = work / "native-resolution" / f"{out.stem}-conan.json"
    cp = run_logged([conan, "graph", "info", ".", "--format=json"], cwd, log, stdout_file=graph_file, check=False)
    if cp.returncode != 0 or not graph_file.exists():
        raise RuntimeError("Conan graph resolution failed")
    data = json.loads(graph_file.read_text(encoding="utf-8"))
    nodes = ((data.get("graph") or {}).get("nodes") or {})
    if not isinstance(nodes, dict):
        raise RuntimeError("Conan graph JSON has no nodes")
    components: Dict[str, dict] = {}
    node_ref: dict[str, str] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    root_ids: set[str] = set()
    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            continue
        parsed = _conan_ref_parts(str(node.get("ref") or ""))
        if not parsed:
            root_ids.add(str(node_id))
            continue
        name, version = parsed
        ref = f"pkg:conan/{quote(name, safe='')}@{quote(version, safe='')}"
        components.setdefault(ref, _resolved_component(name, version, ref, "conan-resolved"))
        node_ref[str(node_id)] = ref
        edges.setdefault(ref, set())
    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            continue
        parent = node_ref.get(str(node_id))
        deps = node.get("dependencies") or {}
        dep_ids: Iterable[str] = deps.keys() if isinstance(deps, dict) else []
        for dep_id in dep_ids:
            child = node_ref.get(str(dep_id))
            if not child:
                continue
            if str(node_id) in root_ids or parent is None:
                edges["__root__"].add(child)
            else:
                edges[parent].add(child)
    if not edges["__root__"]:
        incoming = {x for c in edges.values() for x in c}
        edges["__root__"].update(ref for ref in components if ref not in incoming)
    return _write_bom(temp_project, out, components.values(), edges, coverage="conan-resolved-direct-and-transitive", notes=["C/C++ dependency graph resolved by Conan graph info."], allow_empty=True)


def _parse_control(path: Path) -> list[dict]:
    paragraphs: list[dict] = []
    current: dict[str, str] = {}
    last_key: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines() + [""]:
        if not raw.strip():
            if current:
                paragraphs.append(current)
                current = {}
                last_key = None
            continue
        if raw[:1].isspace() and last_key:
            current[last_key] = current[last_key] + " " + raw.strip()
            continue
        if ":" in raw:
            key, value = raw.split(":", 1)
            current[key.strip()] = value.strip()
            last_key = key.strip()
    return paragraphs


def resolve_vcpkg(project: Project, out: Path, work: Path, log: Path, install: bool) -> int:
    temp_project, cwd = _copy_project(project, work, out.stem + "-vcpkg")
    vcpkg = ensure_command("vcpkg", ["vcpkg"], log, install)
    install_root = work / "native-resolution" / f"{out.stem}-vcpkg-installed"
    if install_root.exists():
        shutil.rmtree(install_root)
    cp = run_logged([vcpkg, "install", f"--x-install-root={install_root}"], cwd, log, env={"VCPKG_DISABLE_METRICS": "1"}, check=False)
    status = install_root / "vcpkg" / "status"
    if cp.returncode != 0 or not status.exists():
        raise RuntimeError("vcpkg dependency resolution failed")
    rows = _parse_control(status)
    components: Dict[str, dict] = {}
    by_name: dict[str, str] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for row in rows:
        name = row.get("Package", "").strip()
        version = (row.get("Version") or row.get("Version-String") or "").strip()
        if not name or not version:
            continue
        purl = f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='')}?package_manager=vcpkg"
        components.setdefault(purl, _resolved_component(name, version, purl, "vcpkg-resolved"))
        by_name[name] = purl
        edges.setdefault(purl, set())
    for row in rows:
        parent = by_name.get(row.get("Package", "").strip())
        if not parent:
            continue
        deps = row.get("Depends", "")
        for token in deps.split(","):
            name = token.strip().split()[0] if token.strip() else ""
            if name in by_name:
                edges[parent].add(by_name[name])
    try:
        manifest = json.loads((cwd / "vcpkg.json").read_text(encoding="utf-8"))
    except Exception:
        manifest = {}
    for dep in manifest.get("dependencies") or []:
        name = dep if isinstance(dep, str) else dep.get("name") if isinstance(dep, dict) else None
        if name and str(name) in by_name:
            edges["__root__"].add(by_name[str(name)])
    if not edges["__root__"]:
        incoming = {x for c in edges.values() for x in c}
        edges["__root__"].update(ref for ref in components if ref not in incoming)
    return _write_bom(temp_project, out, components.values(), edges, coverage="vcpkg-resolved-direct-and-transitive", notes=["C/C++ dependencies resolved by vcpkg in an isolated temporary install root."], allow_empty=True)
