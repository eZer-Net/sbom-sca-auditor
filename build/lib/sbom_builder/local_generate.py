from __future__ import annotations

import ast
import csv
import json
import re
import tomllib
import uuid
import warnings
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from urllib.parse import quote
import xml.etree.ElementTree as ET

from .model import Project


def _purl(ecosystem: str, name: str, version: str, group: str | None = None) -> str:
    version_q = quote(str(version or "unknown"), safe="")
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, pkg = name.split("/", 1)
            return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{version_q}"
        return f"pkg:npm/{quote(name, safe='')}@{version_q}"
    if ecosystem == "pypi":
        return f"pkg:pypi/{quote(name, safe='')}@{version_q}"
    if ecosystem == "maven":
        return f"pkg:maven/{quote(group or '', safe='')}/{quote(name, safe='')}@{version_q}"
    if ecosystem == "golang":
        return f"pkg:golang/{quote(name, safe='/')}@{version_q}"
    if ecosystem == "cargo":
        return f"pkg:cargo/{quote(name, safe='')}@{version_q}"
    if ecosystem == "composer":
        return f"pkg:composer/{quote(name, safe='/')}@{version_q}"
    if ecosystem == "nuget":
        return f"pkg:nuget/{quote(name, safe='')}@{version_q}"
    return f"pkg:generic/{quote(name, safe='')}@{version_q}"


def _write_bom(project: Project, out: Path, components: Iterable[dict], edges: Dict[str, set[str]], *, coverage: str, notes: List[str] | None = None, allow_empty: bool = False) -> int:
    root_name = project.root.name
    root_version = "local"
    root_ref = f"urn:sbom-sca-auditor:local-root:{uuid.uuid5(uuid.NAMESPACE_URL, str(project.root.resolve()))}"
    root_children = edges.pop("__root__", set())
    deps = [{"ref": root_ref, **({"dependsOn": sorted(root_children)} if root_children else {})}]
    for ref, children in sorted(edges.items()):
        deps.append({"ref": ref, **({"dependsOn": sorted(children)} if children else {})})
    properties = [
        {"name": "sbom-sca-auditor:private-dependency-access", "value": "false"},
        {"name": "sbom-sca-auditor:generation-mode", "value": "local-metadata-or-source-inference"},
        {"name": "sbom-sca-auditor:coverage", "value": coverage},
        {"name": "sbom-sca-auditor:package-manager", "value": project.manager},
    ]
    for note in notes or []:
        properties.append({"name": "sbom-sca-auditor:note", "value": note})
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": root_name, "version": root_version, "bom-ref": root_ref},
            "properties": properties,
        },
        "components": sorted(list(components), key=lambda c: (c.get("name", ""), c.get("version", ""), c.get("purl", ""))),
        "dependencies": deps,
    }
    if not result["components"] and not allow_empty:
        raise RuntimeError("local generation found 0 scannable components")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(result["components"])


def _component(name: str, version: str, purl: str, *, license_name: str | None = None, properties: List[dict] | None = None) -> dict:
    c = {"type": "library", "name": name, "version": str(version), "bom-ref": purl, "purl": purl}
    if license_name:
        c["licenses"] = [{"license": {"name": license_name}}]
    if properties:
        c["properties"] = list(properties)
    return c


def _node_selector_parts(selector: str) -> Tuple[str, str]:
    s = selector.strip().strip('"').strip("'")
    if s.startswith("@"):
        slash = s.find("/")
        at = s.find("@", slash + 1) if slash >= 0 else -1
    else:
        at = s.find("@")
    if at <= 0:
        return s, ""
    return s[:at], s[at + 1 :]


def _split_yarn_selectors(header: str) -> List[str]:
    row = next(csv.reader([header], skipinitialspace=True))
    return [x.strip().strip('"') for x in row if x.strip()]


def _parse_yarn_v1(path: Path) -> List[dict]:
    entries: List[dict] = []
    current: dict | None = None
    dep_mode = False
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            if current:
                entries.append(current)
            header = raw.rstrip()[:-1]
            current = {"selectors": _split_yarn_selectors(header), "dependencies": {}}
            dep_mode = False
            continue
        if current is None:
            continue
        stripped = raw.strip()
        if raw.startswith("  ") and not raw.startswith("    "):
            dep_mode = False
            if stripped in {"dependencies:", "optionalDependencies:"}:
                dep_mode = True
                continue
            m = re.match(r'([A-Za-z][\w-]*)\s+"?(.*?)"?$', stripped)
            if m:
                key, value = m.group(1), m.group(2).strip('"')
                if key in {"version", "resolved", "integrity"}:
                    current[key] = value
        elif raw.startswith("    ") and dep_mode:
            m = re.match(r'("?[^"]+?"?)\s+"?(.*?)"?$', stripped)
            if m:
                name = m.group(1).strip('"')
                spec = m.group(2).strip('"')
                current["dependencies"][name] = spec
    if current:
        entries.append(current)
    return entries


def _static_yarn(project: Project, out: Path) -> int:
    lock = project.root / "yarn.lock"
    if not lock.exists():
        raise RuntimeError("local/public mode requires yarn.lock for static Yarn parsing")
    text = lock.read_text(encoding="utf-8", errors="ignore")
    if "__metadata:" in text:
        raise RuntimeError("static Yarn parser supports Yarn Classic v1 lockfiles; Yarn Berry uses public/native resolution fallback")
    entries = _parse_yarn_v1(lock)
    if not entries:
        raise RuntimeError("could not parse Yarn Classic lockfile")
    selector_map: Dict[str, dict] = {}
    by_name: Dict[str, List[dict]] = {}
    for e in entries:
        for sel in e["selectors"]:
            selector_map[sel] = e
            name, _ = _node_selector_parts(sel)
            by_name.setdefault(name, []).append(e)

    def resolve(name: str, spec: str) -> dict | None:
        exact = selector_map.get(f"{name}@{spec}")
        if exact:
            return exact
        candidates = by_name.get(name, [])
        if len(candidates) == 1:
            return candidates[0]
        for e in candidates:
            for sel in e["selectors"]:
                n, s = _node_selector_parts(sel)
                if n == name and s == spec:
                    return e
        return None

    components: Dict[str, dict] = {}
    entry_ref: Dict[int, str] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for e in entries:
        name = _node_selector_parts(e["selectors"][0])[0]
        version = str(e.get("version") or "unknown")
        ref = _purl("npm", name, version)
        entry_ref[id(e)] = ref
        components.setdefault(ref, _component(name, version, ref))
        edges.setdefault(ref, set())
    for e in entries:
        ref = entry_ref[id(e)]
        for dep_name, spec in e.get("dependencies", {}).items():
            child = resolve(dep_name, spec)
            if child:
                edges[ref].add(entry_ref[id(child)])

    try:
        root_meta = json.loads((project.root / "package.json").read_text(encoding="utf-8"))
    except Exception:
        root_meta = {}
    root_deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        val = root_meta.get(key)
        if isinstance(val, dict):
            root_deps.update({str(k): str(v) for k, v in val.items()})
    unresolved = []
    for name, spec in root_deps.items():
        e = resolve(name, spec)
        if e:
            edges["__root__"].add(entry_ref[id(e)])
        else:
            unresolved.append(name)
    notes = []
    if unresolved:
        notes.append("Some root dependencies could not be mapped to yarn.lock entries: " + ", ".join(sorted(unresolved)[:20]))
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-direct-and-transitive", notes=notes)


def _npm_lock_v2(project: Project, data: dict, out: Path) -> int:
    packages = data.get("packages") or {}
    if not isinstance(packages, dict) or not packages:
        raise RuntimeError("package-lock.json has no packages map")
    components: Dict[str, dict] = {}
    path_ref: Dict[str, str] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}

    def pkg_name(key: str, meta: dict) -> str:
        if meta.get("name"):
            return str(meta["name"])
        marker = "node_modules/"
        if marker in key:
            return key.rsplit(marker, 1)[1]
        return Path(key).name

    for key, meta in packages.items():
        if key == "" or not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if not version:
            continue
        name = pkg_name(key, meta)
        ref = _purl("npm", name, str(version))
        path_ref[key] = ref
        components.setdefault(ref, _component(name, str(version), ref, license_name=meta.get("license") if isinstance(meta.get("license"), str) else None))
        edges.setdefault(ref, set())

    def ancestor_keys(key: str) -> Iterable[str]:
        current = key
        while True:
            yield current
            marker = "/node_modules/"
            if marker not in current:
                break
            current = current.rsplit(marker, 1)[0]
        yield ""

    def resolve_path(parent_key: str, dep_name: str) -> str | None:
        for anc in ancestor_keys(parent_key):
            candidate = f"{anc}/node_modules/{dep_name}" if anc else f"node_modules/{dep_name}"
            if candidate in path_ref:
                return candidate
        return None

    root_meta = packages.get("") if isinstance(packages.get(""), dict) else {}
    for dep_name in list((root_meta.get("dependencies") or {}).keys()) + list((root_meta.get("devDependencies") or {}).keys()) + list((root_meta.get("optionalDependencies") or {}).keys()):
        child = resolve_path("", str(dep_name))
        if child:
            edges["__root__"].add(path_ref[child])
    for key, meta in packages.items():
        if key == "" or key not in path_ref or not isinstance(meta, dict):
            continue
        ref = path_ref[key]
        deps = {}
        for field in ("dependencies", "optionalDependencies"):
            val = meta.get(field)
            if isinstance(val, dict):
                deps.update(val)
        for dep_name in deps:
            child = resolve_path(key, str(dep_name))
            if child:
                edges[ref].add(path_ref[child])
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-direct-and-transitive")


def _npm_lock_v1(project: Project, data: dict, out: Path) -> int:
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}

    def walk(name: str, meta: dict, parent: str) -> str | None:
        if not isinstance(meta, dict):
            return None
        version = str(meta.get("version") or "unknown")
        ref = _purl("npm", name, version)
        components.setdefault(ref, _component(name, version, ref))
        edges.setdefault(ref, set())
        edges.setdefault(parent, set()).add(ref)
        nested = meta.get("dependencies") or {}
        if isinstance(nested, dict):
            for child_name, child_meta in nested.items():
                walk(str(child_name), child_meta, ref)
        return ref

    deps = data.get("dependencies") or {}
    if not isinstance(deps, dict) or not deps:
        raise RuntimeError("package-lock.json has no dependency inventory")
    for name, meta in deps.items():
        walk(str(name), meta, "__root__")
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-direct-and-transitive")


def _static_npm(project: Project, out: Path) -> int:
    lock = project.root / "package-lock.json"
    if not lock.exists():
        lock = project.root / "npm-shrinkwrap.json"
    if not lock.exists():
        raise RuntimeError("static npm parsing requires package-lock.json or npm-shrinkwrap.json")
    data = json.loads(lock.read_text(encoding="utf-8"))
    if isinstance(data.get("packages"), dict):
        return _npm_lock_v2(project, data, out)
    return _npm_lock_v1(project, data, out)



_SKIP_SOURCE_DIRS = {".git", ".hg", ".svn", ".sbom-work", ".scan-sca_osa", "node_modules", ".venv", "venv", "vendor", "target", "dist", "build", "__pycache__"}


def _u(unresolved: List[dict], project: Project, source: str, raw: str, reason: str, *, name: str | None = None, declared: str | None = None) -> None:
    unresolved.append({
        "ecosystem": project.ecosystem,
        "manager": project.manager,
        "module": str(project.root),
        "source": source,
        "raw": raw,
        "name": name,
        "declared": declared,
        "reason": reason,
    })


def _write_unresolved(path: Path | None, unresolved: List[dict]) -> None:
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(unresolved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _declared_component(ecosystem: str, name: str, spec: str | None, *, group: str | None = None, inferred: bool = False) -> dict:
    raw = (spec or "").strip()
    exact = None
    if ecosystem == "pypi":
        m = re.fullmatch(r"==\s*([^\s;]+)", raw)
        if m:
            exact = m.group(1)
    elif ecosystem in {"npm", "cargo", "nuget", "composer", "golang", "maven"}:
        if raw and not re.search(r"[<>=~^*|,\s]", raw) and not raw.startswith(("git", "ssh", "http", "file:", "workspace:", "link:")):
            exact = raw.lstrip("v")
    version = exact or "latest"
    purl = _purl(ecosystem, name, version, group)
    props = []
    if raw:
        props.append({"name": "sbom-sca-auditor:declared-spec", "value": raw})
    if not exact:
        props.append({"name": "sbom-sca-auditor:version-status", "value": "unresolved-latest"})
    if inferred:
        props.append({"name": "sbom-sca-auditor:source-inferred", "value": "true"})
    return _component(name, version, purl, properties=props)


def _iter_source_files(root: Path, suffixes: set[str], exclude_roots: tuple[Path, ...] = ()) -> Iterable[Path]:
    excluded = tuple(x.resolve() for x in exclude_roots)
    for path in root.rglob("*"):
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in _SKIP_SOURCE_DIRS for part in rel_parts):
            continue
        rp = path.resolve()
        if any(rp == x or x in rp.parents for x in excluded):
            continue
        if path.is_file() and path.suffix.lower() in suffixes:
            yield path


def _write_synthetic_manifest(out: Path, name: str, lines: Iterable[str]) -> Path:
    generated = out.parent.parent / "generated-manifests"
    generated.mkdir(parents=True, exist_ok=True)
    path = generated / name
    path.write_text("\n".join(sorted(set(lines))) + "\n", encoding="utf-8")
    return path


def _python_imports(root: Path, exclude_roots: tuple[Path, ...] = ()) -> set[str]:
    imports: set[str] = set()
    for path in _iter_source_files(root, {".py"}, exclude_roots):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imports.add(node.module.split(".", 1)[0])
    stdlib = set(getattr(sys, "stdlib_module_names", set())) | {"__future__"}
    imports = {x for x in imports if x and x not in stdlib and not (root / f"{x}.py").exists() and not (root / x).exists()}
    # Import names and distribution names are not always the same. Keep a
    # conservative mapping for well-known, unambiguous Python packages.
    aliases = {
        "dateutil": "python-dateutil",
        "rest_framework": "djangorestframework",
        "yaml": "PyYAML",
        "OpenSSL": "pyOpenSSL",
        "PIL": "Pillow",
        "bs4": "beautifulsoup4",
        "sklearn": "scikit-learn",
        "jwt": "PyJWT",
    }
    return {aliases.get(name, name) for name in imports}


def _node_imports(root: Path, exclude_roots: tuple[Path, ...] = ()) -> set[str]:
    packages: set[str] = set()
    pattern = re.compile(r"(?:from\s+|require\s*\(\s*|import\s*\(\s*)[\"']([^\"']+)[\"']")
    builtin = {"fs", "path", "url", "util", "events", "stream", "http", "https", "crypto", "os", "assert", "buffer", "child_process", "zlib", "querystring", "tty", "net", "tls", "dns", "module", "worker_threads"}
    for path in _iter_source_files(root, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"}, exclude_roots):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for raw in pattern.findall(text):
            if raw.startswith((".", "/", "node:")) or raw in builtin:
                continue
            if raw.startswith("@"):
                parts = raw.split("/")
                if len(parts) >= 2:
                    packages.add("/".join(parts[:2]))
            else:
                packages.add(raw.split("/", 1)[0])
    return packages


def _generic_source_tokens(project: Project) -> set[str]:
    tokens: set[str] = set()
    if project.ecosystem == "go":
        pat = re.compile(r'"([^"\s]+\.[^"\s]+)"')
        for path in _iter_source_files(project.root, {".go"}, project.exclude_roots):
            tokens.update(x for x in pat.findall(path.read_text(encoding="utf-8", errors="ignore")) if not x.startswith(("./", "../")))
    elif project.ecosystem == "rust":
        pat = re.compile(r"(?m)^\s*(?:use|extern\s+crate)\s+([A-Za-z_][A-Za-z0-9_]*)")
        for path in _iter_source_files(project.root, {".rs"}, project.exclude_roots):
            tokens.update(x for x in pat.findall(path.read_text(encoding="utf-8", errors="ignore")) if x not in {"std", "core", "alloc", "crate", "self", "super"})
    elif project.ecosystem == "java":
        pat = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z0-9_.]+)")
        for path in _iter_source_files(project.root, {".java", ".kt", ".kts"}, project.exclude_roots):
            for imp in pat.findall(path.read_text(encoding="utf-8", errors="ignore")):
                parts = imp.split(".")
                if len(parts) >= 2 and parts[0] not in {"java", "javax", "kotlin"}:
                    tokens.add(".".join(parts[:2]))
    elif project.ecosystem == "dotnet":
        pat = re.compile(r"(?m)^\s*(?:global\s+)?using\s+([A-Za-z0-9_.]+)")
        for path in _iter_source_files(project.root, {".cs", ".fs", ".vb"}, project.exclude_roots):
            tokens.update(pat.findall(path.read_text(encoding="utf-8", errors="ignore")))
    elif project.ecosystem == "php":
        pat = re.compile(r"(?m)^\s*use\s+([A-Za-z0-9_\\]+)")
        for path in _iter_source_files(project.root, {".php"}, project.exclude_roots):
            for imp in pat.findall(path.read_text(encoding="utf-8", errors="ignore")):
                parts = imp.split("\\")
                if len(parts) >= 2:
                    tokens.add("\\".join(parts[:2]))
    elif project.ecosystem == "cpp":
        pat = re.compile(r'(?m)^\s*#\s*include\s*[<"]([^>"]+)[>"]')
        for path in _iter_source_files(project.root, {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}, project.exclude_roots):
            for header in pat.findall(path.read_text(encoding="utf-8", errors="ignore")):
                if not header.startswith(("./", "../")):
                    tokens.add(header)
    return tokens


def _static_source(project: Project, out: Path, unresolved: List[dict]) -> int:
    edges: Dict[str, set[str]] = {"__root__": set()}
    generated_dir = out.parent.parent / "generated-manifests"
    generated_dir.mkdir(parents=True, exist_ok=True)

    if project.ecosystem == "python":
        names = sorted(_python_imports(project.root, project.exclude_roots))
        # Source imports are evidence only. Without dependency metadata, no
        # package version is invented or added to the SBOM.
        (generated_dir / "inferred-python-requirements.in").write_text(
            "\n".join(names) + ("\n" if names else ""), encoding="utf-8"
        )
        manifest_rows = [{"name": n, "requestedVersion": None, "source": "source-import"} for n in names]
    elif project.ecosystem == "node":
        names = sorted(_node_imports(project.root, project.exclude_roots))
        (generated_dir / "inferred-package.json").write_text(
            json.dumps({"name": project.root.name, "private": True, "dependencies": {n: "unknown" for n in names}}, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest_rows = [{"name": n, "requestedVersion": None, "source": "source-import"} for n in names]
    else:
        names = sorted(_generic_source_tokens(project))
        manifest_rows = [{"name": n, "requestedVersion": None, "source": "source-import"} for n in names]

    (generated_dir / f"inferred-{project.ecosystem}-dependencies.json").write_text(
        json.dumps(manifest_rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    for row in manifest_rows:
        _u(
            unresolved,
            project,
            "source-import",
            row["name"],
            "dependency inferred from source but no exact package/version was resolved; excluded from SBOM",
            name=row["name"],
            declared=None,
        )
    return _write_bom(
        project,
        out,
        [],
        edges,
        coverage="source-inferred-unresolved",
        notes=["Synthetic dependency manifest generated from source imports. Only resolver-confirmed package/version pairs are eligible for the SBOM."],
        allow_empty=True,
    )

def _static_node_manifest(project: Project, out: Path, unresolved: List[dict]) -> int:
    path = project.root / "package.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec_v in deps.items():
            spec = str(spec_v).strip()
            # Exact manifest versions are safe to record. Ranges/tags/VCS/local
            # references are not exact resolved versions and therefore stay out
            # of the SBOM unless a resolver resolves them first.
            exact = bool(spec) and not re.search(r"[<>=~^*|,\s]", spec) and not spec.startswith(("git", "ssh", "http", "file:", "workspace:", "link:"))
            if not exact:
                reason = "non-registry/private/VCS/local dependency was not resolved" if spec.startswith(("git", "ssh", "http", "file:", "workspace:", "link:")) or "bitbucket" in spec.lower() else "version is not an exact resolved version"
                _u(unresolved, project, "package.json", f"{name}: {spec or 'latest'}", reason + "; excluded from SBOM", name=str(name), declared=spec or "latest")
                continue
            version = spec.lstrip("v")
            ref = _purl("npm", str(name), version)
            components[ref] = _component(str(name), version, ref)
            edges["__root__"].add(ref)
    return _write_bom(
        project, out, components.values(), edges,
        coverage="manifest-exact-direct-only",
        notes=["Only exact manifest versions are recorded; ranges/tags/VCS dependencies require resolution for inclusion and transitives."],
        allow_empty=True,
    )

def _static_pyproject(project: Project, out: Path, unresolved: List[dict]) -> int:
    path = project.root / "pyproject.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries: List[str] = []
    proj = data.get("project")
    if isinstance(proj, dict) and isinstance(proj.get("dependencies"), list):
        entries.extend(str(x) for x in proj["dependencies"])
    poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies")
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if str(name).lower() == "python":
                    continue
                if isinstance(spec, str):
                    entries.append(f"{name}{spec if spec.startswith(('=', '<', '>', '~', '^')) else '==' + spec}")
                elif isinstance(spec, dict) and spec.get("version"):
                    entries.append(f"{name}{spec['version']}")
                else:
                    entries.append(str(name))
    return _requirements_entries_to_bom(project, out, entries, unresolved, source="pyproject.toml", coverage="manifest-direct-only")


def _parse_requirement_line(line: str) -> tuple[str | None, str | None, str | None]:
    clean = line.strip()
    clean = re.sub(r"\s+#.*$", "", clean).strip()
    if not clean:
        return None, None, None
    if clean.startswith(("-r", "--requirement", "-c", "--constraint")):
        return None, None, "include-directive"
    if clean.startswith(("--", "git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:")):
        return None, None, "vcs-url-option"
    clean = clean.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*@\s*(.+)$", clean)
    if m:
        return m.group(1), m.group(2).strip(), "direct-url"
    m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", clean)
    if not m:
        return None, None, "unparsed"
    return m.group(1), m.group(2).strip(), None


def _requirements_entries_to_bom(project: Project, out: Path, entries: Iterable[str], unresolved: List[dict], *, source: str, coverage: str) -> int:
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for raw in entries:
        name, spec, problem = _parse_requirement_line(raw)
        if problem:
            _u(unresolved, project, source, raw, f"{problem}; excluded from SBOM", name=name, declared=spec)
            continue
        if not name:
            continue
        m = re.fullmatch(r"==\s*([^\s;]+)", spec or "")
        if not m:
            _u(
                unresolved,
                project,
                source,
                raw,
                "dependency has no exact resolved version; excluded from SBOM until resolver returns a concrete version",
                name=name,
                declared=spec or "latest",
            )
            continue
        version = m.group(1)
        ref = _purl("pypi", name, version)
        components[ref] = _component(name, version, ref)
        edges["__root__"].add(ref)
    return _write_bom(
        project,
        out,
        components.values(),
        edges,
        coverage=coverage,
        notes=["Only exact package versions are included. Unpinned/ranged/VCS entries are excluded and reported separately."],
        allow_empty=True,
    )

def _collect_requirement_entries(project: Project, unresolved: List[dict]) -> List[str]:
    seen: set[Path] = set()
    entries: List[str] = []

    def visit(path: Path) -> None:
        path = path.resolve()
        if path in seen or not path.exists():
            return
        seen.add(path)
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            # Keep URL fragments intact; only strip whitespace comments.
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(?:-r|--requirement)\s+(.+)$", line)
            if m:
                child = (path.parent / m.group(1).strip()).resolve()
                if child.exists():
                    visit(child)
                else:
                    _u(unresolved, project, str(path.name), raw, "referenced requirements file not found", declared=m.group(1).strip())
                continue
            m = re.match(r"^(?:-c|--constraint)\s+(.+)$", line)
            if m:
                constraint = (path.parent / m.group(1).strip()).resolve()
                if constraint.exists():
                    visit(constraint)
                else:
                    _u(unresolved, project, str(path.name), raw, "referenced constraints file not found", declared=m.group(1).strip())
                continue
            entries.append(line)

    for req in sorted(project.root.glob("requirements*.txt")):
        visit(req)
    return entries


def _static_pip_requirements(project: Project, out: Path, unresolved: List[dict] | None = None) -> int:
    unresolved = unresolved if unresolved is not None else []
    entries = _collect_requirement_entries(project, unresolved)
    return _requirements_entries_to_bom(project, out, entries, unresolved, source="requirements", coverage="requirements-direct-inventory")

def _static_pnpm(project: Project, out: Path) -> int:
    lock = project.root / "pnpm-lock.yaml"
    if not lock.exists():
        raise RuntimeError("local pnpm mode requires pnpm-lock.yaml")
    text = lock.read_text(encoding="utf-8", errors="ignore")
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    # Supports common pnpm lockfile package/snapshot keys without requiring a YAML library.
    # v9 examples: "  '@scope/pkg@1.2.3':" / "  foo@1.2.3:".
    # older examples: "  /foo/1.2.3:" / "  /@scope/foo/1.2.3:".
    in_packages = False
    for raw in text.splitlines():
        if re.match(r"^(packages|snapshots):\s*$", raw):
            in_packages = True
            continue
        if in_packages and raw and not raw.startswith(" "):
            in_packages = False
        if not in_packages:
            continue
        m = re.match(r"^\s{2}['\"]?([^'\"]+)['\"]?:\s*$", raw)
        if not m:
            continue
        key = m.group(1).strip()
        name = version = None
        if key.startswith("/"):
            parts = key.strip("/").split("/")
            if parts and parts[0].startswith("@") and len(parts) >= 3:
                name = "/".join(parts[:2]); version = parts[2]
            elif len(parts) >= 2:
                name, version = parts[0], parts[1]
        else:
            # Ignore peer suffixes such as "(react@18...)" when deriving the component version.
            base = key.split("(", 1)[0]
            if base.startswith("@"):
                slash = base.find("/")
                at = base.find("@", slash + 1) if slash >= 0 else -1
            else:
                at = base.rfind("@")
            if at > 0:
                name, version = base[:at], base[at + 1:]
        if name and version and version not in {"link:", "workspace:"}:
            ref = _purl("npm", name, version)
            components.setdefault(ref, _component(name, version, ref))
            edges["__root__"].add(ref)
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-component-inventory", notes=["pnpm local mode extracts all local lockfile package versions; exact parent-child edges are not reconstructed"])


def _static_python_lock(project: Project, out: Path) -> int:
    if project.manager == "uv":
        lock = project.root / "uv.lock"
    elif project.manager == "poetry":
        lock = project.root / "poetry.lock"
    else:
        return _static_pip_requirements(project, out)
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    packages = data.get("package") or []
    if not isinstance(packages, list) or not packages:
        raise RuntimeError(f"{lock.name} contains no package inventory")
    components: Dict[str, dict] = {}
    by_name: Dict[str, List[Tuple[dict, str]]] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "")
        version = str(pkg.get("version") or "")
        if not name or not version:
            continue
        ref = _purl("pypi", name, version)
        components.setdefault(ref, _component(name, version, ref))
        by_name.setdefault(name.lower().replace("_", "-"), []).append((pkg, ref))
        edges.setdefault(ref, set())

    def dep_items(pkg: dict) -> Iterable[Tuple[str, str | None]]:
        deps = pkg.get("dependencies")
        if isinstance(deps, dict):
            for n, spec in deps.items():
                yield str(n), None
        elif isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str):
                    yield dep, None
                elif isinstance(dep, dict) and dep.get("name"):
                    yield str(dep["name"]), str(dep.get("version")) if dep.get("version") else None

    for pkg_list in by_name.values():
        for pkg, ref in pkg_list:
            for dep_name, dep_version in dep_items(pkg):
                candidates = by_name.get(dep_name.lower().replace("_", "-"), [])
                child_ref = None
                if dep_version:
                    for cpkg, cref in candidates:
                        if str(cpkg.get("version")) == dep_version:
                            child_ref = cref; break
                if child_ref is None and len(candidates) == 1:
                    child_ref = candidates[0][1]
                if child_ref:
                    edges[ref].add(child_ref)

    # Infer local/root package(s): lock packages that point to current project or whose name matches pyproject.
    root_names: set[str] = set()
    pyproject = project.root / "pyproject.toml"
    if pyproject.exists():
        try:
            pydata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            for section in (pydata.get("project"), (pydata.get("tool") or {}).get("poetry")):
                if isinstance(section, dict) and section.get("name"):
                    root_names.add(str(section["name"]).lower().replace("_", "-"))
        except Exception:
            pass
    for name, pkg_list in by_name.items():
        if name in root_names:
            for _, ref in pkg_list:
                edges["__root__"].add(ref)
    if not edges["__root__"]:
        # Keep all components discoverable without fabricating package-to-package edges.
        edges["__root__"].update(ref for ref in components)
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-direct-and-transitive")


def _static_go(project: Project, out: Path) -> int:
    text = (project.root / "go.mod").read_text(encoding="utf-8", errors="ignore")
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_require = True; continue
        if in_require and line == ")":
            in_require = False; continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            ref = _purl("golang", name, version)
            components.setdefault(ref, _component(name, version, ref))
            edges["__root__"].add(ref)
    return _write_bom(project, out, components.values(), edges, coverage="manifest-resolved-module-inventory", notes=["go.mod lists direct and indirect modules; exact transitive parent edges are not reconstructed in local mode"])


def _static_cargo(project: Project, out: Path) -> int:
    lock = project.root / "Cargo.lock"
    if not lock.exists():
        raise RuntimeError("local Rust mode requires Cargo.lock")
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    pkgs = data.get("package") or []
    components: Dict[str, dict] = {}
    by_name: Dict[str, List[Tuple[dict, str]]] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for pkg in pkgs:
        if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("version"):
            continue
        name, version = str(pkg["name"]), str(pkg["version"])
        ref = _purl("cargo", name, version)
        components.setdefault(ref, _component(name, version, ref))
        by_name.setdefault(name, []).append((pkg, ref))
        edges.setdefault(ref, set())
    dep_re = re.compile(r"^([^ ]+)(?: ([^ ]+))?")
    for plist in by_name.values():
        for pkg, ref in plist:
            for dep in pkg.get("dependencies") or []:
                if not isinstance(dep, str):
                    continue
                m = dep_re.match(dep)
                if not m:
                    continue
                name, ver = m.group(1), m.group(2)
                candidates = by_name.get(name, [])
                child = None
                if ver:
                    child = next((cref for cpkg, cref in candidates if str(cpkg.get("version")) == ver), None)
                if child is None and len(candidates) == 1:
                    child = candidates[0][1]
                if child:
                    edges[ref].add(child)
    # Root package isn't normally in Cargo.lock; connect roots to components with no incoming edge.
    incoming = {c for children in edges.values() for c in children}
    edges["__root__"].update(ref for ref in components if ref not in incoming)
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-direct-and-transitive")


def _static_composer(project: Project, out: Path) -> int:
    lock = project.root / "composer.lock"
    if not lock.exists():
        raise RuntimeError("local PHP mode requires composer.lock")
    data = json.loads(lock.read_text(encoding="utf-8"))
    packages = list(data.get("packages") or []) + list(data.get("packages-dev") or [])
    components: Dict[str, dict] = {}
    by_name: Dict[str, str] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for pkg in packages:
        if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("version"):
            continue
        name, version = str(pkg["name"]), str(pkg["version"])
        ref = _purl("composer", name, version)
        by_name[name] = ref
        lic = None
        if isinstance(pkg.get("license"), list) and pkg["license"]:
            lic = str(pkg["license"][0])
        components.setdefault(ref, _component(name, version, ref, license_name=lic))
        edges.setdefault(ref, set())
    for pkg in packages:
        if not isinstance(pkg, dict) or str(pkg.get("name")) not in by_name:
            continue
        ref = by_name[str(pkg["name"])]
        for field in ("require", "require-dev"):
            req = pkg.get(field)
            if isinstance(req, dict):
                for dep_name in req:
                    if dep_name in by_name:
                        edges[ref].add(by_name[dep_name])
    try:
        manifest = json.loads((project.root / "composer.json").read_text(encoding="utf-8"))
    except Exception:
        manifest = {}
    for field in ("require", "require-dev"):
        req = manifest.get(field)
        if isinstance(req, dict):
            for dep_name in req:
                if dep_name in by_name:
                    edges["__root__"].add(by_name[dep_name])
    return _write_bom(project, out, components.values(), edges, coverage="lockfile-direct-and-transitive")


def _static_dotnet(project: Project, out: Path, unresolved: List[dict]) -> int:
    candidates = list(project.root.glob("packages.lock.json")) + list(project.root.glob("**/packages.lock.json"))
    if not candidates:
        candidates = list(project.root.glob("**/obj/project.assets.json"))
    if not candidates:
        _u(unresolved, project, str(project.manifest.name), str(project.manifest.name), "no packages.lock.json/project.assets.json; exact NuGet inventory cannot be determined")
        return _write_bom(project, out, [], {"__root__": set()}, coverage="nuget-unresolved", allow_empty=True)
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    for path in candidates:
        data = json.loads(path.read_text(encoding="utf-8"))
        if path.name == "packages.lock.json":
            deps_by_tf = data.get("dependencies") or {}
            for _, deps in deps_by_tf.items():
                if not isinstance(deps, dict):
                    continue
                for name, meta in deps.items():
                    if not isinstance(meta, dict):
                        continue
                    version = str(meta.get("resolved") or "").strip().lstrip("[").rstrip("]")
                    if not version:
                        _u(unresolved, project, path.name, str(name), "NuGet package has no exact resolved version; excluded from SBOM", name=str(name))
                        continue
                    ref = _purl("nuget", str(name), version)
                    components.setdefault(ref, _component(str(name), version, ref))
                    edges.setdefault(ref, set())
                    if str(meta.get("type", "")).lower() == "direct":
                        edges["__root__"].add(ref)
        else:
            libs = data.get("libraries") or {}
            for key, meta in libs.items():
                if "/" not in key:
                    continue
                name, version = key.rsplit("/", 1)
                if not version:
                    continue
                ref = _purl("nuget", name, version)
                components.setdefault(ref, _component(name, version, ref))
                edges["__root__"].add(ref)
    return _write_bom(project, out, components.values(), edges, coverage="local-restore-inventory", notes=["NuGet local metadata may not preserve all parent-child edges."], allow_empty=True)

def _static_maven(project: Project, out: Path, unresolved: List[dict]) -> int:
    pom = project.root / "pom.xml"
    tree = ET.parse(pom)
    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"
    props = {}
    props_el = root.find(f"{ns}properties")
    if props_el is not None:
        for child in props_el:
            props[child.tag.split("}")[-1]] = (child.text or "").strip()
    components = []
    edges: Dict[str, set[str]] = {"__root__": set()}
    deps_el = root.find(f"{ns}dependencies")
    if deps_el is not None:
        for dep in deps_el.findall(f"{ns}dependency"):
            group = (dep.findtext(f"{ns}groupId") or "").strip()
            name = (dep.findtext(f"{ns}artifactId") or "").strip()
            version = (dep.findtext(f"{ns}version") or "").strip()
            if version.startswith("${") and version.endswith("}"):
                version = props.get(version[2:-1], "")
            if not group or not name or not version or "${" in version:
                _u(unresolved, project, "pom.xml", f"{group}:{name}:{version or '?'}", "Maven dependency has no exact locally-resolved version; excluded from SBOM", name=name or None, declared=version or None)
                continue
            ref = _purl("maven", name, version, group)
            components.append(_component(name, version, ref))
            edges["__root__"].add(ref)
    return _write_bom(project, out, components, edges, coverage="manifest-exact-direct-only", notes=["Maven transitive dependencies require native resolution."], allow_empty=True)

def _static_gradle(project: Project, out: Path, unresolved: List[dict]) -> int:
    text = "\n".join((project.root / n).read_text(encoding="utf-8", errors="ignore") for n in ("build.gradle", "build.gradle.kts") if (project.root / n).exists())
    pattern = re.compile(r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*[\"\']([^:\"\']+):([^:\"\']+):([^\"\']+)[\"\']')
    components = []
    edges: Dict[str, set[str]] = {"__root__": set()}
    for group, name, version in pattern.findall(text):
        version = version.strip()
        if not version or any(token in version for token in ("$", "+", "[", "]", "(", ")")):
            _u(unresolved, project, project.manifest.name, f"{group}:{name}:{version}", "Gradle dependency version is dynamic/unresolved; excluded from SBOM", name=name, declared=version)
            continue
        ref = _purl("maven", name, version, group)
        components.append(_component(name, version, ref))
        edges["__root__"].add(ref)
    return _write_bom(project, out, components, edges, coverage="manifest-exact-direct-only", notes=["Gradle transitive dependencies require native resolution."], allow_empty=True)

def _static_cpp_manifest(project: Project, out: Path, unresolved: List[dict]) -> int:
    names: list[str] = []
    if project.manager == "vcpkg" and (project.root / "vcpkg.json").exists():
        try:
            data = json.loads((project.root / "vcpkg.json").read_text(encoding="utf-8"))
            for dep in data.get("dependencies") or []:
                name = dep if isinstance(dep, str) else dep.get("name") if isinstance(dep, dict) else None
                if name:
                    names.append(str(name))
        except Exception:
            pass
    elif project.manager == "conan":
        text = project.manifest.read_text(encoding="utf-8", errors="ignore")
        if project.manifest.name == "conanfile.txt":
            in_requires = False
            for raw in text.splitlines():
                line = raw.strip()
                if line.startswith("["):
                    in_requires = line.lower() == "[requires]"
                    continue
                if in_requires and line and not line.startswith("#"):
                    names.append(line)
    for name in sorted(set(names)):
        _u(unresolved, project, project.manifest.name, name, "C/C++ dependency metadata was found but a native Conan/vcpkg resolved graph was not available; excluded from SBOM", name=name)
    return _write_bom(project, out, [], {"__root__": set()}, coverage="cpp-native-resolution-unavailable", allow_empty=True)


def generate_local_project(project: Project, out: Path, unresolved_out: Path | None = None) -> int:
    unresolved: List[dict] = []
    try:
        if project.manager == "source":
            return _static_source(project, out, unresolved)
        if project.ecosystem == "node" and project.manager == "yarn":
            if (project.root / "yarn.lock").exists():
                return _static_yarn(project, out)
            return _static_node_manifest(project, out, unresolved)
        if project.ecosystem == "node" and project.manager == "npm":
            if (project.root / "package-lock.json").exists() or (project.root / "npm-shrinkwrap.json").exists():
                return _static_npm(project, out)
            return _static_node_manifest(project, out, unresolved)
        if project.ecosystem == "node" and project.manager == "pnpm":
            if (project.root / "pnpm-lock.yaml").exists():
                return _static_pnpm(project, out)
            return _static_node_manifest(project, out, unresolved)
        if project.ecosystem == "python" and project.manager == "pyproject":
            return _static_pyproject(project, out, unresolved)
        if project.ecosystem == "python" and project.manager == "pip":
            return _static_pip_requirements(project, out, unresolved)
        if project.ecosystem == "python":
            return _static_python_lock(project, out)
        if project.ecosystem == "go" and project.manager != "source":
            return _static_go(project, out)
        if project.ecosystem == "rust" and project.manager != "source":
            return _static_cargo(project, out)
        if project.ecosystem == "php" and project.manager != "source":
            return _static_composer(project, out)
        if project.ecosystem == "dotnet" and project.manager != "source":
            return _static_dotnet(project, out, unresolved)
        if project.ecosystem == "java" and project.manager == "maven":
            return _static_maven(project, out, unresolved)
        if project.ecosystem == "java" and project.manager == "gradle":
            return _static_gradle(project, out, unresolved)
        if project.ecosystem == "cpp" and project.manager != "source":
            return _static_cpp_manifest(project, out, unresolved)
        raise RuntimeError(f"local SBOM generation is not implemented for {project.ecosystem}/{project.manager}")
    finally:
        _write_unresolved(unresolved_out, unresolved)
