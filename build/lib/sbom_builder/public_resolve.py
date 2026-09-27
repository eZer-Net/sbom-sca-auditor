from __future__ import annotations

import json
import re
import shutil
import tempfile
import tarfile
import uuid
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from urllib.parse import quote

from .model import Project
from .tools import ensure_command, run_logged
from .native_resolve import resolve_maven, resolve_dotnet, resolve_go, resolve_conan, resolve_vcpkg
from .local_generate import (
    _collect_requirement_entries,
    _node_imports,
    _parse_requirement_line,
    _python_imports,
    _static_node_manifest,
    _static_pyproject,
    generate_local_project,
    _component,
    _purl,
    _write_bom,
)


def _npm_purl(name: str, version: str) -> str:
    if name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"


def _pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{quote(name, safe='')}@{quote(version, safe='')}"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _write_unresolved(path: Path | None, rows: List[dict]) -> None:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _fallback_local_with_unresolved(project: Project, out: Path, unresolved_out: Path | None, existing: List[dict]) -> int:
    temp = None
    if unresolved_out:
        temp = unresolved_out.with_suffix(".local.json")
        if temp.exists():
            temp.unlink()
    count = generate_local_project(project, out, temp)
    rows = list(existing)
    if temp and temp.exists():
        try:
            local_rows = json.loads(temp.read_text(encoding="utf-8"))
            if isinstance(local_rows, list):
                rows.extend(x for x in local_rows if isinstance(x, dict))
        except Exception:
            pass
        temp.unlink(missing_ok=True)
    _write_unresolved(unresolved_out, rows)
    return count


def _row(project: Project, source: str, raw: str, reason: str, name: str | None = None, declared: str | None = None) -> dict:
    return {
        "ecosystem": project.ecosystem,
        "manager": project.manager,
        "module": str(project.root),
        "source": source,
        "raw": raw,
        "name": name,
        "declared": declared,
        "reason": reason,
    }


def _write_python_report_bom(project: Project, out: Path, reports: List[dict], direct_names: set[str]) -> int:
    packages: Dict[str, dict] = {}
    for report in reports:
        for item in report.get("install") or []:
            meta = item.get("metadata") or {}
            name = str(meta.get("name") or "").strip()
            version = str(meta.get("version") or "").strip()
            if not name or not version:
                continue
            packages[_norm(name)] = {"name": name, "version": version, "metadata": meta}
    if not packages:
        raise RuntimeError("public PyPI resolution returned 0 packages")

    refs = {k: _pypi_purl(v["name"], v["version"]) for k, v in packages.items()}
    components = [
        {
            "type": "library", "name": v["name"], "version": v["version"],
            "bom-ref": refs[k], "purl": refs[k],
            "properties": [{"name": "sbom-sca-auditor:version-source", "value": "pip-resolved-at-scan"}],
        }
        for k, v in sorted(packages.items())
    ]
    root_ref = f"urn:sbom-sca-auditor:public-root:{uuid.uuid5(uuid.NAMESPACE_URL, str(project.root.resolve()))}"
    edges: Dict[str, set[str]] = {root_ref: set()}
    for k, pkg in packages.items():
        ref = refs[k]
        edges.setdefault(ref, set())
        reqs = (pkg["metadata"].get("requires_dist") or [])
        for req in reqs:
            if not isinstance(req, str):
                continue
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)", req)
            if not m:
                continue
            child = refs.get(_norm(m.group(1)))
            if child:
                edges[ref].add(child)
    for name in direct_names:
        ref = refs.get(_norm(name))
        if ref:
            edges[root_ref].add(ref)

    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": project.root.name, "version": "local", "bom-ref": root_ref},
            "properties": [
                {"name": "sbom-sca-auditor:private-dependency-access", "value": "false"},
                {"name": "sbom-sca-auditor:generation-mode", "value": "public-pypi-resolution"},
                {"name": "sbom-sca-auditor:coverage", "value": "public-direct-and-transitive"},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": ref, **({"dependsOn": sorted(children)} if children else {})}
            for ref, children in sorted(edges.items())
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(components)


def _exact_python_version(spec: str | None) -> str | None:
    m = re.fullmatch(r"==\s*([^\s;]+)", (spec or "").strip())
    return m.group(1) if m else None


def _write_python_direct_bom(project: Project, out: Path, exact: List[Tuple[str, str]]) -> int:
    root_ref = f"urn:sbom-sca-auditor:public-root:{uuid.uuid5(uuid.NAMESPACE_URL, str(project.root.resolve()))}"
    components = []
    direct_refs = []
    for name, version in exact:
        ref = _pypi_purl(name, version)
        components.append({"type": "library", "name": name, "version": version, "bom-ref": ref, "purl": ref})
        direct_refs.append(ref)
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": project.root.name, "version": "local", "bom-ref": root_ref}},
        "components": components,
        "dependencies": [{"ref": root_ref, **({"dependsOn": direct_refs} if direct_refs else {})}] + [{"ref": r} for r in direct_refs],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(components)


def _inspect_python_archive(py: str, project: Project, work: Path, log: Path, name: str, version: str) -> tuple[bool, List[str]]:
    """Download an exact wheel without installing it and read Requires-Dist metadata."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{name}-{version}")
    dest = work / "package-inspection" / "python" / safe
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    cp = run_logged([
        py, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
        "--disable-pip-version-check", "--timeout", "15", "--retries", "1",
        "--index-url", "https://pypi.org/simple", "--dest", str(dest), f"{name}=={version}",
    ], project.root, log, check=False)
    wheels = sorted(dest.glob("*.whl"))
    if cp.returncode != 0 or not wheels:
        return False, []
    requires: List[str] = []
    try:
        with zipfile.ZipFile(wheels[0]) as zf:
            metadata_name = next((n for n in zf.namelist() if n.endswith(".dist-info/METADATA")), None)
            if metadata_name:
                text = zf.read(metadata_name).decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    if line.startswith("Requires-Dist:"):
                        requires.append(line.split(":", 1)[1].strip())
    except Exception:
        return False, []
    (dest / "inspection.json").write_text(json.dumps({
        "package": name, "version": version, "requires_dist": requires,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True, requires



def _gradle_command(project: Project, log: Path, install: bool) -> list[str]:
    wrapper = project.root / "gradlew"
    if wrapper.exists():
        try:
            wrapper.chmod(wrapper.stat().st_mode | 0o111)
        except OSError:
            pass
        ensure_command("java", ["openjdk"], log, install)
        return [str(wrapper)]
    ensure_command("java", ["openjdk"], log, install)
    return [ensure_command("gradle", ["gradle"], log, install)]


def _parse_gradle_dependencies(text: str, project: Project, out: Path) -> int:
    line_re = re.compile(r"^(?P<prefix>(?:[| ]{5})*)[+\\]---\s+(?P<body>.+)$")
    coord_re = re.compile(r"(?P<group>[A-Za-z0-9_.-]+):(?P<name>[A-Za-z0-9_.-]+):(?P<version>[^\s]+)(?:\s+->\s+(?P<resolved>[^\s]+))?")
    components: Dict[str, dict] = {}
    edges: Dict[str, set[str]] = {"__root__": set()}
    stack: list[str] = []
    for raw in text.splitlines():
        m = line_re.match(raw)
        if not m:
            continue
        cm = coord_re.search(m.group("body"))
        if not cm:
            continue
        version = (cm.group("resolved") or cm.group("version")).rstrip("(*)")
        if version in {"FAILED", "project"} or not version:
            continue
        group, name = cm.group("group"), cm.group("name")
        ref = _purl("maven", name, version, group)
        components.setdefault(ref, _component(name, version, ref, properties=[{"name": "sbom-sca-auditor:version-source", "value": "gradle-resolved"}]))
        edges.setdefault(ref, set())
        depth = len(m.group("prefix")) // 5
        if depth == 0:
            edges["__root__"].add(ref)
        elif depth - 1 < len(stack):
            edges.setdefault(stack[depth - 1], set()).add(ref)
        if len(stack) <= depth:
            stack.extend([ref] * (depth + 1 - len(stack)))
        stack[depth] = ref
        del stack[depth + 1:]
    return _write_bom(project, out, components.values(), edges, coverage="gradle-resolved-direct-and-transitive", notes=["Dependencies were resolved by the project's Gradle build before Trivy scanning."], allow_empty=False)


def _public_gradle(project: Project, out: Path, work: Path, log: Path, install: bool, unresolved_out: Path | None) -> int:
    # Build in a temporary writable copy. This keeps the target repository read-only
    # (including Docker /workspace:ro) and avoids leaving build artifacts behind.
    build_root = work / "gradle-src" / out.stem
    if build_root.exists():
        shutil.rmtree(build_root)
    shutil.copytree(
        project.root, build_root,
        ignore=shutil.ignore_patterns(".git", ".gradle", "build", "target", "node_modules", ".scan-sca_osa", "__pycache__"),
    )
    build_manifest = build_root / project.manifest.name
    build_project = Project("java", "gradle", build_root, build_manifest, project.frameworks, project.warnings)
    gradle = _gradle_command(build_project, log, install)
    build = run_logged([*gradle, "build", "-x", "test", "--console=plain", "--no-daemon"], build_root, log, check=False)
    if build.returncode != 0:
        # Keep a best-effort manifest SBOM so the whole repository scan can continue.
        rows = [_row(project, "gradle", str(project.manifest), "Gradle build failed; falling back to dependencies declared directly in the build file")]
        return _fallback_local_with_unresolved(project, out, unresolved_out, rows)
    dep_output = work / "gradle" / f"{out.stem}-dependencies.txt"
    dep_output.parent.mkdir(parents=True, exist_ok=True)
    resolved = False
    for configuration in ("runtimeClasspath", "compileClasspath"):
        cp = run_logged([*gradle, "dependencies", "--configuration", configuration, "--console=plain", "--no-daemon"], build_root, log, stdout_file=dep_output, check=False)
        if cp.returncode == 0 and dep_output.exists() and "---" in dep_output.read_text(encoding="utf-8", errors="ignore"):
            resolved = True
            break
    if not resolved:
        rows = [_row(project, "gradle", str(project.manifest), "Gradle build succeeded, but a runtime/compile dependency graph could not be resolved; falling back to direct declarations")]
        return _fallback_local_with_unresolved(project, out, unresolved_out, rows)
    try:
        count = _parse_gradle_dependencies(dep_output.read_text(encoding="utf-8", errors="ignore"), project, out)
        _write_unresolved(unresolved_out, [])
        return count
    except Exception:
        rows = [_row(project, "gradle", str(project.manifest), "Gradle dependency output could not be converted into a CycloneDX graph; falling back to direct declarations")]
        return _fallback_local_with_unresolved(project, out, unresolved_out, rows)

def _python_specs(project: Project) -> tuple[List[Tuple[str, str]], List[dict]]:
    """Return only exact direct pins eligible for package download/resolution."""
    exact: List[Tuple[str, str]] = []
    unresolved: List[dict] = []
    if project.manager == "source":
        for name in sorted(_python_imports(project.root, project.exclude_roots)):
            unresolved.append(_row(
                project, "source-import", name,
                "dependency inferred from source has no exact version; excluded from SBOM",
                name=name, declared=None,
            ))
        return exact, unresolved

    if project.manager == "pyproject":
        import tomllib
        data = tomllib.loads((project.root / "pyproject.toml").read_text(encoding="utf-8"))
        entries: List[str] = []
        proj = data.get("project")
        if isinstance(proj, dict) and isinstance(proj.get("dependencies"), list):
            entries.extend(str(x) for x in proj["dependencies"])
        poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
        if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
            for name, spec in poetry["dependencies"].items():
                if str(name).lower() == "python":
                    continue
                if isinstance(spec, str):
                    entries.append(f"{name}{spec if spec.startswith(('=', '<', '>', '~', '^')) else '==' + spec}")
                elif isinstance(spec, dict) and spec.get("version"):
                    entries.append(f"{name}{spec['version']}")
                else:
                    entries.append(str(name))
    else:
        entries = _collect_requirement_entries(project, unresolved)

    for raw in entries:
        name, spec, problem = _parse_requirement_line(raw)
        if problem or not name:
            unresolved.append(_row(project, "dependency-metadata", raw, "dependency syntax/source is not an exact public package pin; excluded from SBOM", name=name, declared=spec))
            continue
        version = _exact_python_version(spec)
        if not version:
            unresolved.append(_row(
                project, "dependency-metadata", raw,
                "dependency version is not exact; ranges and latest are not downloaded or added to SBOM",
                name=name, declared=spec or "latest",
            ))
            continue
        exact.append((name, version))
    return exact, unresolved


def _python_resolver_specs(project: Project) -> tuple[List[str], set[str], List[dict]]:
    """Return public registry specs that pip can resolve without guessing source imports.

    Version ranges are allowed only when they are explicitly declared in a manifest.
    Source-only imports and URL/VCS/local dependencies remain unresolved.
    """
    unresolved: List[dict] = []
    entries: List[str] = []
    if project.manager == "source":
        return [], set(), [_row(project, "source-import", n, "dependency inferred from source has no exact package/version metadata; excluded from SBOM", name=n) for n in sorted(_python_imports(project.root, project.exclude_roots))]
    if project.manager == "pyproject":
        import tomllib
        data = tomllib.loads((project.root / "pyproject.toml").read_text(encoding="utf-8"))
        proj = data.get("project")
        if isinstance(proj, dict) and isinstance(proj.get("dependencies"), list):
            entries.extend(str(x) for x in proj["dependencies"])
        poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
        if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
            for name, spec in poetry["dependencies"].items():
                if str(name).lower() == "python":
                    continue
                if isinstance(spec, str):
                    entries.append(f"{name}{spec if spec.startswith(('=', '<', '>', '~')) else '==' + spec}")
                elif isinstance(spec, dict) and spec.get("version"):
                    version = str(spec["version"])
                    entries.append(f"{name}{version if version.startswith(('=', '<', '>', '~')) else '==' + version}")
                else:
                    unresolved.append(_row(project, "pyproject.toml", str(name), "dependency declaration cannot be safely translated to a public pip requirement", name=str(name)))
    else:
        entries = _collect_requirement_entries(project, unresolved)

    specs: List[str] = []
    direct: set[str] = set()
    for raw in entries:
        name, spec, problem = _parse_requirement_line(raw)
        if problem or not name:
            unresolved.append(_row(project, "dependency-metadata", raw, "dependency source is URL/VCS/local or unsupported; excluded from public resolution", name=name, declared=spec))
            continue
        # A completely unversioned name is equivalent to asking the registry for latest; keep it unresolved.
        if not (spec or "").strip():
            unresolved.append(_row(project, "dependency-metadata", raw, "dependency has no version constraint; scanner does not resolve implicit latest", name=name, declared=None))
            continue
        specs.append(f"{name}{spec}")
        direct.add(name)
    return specs, direct, unresolved


def _public_python(project: Project, out: Path, work: Path, log: Path, install: bool, unresolved_out: Path | None) -> int:
    if project.manager == "source":
        return generate_local_project(project, out, unresolved_out)
    py = ensure_command("python3", ["python"], log, install)
    specs, direct_names, unresolved = _python_resolver_specs(project)
    if not specs:
        _write_unresolved(unresolved_out, unresolved)
        return _write_python_direct_bom(project, out, [])

    resolve_dir = work / "public-resolution" / out.stem
    resolve_dir.mkdir(parents=True, exist_ok=True)
    report_path = resolve_dir / "pip-report.json"
    cmd = [
        py, "-m", "pip", "install", "--dry-run", "--ignore-installed",
        "--disable-pip-version-check", "--only-binary=:all:", "--timeout", "15", "--retries", "1",
        "--index-url", "https://pypi.org/simple", "--report", str(report_path), *specs,
    ]
    cp = run_logged(cmd, project.root, log, check=False)
    if cp.returncode == 0 and report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        count = _write_python_report_bom(project, out, [report], direct_names)
        _write_unresolved(unresolved_out, unresolved)
        return count

    # If pip cannot produce a coherent graph, preserve only exact pins that were independently verified.
    exact, exact_unresolved = _python_specs(project)
    unresolved.extend(exact_unresolved)
    inspected: List[Tuple[str, str]] = []
    for name, version in exact:
        ok, _ = _inspect_python_archive(py, project, work, log, name, version)
        if ok:
            inspected.append((name, version))
    count = _write_python_direct_bom(project, out, inspected)
    unresolved.append(_row(project, "pip", ", ".join(specs), "pip could not resolve a complete dependency graph; no transitive versions were invented"))
    _write_unresolved(unresolved_out, unresolved)
    return count

def _exact_npm_version(spec: str) -> str | None:
    raw = spec.strip()
    m = re.fullmatch(r"v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)", raw)
    return m.group(1) if m else None


def _write_node_direct_bom(project: Project, out: Path, exact: Dict[str, str]) -> int:
    root_ref = f"urn:sbom-sca-auditor:public-root:{uuid.uuid5(uuid.NAMESPACE_URL, str(project.root.resolve()))}"
    components = []
    refs = []
    for name, version in sorted(exact.items()):
        ref = _npm_purl(name, version)
        components.append({"type": "library", "name": name, "version": version, "bom-ref": ref, "purl": ref})
        refs.append(ref)
    result = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"component": {"type": "application", "name": project.root.name, "version": "local", "bom-ref": root_ref}},
        "components": components,
        "dependencies": [{"ref": root_ref, **({"dependsOn": refs} if refs else {})}] + [{"ref": r} for r in refs],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(components)


def _inspect_npm_archive(npm: str, project: Project, work: Path, log: Path, name: str, version: str) -> bool:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{name}-{version}")
    dest = work / "package-inspection" / "node" / safe
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    cp = run_logged([
        npm, "pack", f"{name}@{version}", "--ignore-scripts", "--json",
        "--pack-destination", str(dest), "--registry=https://registry.npmjs.org",
    ], project.root, log, check=False)
    archives = sorted(dest.glob("*.tgz"))
    if cp.returncode != 0 or not archives:
        return False
    try:
        with tarfile.open(archives[0], "r:gz") as tf:
            member = next((m for m in tf.getmembers() if m.name == "package/package.json"), None)
            if not member:
                return False
            fh = tf.extractfile(member)
            if fh is None:
                return False
            meta = json.loads(fh.read().decode("utf-8", errors="ignore"))
        deps = meta.get("dependencies") if isinstance(meta, dict) else {}
        (dest / "inspection.json").write_text(json.dumps({
            "package": name, "version": version,
            "dependencies": deps if isinstance(deps, dict) else {},
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return True
    except Exception:
        return False


def _node_specs(project: Project) -> tuple[Dict[str, str], List[dict]]:
    unresolved: List[dict] = []
    exact: Dict[str, str] = {}
    if project.manager == "source":
        for name in sorted(_node_imports(project.root, project.exclude_roots)):
            unresolved.append(_row(
                project, "source-import", name,
                "dependency inferred from source has no exact version; excluded from SBOM",
                name=name, declared=None,
            ))
        return exact, unresolved
    path = project.root / "package.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec_v in block.items():
            spec = str(spec_v).strip()
            version = _exact_npm_version(spec)
            if not version:
                reason = "dependency source is private/VCS/local and is not accessed by this scanner" if spec.startswith(("git", "ssh", "http", "file:", "workspace:", "link:")) or "bitbucket" in spec.lower() else "dependency version is not exact; ranges and latest are not downloaded or added to SBOM"
                unresolved.append(_row(project, "package.json", f"{name}: {spec or 'latest'}", reason, name=str(name), declared=spec or "latest"))
                continue
            exact[str(name)] = version
    return exact, unresolved


def _public_node(project: Project, out: Path, work: Path, log: Path, install: bool, unresolved_out: Path | None) -> int:
    if project.manager == "source":
        return generate_local_project(project, out, unresolved_out)
    # A lockfile is stronger than re-resolving the project today. It records the
    # versions selected when the application was built.
    if project.manager == "yarn" and (project.root / "yarn.lock").exists():
        text = (project.root / "yarn.lock").read_text(encoding="utf-8", errors="ignore")
        if "__metadata:" not in text:
            return generate_local_project(project, out, unresolved_out)
    if project.manager == "npm" and ((project.root / "package-lock.json").exists() or (project.root / "npm-shrinkwrap.json").exists()):
        return generate_local_project(project, out, unresolved_out)
    if project.manager == "pnpm" and (project.root / "pnpm-lock.yaml").exists():
        return generate_local_project(project, out, unresolved_out)

    npm = ensure_command("npm", ["node"], log, install)
    exact, unresolved = _node_specs(project)
    if not exact:
        _write_unresolved(unresolved_out, unresolved)
        return _write_node_direct_bom(project, out, {})

    inspected: Dict[str, str] = {}
    for name, version in exact.items():
        if _inspect_npm_archive(npm, project, work, log, name, version):
            inspected[name] = version
        else:
            unresolved.append(_row(
                project, "public-npm", f"{name}@{version}",
                "exact package archive could not be downloaded and inspected from public npm registry; excluded from SBOM",
                name=name, declared=version,
            ))
    if not inspected:
        _write_unresolved(unresolved_out, unresolved)
        return _write_node_direct_bom(project, out, {})

    resolve_dir = work / "public-resolution" / out.stem
    if resolve_dir.exists():
        shutil.rmtree(resolve_dir)
    resolve_dir.mkdir(parents=True)
    (resolve_dir / "package.json").write_text(json.dumps({
        "name": "sbom-public-resolver", "private": True, "version": "0.0.0", "dependencies": inspected,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    cp = run_logged([
        npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
        "--registry=https://registry.npmjs.org", "--fetch-timeout=15000", "--fetch-retries=1",
    ], resolve_dir, log, check=False)
    lock = resolve_dir / "package-lock.json"
    if cp.returncode != 0 or not lock.exists():
        count = _write_node_direct_bom(project, out, inspected)
        _write_unresolved(unresolved_out, unresolved)
        return count

    temp_project = Project("node", "npm", resolve_dir, resolve_dir / "package.json", project.frameworks, project.warnings)
    count = generate_local_project(temp_project, out, None)
    data = json.loads(out.read_text(encoding="utf-8"))
    if isinstance(data.get("metadata"), dict) and isinstance(data["metadata"].get("component"), dict):
        data["metadata"]["component"]["name"] = project.root.name
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_unresolved(unresolved_out, unresolved)
    return count


def generate_public_project(project: Project, out: Path, work: Path, log: Path, install: bool, unresolved_out: Path | None = None) -> int:
    """Generate from local metadata and public registries without private access.

    Lockfiles and manifests are preferred. Source-only dependencies without a
    confirmed package version remain unresolved and are excluded from the SBOM.
    Gradle projects are built and their resolved dependency graph is used for SBOM.
    """
    if project.ecosystem == "python":
        if project.manager in {"uv", "poetry"}:
            return generate_local_project(project, out, unresolved_out)
        return _public_python(project, out, work, log, install, unresolved_out)
    if project.ecosystem == "node":
        return _public_node(project, out, work, log, install, unresolved_out)
    if project.ecosystem == "java" and project.manager == "gradle":
        return _public_gradle(project, out, work, log, install, unresolved_out)
    if project.ecosystem == "java" and project.manager == "maven":
        try:
            count = resolve_maven(project, out, work, log, install)
            _write_unresolved(unresolved_out, [])
            return count
        except Exception as exc:
            return _fallback_local_with_unresolved(project, out, unresolved_out, [_row(project, "maven", str(project.manifest), f"native Maven resolution failed: {exc}; using only exact direct declarations")])
    if project.ecosystem == "dotnet" and project.manager == "nuget":
        try:
            count = resolve_dotnet(project, out, work, log, install)
            _write_unresolved(unresolved_out, [])
            return count
        except Exception as exc:
            return _fallback_local_with_unresolved(project, out, unresolved_out, [_row(project, "nuget", str(project.manifest), f"dotnet restore failed: {exc}; using existing local metadata only")])
    if project.ecosystem == "go" and project.manager == "gomod":
        try:
            count = resolve_go(project, out, work, log, install)
            _write_unresolved(unresolved_out, [])
            return count
        except Exception as exc:
            return _fallback_local_with_unresolved(project, out, unresolved_out, [_row(project, "go.mod", str(project.manifest), f"native Go module resolution failed: {exc}; using go.mod inventory without invented edges")])
    if project.ecosystem == "cpp" and project.manager == "conan":
        try:
            count = resolve_conan(project, out, work, log, install)
            _write_unresolved(unresolved_out, [])
            return count
        except Exception as exc:
            return _fallback_local_with_unresolved(project, out, unresolved_out, [_row(project, "conan", str(project.manifest), f"Conan graph resolution failed: {exc}")])
    if project.ecosystem == "cpp" and project.manager == "vcpkg":
        try:
            count = resolve_vcpkg(project, out, work, log, install)
            _write_unresolved(unresolved_out, [])
            return count
        except Exception as exc:
            return _fallback_local_with_unresolved(project, out, unresolved_out, [_row(project, "vcpkg", str(project.manifest), f"vcpkg graph resolution failed: {exc}")])
    return generate_local_project(project, out, unresolved_out)
