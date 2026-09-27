from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable, List, Set

from .model import Project

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".sbom-work",
    "node_modules", ".venv", "venv", "vendor", "target", "dist",
    "build", ".gradle", "__pycache__", ".tox", ".mypy_cache",
}

PY_FRAMEWORKS = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "tornado": "Tornado",
}
NODE_FRAMEWORKS = {
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "@angular/core": "Angular",
    "@nestjs/core": "NestJS",
    "express": "Express",
    "koa": "Koa",
    "@sveltejs/kit": "SvelteKit",
}
JAVA_MARKERS = {
    "spring-boot": "Spring Boot",
    "io.quarkus": "Quarkus",
    "micronaut": "Micronaut",
    "ktor": "Ktor",
}
GO_MARKERS = {
    "github.com/gin-gonic/gin": "Gin",
    "github.com/gofiber/fiber": "Fiber",
    "github.com/labstack/echo": "Echo",
}
RUST_MARKERS = {
    "actix-web": "Actix Web",
    "axum": "Axum",
    "rocket": "Rocket",
}
PHP_MARKERS = {
    "laravel/framework": "Laravel",
    "symfony/framework-bundle": "Symfony",
}


def _walk(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".sbom-work") and not d.startswith(".scan-sca_osa")]
        yield Path(current)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _frameworks_from_text(text: str, markers: dict[str, str]) -> List[str]:
    low = text.lower()
    return sorted({friendly for marker, friendly in markers.items() if marker.lower() in low})


def _node_frameworks(package_json: Path) -> List[str]:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except Exception:
        return []
    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            deps.update(value)
    return sorted({friendly for name, friendly in NODE_FRAMEWORKS.items() if name in deps})


def _python_frameworks(root: Path) -> List[str]:
    chunks: List[str] = []
    for name in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile"):
        p = root / name
        if p.exists():
            chunks.append(_read_text(p))
    for p in root.glob("requirements*.txt"):
        chunks.append(_read_text(p))
    return _frameworks_from_text("\n".join(chunks), PY_FRAMEWORKS)


def _node_manager(root: Path, package_json: Path) -> tuple[str, List[str]]:
    warnings: List[str] = []
    lockfiles = []
    if (root / "pnpm-lock.yaml").exists():
        lockfiles.append("pnpm-lock.yaml")
    if (root / "yarn.lock").exists():
        lockfiles.append("yarn.lock")
    if (root / "package-lock.json").exists():
        lockfiles.append("package-lock.json")
    if (root / "npm-shrinkwrap.json").exists():
        lockfiles.append("npm-shrinkwrap.json")

    # packageManager is the strongest explicit signal and avoids guessing when
    # repositories contain stale lockfiles from another package manager.
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
        pm = str(data.get("packageManager", "")).strip().lower()
        if pm.startswith("pnpm@"):
            manager = "pnpm"
        elif pm.startswith("yarn@"):
            manager = "yarn"
        elif pm.startswith("npm@"):
            manager = "npm"
        else:
            manager = ""
    except Exception:
        manager = ""

    if not manager:
        if (root / "pnpm-lock.yaml").exists() or (root / "pnpm-workspace.yaml").exists():
            manager = "pnpm"
        elif (root / "yarn.lock").exists():
            manager = "yarn"
        else:
            manager = "npm"

    families = set()
    for lf in lockfiles:
        if lf.startswith("pnpm"):
            families.add("pnpm")
        elif lf == "yarn.lock":
            families.add("yarn")
        else:
            families.add("npm")
    if len(families) > 1:
        warnings.append(f"multiple Node lockfiles: {', '.join(lockfiles)}; using {manager}")
    return manager, warnings


def _is_workspace_root(root: Path) -> bool:
    pj = root / "package.json"
    if not pj.exists():
        return False
    if (root / "pnpm-workspace.yaml").exists():
        return True
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
        return bool(data.get("workspaces"))
    except Exception:
        return False


def _has_workspace_ancestor(path: Path, search_root: Path) -> bool:
    parent = path.parent
    while parent != search_root.parent and parent != parent.parent:
        if _is_workspace_root(parent):
            return True
        if parent == search_root:
            break
        parent = parent.parent
    return False


def _has_gradle_ancestor(path: Path, search_root: Path) -> bool:
    parent = path.parent
    while parent != search_root.parent and parent != parent.parent:
        if any((parent / n).exists() for n in ("settings.gradle", "settings.gradle.kts")):
            return True
        if parent == search_root:
            break
        parent = parent.parent
    return False


def _has_rust_workspace_ancestor(path: Path, search_root: Path) -> bool:
    parent = path.parent
    while parent != search_root.parent and parent != parent.parent:
        cargo = parent / "Cargo.toml"
        if cargo.exists() and "[workspace]" in _read_text(cargo):
            return True
        if parent == search_root:
            break
        parent = parent.parent
    return False



SOURCE_EXTENSIONS = {
    "python": {".py"},
    "node": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"},
    "java": {".java", ".kt", ".kts"},
    "go": {".go"},
    "rust": {".rs"},
    "dotnet": {".cs", ".fs", ".vb"},
    "php": {".php"},
    "cpp": {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"},
}


def _detect_source_ecosystems(root: Path) -> dict[str, int]:
    counts = {k: 0 for k in SOURCE_EXTENSIONS}
    for d in _walk(root):
        try:
            for child in d.iterdir():
                if not child.is_file():
                    continue
                suffix = child.suffix.lower()
                for eco, exts in SOURCE_EXTENSIONS.items():
                    if suffix in exts:
                        counts[eco] += 1
        except OSError:
            continue
    return {k: v for k, v in counts.items() if v}


def source_extension_counts(root: Path, ecosystem: str, exclude_roots: tuple[Path, ...] = ()) -> dict[str, int]:
    """Return source-file evidence used for technology detection.

    Counts only extensions that belong to the requested ecosystem and ignores
    nested roots already covered by another detected service.
    """
    suffixes = SOURCE_EXTENSIONS.get(ecosystem, set())
    excluded = tuple(x.resolve() for x in exclude_roots)
    counts: dict[str, int] = {}
    for d in _walk(root):
        rd = d.resolve()
        if any(rd == x or x in rd.parents for x in excluded):
            continue
        try:
            for child in d.iterdir():
                if child.is_file() and child.suffix.lower() in suffixes:
                    suffix = child.suffix.lower()
                    counts[suffix] = counts.get(suffix, 0) + 1
        except OSError:
            continue
    return dict(sorted(counts.items()))


def _source_frameworks(root: Path, ecosystem: str, exclude_roots: tuple[Path, ...] = ()) -> List[str]:
    markers = {
        "python": PY_FRAMEWORKS,
        "node": NODE_FRAMEWORKS,
        "java": JAVA_MARKERS,
        "go": GO_MARKERS,
        "rust": RUST_MARKERS,
        "php": PHP_MARKERS,
    }.get(ecosystem, {})
    if not markers:
        return []
    chunks: List[str] = []
    exts = SOURCE_EXTENSIONS.get(ecosystem, set())
    excluded = tuple(x.resolve() for x in exclude_roots)
    for d in _walk(root):
        rd = d.resolve()
        if any(rd == x or x in rd.parents for x in excluded):
            continue
        for child in d.iterdir():
            if child.is_file() and child.suffix.lower() in exts:
                chunks.append(_read_text(child)[:12000])
                if len(chunks) >= 80:
                    return _frameworks_from_text("\n".join(chunks), markers)
    return _frameworks_from_text("\n".join(chunks), markers)

def detect_projects(root: Path) -> List[Project]:
    root = root.resolve()
    found: List[Project] = []
    seen: Set[tuple[str, Path]] = set()

    # Detect solution files once; individual .NET projects under a solution are skipped.
    sln_files: List[Path] = []
    for d in _walk(root):
        sln_files.extend(sorted(d.glob("*.sln")))
        sln_files.extend(sorted(d.glob("*.slnx")))

    for d in _walk(root):
        # Python: one manager per directory, priority uv > Poetry > pip.
        if (d / "uv.lock").exists() and (d / "pyproject.toml").exists():
            p = Project("python", "uv", d, d / "pyproject.toml", _python_frameworks(d))
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))
        elif (d / "poetry.lock").exists() and (d / "pyproject.toml").exists():
            p = Project("python", "poetry", d, d / "pyproject.toml", _python_frameworks(d))
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))
        else:
            reqs = sorted(d.glob("requirements*.txt"))
            if reqs:
                p = Project("python", "pip", d, reqs[0], _python_frameworks(d))
                if (p.ecosystem, p.root) not in seen:
                    found.append(p); seen.add((p.ecosystem, p.root))
            elif (d / "pyproject.toml").exists():
                p = Project("python", "pyproject", d, d / "pyproject.toml", _python_frameworks(d), ["no Python lockfile; dependency versions may be unresolved"])
                if (p.ecosystem, p.root) not in seen:
                    found.append(p); seen.add((p.ecosystem, p.root))

        # Node workspaces: only scan workspace root, not each package.
        package_json = d / "package.json"
        if package_json.exists() and not _has_workspace_ancestor(d, root):
            manager, warnings = _node_manager(d, package_json)
            p = Project("node", manager, d, package_json, _node_frameworks(package_json), warnings)
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))

        # Maven: aggregate root POMs are preferred; nested Maven modules are skipped when parent has pom.xml.
        pom = d / "pom.xml"
        if pom.exists():
            parent = d.parent
            nested = False
            while parent != root.parent and parent != parent.parent:
                if (parent / "pom.xml").exists():
                    nested = True; break
                if parent == root:
                    break
                parent = parent.parent
            if not nested:
                p = Project("java", "maven", d, pom, _frameworks_from_text(_read_text(pom), JAVA_MARKERS))
                if (p.ecosystem, p.root) not in seen:
                    found.append(p); seen.add((p.ecosystem, p.root))

        # Gradle: settings.gradle marks build root; fallback to a standalone build.gradle.
        gradle_manifest = None
        for name in ("settings.gradle.kts", "settings.gradle", "build.gradle.kts", "build.gradle"):
            if (d / name).exists():
                gradle_manifest = d / name
                break
        if gradle_manifest and not _has_gradle_ancestor(d, root):
            text = "\n".join(_read_text(d / n) for n in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts") if (d / n).exists())
            p = Project("java", "gradle", d, gradle_manifest, _frameworks_from_text(text, JAVA_MARKERS))
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))

        # Go modules.
        gomod = d / "go.mod"
        if gomod.exists():
            p = Project("go", "gomod", d, gomod, _frameworks_from_text(_read_text(gomod), GO_MARKERS))
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))

        # Rust workspaces: only workspace root when present.
        cargo = d / "Cargo.toml"
        if cargo.exists() and not _has_rust_workspace_ancestor(d, root):
            p = Project("rust", "cargo", d, cargo, _frameworks_from_text(_read_text(cargo), RUST_MARKERS))
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))

        # PHP Composer.
        composer = d / "composer.json"
        if composer.exists():
            p = Project("php", "composer", d, composer, _frameworks_from_text(_read_text(composer), PHP_MARKERS))
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))

        # C/C++ package managers. Prefer Conan when both metadata formats are present.
        conan = next((d / name for name in ("conanfile.py", "conanfile.txt") if (d / name).exists()), None)
        vcpkg = d / "vcpkg.json"
        if conan is not None:
            p = Project("cpp", "conan", d, conan, [])
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))
        elif vcpkg.exists():
            p = Project("cpp", "vcpkg", d, vcpkg, [])
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))

    # .NET: prefer solution-level aggregate SBOMs.
    if sln_files:
        for sln in sln_files:
            p = Project("dotnet", "nuget", sln.parent, sln, ["ASP.NET Core"] if "aspnet" in _read_text(sln).lower() else [])
            if (p.ecosystem, p.root) not in seen:
                found.append(p); seen.add((p.ecosystem, p.root))
    else:
        for d in _walk(root):
            for proj in sorted(list(d.glob("*.csproj")) + list(d.glob("*.fsproj")) + list(d.glob("*.vbproj"))):
                text = _read_text(proj)
                fw = ["ASP.NET Core"] if "microsoft.aspnetcore" in text.lower() else []
                p = Project("dotnet", "nuget", d, proj, fw)
                if (p.ecosystem, p.root) not in seen:
                    found.append(p); seen.add((p.ecosystem, p.root))
                    break

    # Add a source-inferred umbrella project for source files that are not
    # covered by any detected module of the same ecosystem. This is important
    # for repositories where a nested test/tool directory has pyproject.toml,
    # while the actual application source lives at repository root (SPA case).
    source_counts = _detect_source_ecosystems(root)
    for ecosystem in source_counts:
        covered = tuple(sorted(
            {p.root.resolve() for p in found if p.ecosystem == ecosystem},
            key=lambda x: len(x.parts),
        ))
        if root.resolve() in covered:
            continue
        suffixes = SOURCE_EXTENSIONS.get(ecosystem, set())
        uncovered = 0
        for d in _walk(root):
            rd = d.resolve()
            if any(rd == c or c in rd.parents for c in covered):
                continue
            try:
                uncovered += sum(1 for child in d.iterdir() if child.is_file() and child.suffix.lower() in suffixes)
            except OSError:
                continue
        if uncovered <= 0:
            continue
        warnings = [f"no dependency metadata covers {uncovered} source files; inferring dependencies from uncovered source"]
        p = Project(
            ecosystem, "source", root, root,
            _source_frameworks(root, ecosystem, covered), warnings, covered,
        )
        found.append(p)

    return sorted(found, key=lambda p: (str(p.root), p.ecosystem, p.manager))
