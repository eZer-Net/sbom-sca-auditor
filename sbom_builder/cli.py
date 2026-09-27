from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

from .config import DEFAULT_SEVERITIES, SUPPORTED_SEVERITIES, ScanConfig
from .detect import detect_projects, source_extension_counts
from .diagnostics import diagnose_log
from .identity import module_id
from .graph import write_dependency_graph_html
from .merge import merge_sboms, stats
from .model import Project
from .public_resolve import generate_public_project
from .scan import findings_with_paths, normalized_unresolved, scan_trivy, vulnerability_summary, write_vulnerabilities
from .platform import platform_name
from .tools import set_live_progress


STAGE_GOALS = {
    1: "Recursively search the whole project for supported lockfiles, manifests and source-code evidence.",
    2: "Collect dependencies using Lockfile -> Manifest -> Source and create module SBOMs.",
    3: "Merge all module SBOMs into one CycloneDX repository SBOM.",
    4: "Scan SBOM components with Trivy and restore dependency paths for findings.",
    5: "Write the final reports and show a concise scan summary.",
}


class JsonReporter:
    """Concise console reporter and one durable structured process log."""

    def __init__(self, path: Path, target_name: str):
        self.path = path
        self.data = {"target": target_name, "status": "running", "stages": []}
        self.current: dict | None = None

    def start_step(self, number: int, name: str) -> None:
        step = {"stage": number, "name": name, "goal": STAGE_GOALS[number], "events": []}
        self.data["stages"].append(step)
        self.current = step
        print(f"[{number}/5] {name}", flush=True)

    def line(self, text: str = "") -> None:
        print(text, flush=True)

    def event(self, action: str, **details) -> None:
        if self.current is None:
            return
        item = {"action": action}
        if details:
            item.update(details)
        self.current["events"].append(item)

    def finish(self, status: str, **summary) -> None:
        self.data["status"] = status
        if summary:
            self.data["summary"] = summary
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _relative_display(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve())
        return "." if str(rel) == "." else str(rel)
    except (ValueError, OSError):
        return path.name or str(path)


def _framework_text(project: Project) -> str:
    return ", ".join(project.frameworks) if project.frameworks else "not detected"


def _dependency_files(project: Project) -> list[str]:
    root = project.root
    candidates: list[Path] = []
    if project.ecosystem == "python":
        candidates.extend(sorted(root.glob("requirements*.txt")))
        candidates.extend(root / name for name in ("pyproject.toml", "uv.lock", "poetry.lock", "Pipfile.lock") if (root / name).exists())
    elif project.ecosystem == "node":
        candidates.extend(root / name for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml") if (root / name).exists())
    elif project.ecosystem == "java":
        candidates.extend(root / name for name in ("pom.xml", "settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts") if (root / name).exists())
    elif project.ecosystem == "go":
        candidates.extend(root / name for name in ("go.mod", "go.sum") if (root / name).exists())
    elif project.ecosystem == "rust":
        candidates.extend(root / name for name in ("Cargo.toml", "Cargo.lock") if (root / name).exists())
    elif project.ecosystem == "php":
        candidates.extend(root / name for name in ("composer.json", "composer.lock") if (root / name).exists())
    elif project.ecosystem == "dotnet":
        candidates.extend(sorted(root.glob("*.sln")))
        candidates.extend(sorted(root.glob("*.slnx")))
        candidates.extend(sorted(root.glob("*.*proj")))
        candidates.extend(root / name for name in ("packages.lock.json",) if (root / name).exists())
    elif project.ecosystem == "cpp":
        candidates.extend(root / name for name in ("conanfile.py", "conanfile.txt", "conan.lock", "vcpkg.json", "vcpkg-configuration.json", "CMakeLists.txt") if (root / name).exists())
    seen: list[str] = []
    for candidate in candidates:
        if candidate.exists() and candidate.name not in seen:
            seen.append(candidate.name)
    return seen


def _has_resolved_metadata(project: Project) -> bool:
    root = project.root
    if project.ecosystem == "python":
        return any((root / name).exists() for name in ("uv.lock", "poetry.lock", "Pipfile.lock"))
    if project.ecosystem == "node":
        return any((root / name).exists() for name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"))
    if project.ecosystem == "rust":
        return (root / "Cargo.lock").exists()
    if project.ecosystem == "php":
        return (root / "composer.lock").exists()
    if project.ecosystem == "dotnet":
        return (root / "packages.lock.json").exists()
    if project.ecosystem == "go":
        return (root / "go.mod").exists()
    return False


def _project_kind(project: Project) -> str:
    labels = {
        "python": "Python", "node": "Node.js", "java": "Java/Kotlin", "go": "Go",
        "rust": "Rust", "dotnet": ".NET / C#", "php": "PHP", "cpp": "C / C++",
    }
    return labels.get(project.ecosystem, project.ecosystem)


def _source_evidence(project: Project) -> dict[str, int]:
    return source_extension_counts(project.root, project.ecosystem, project.exclude_roots)


def _source_evidence_text(evidence: dict[str, int]) -> str:
    if not evidence:
        return "none"
    return ", ".join(f"{suffix}={count}" for suffix, count in evidence.items())


def _dependency_source(project: Project, files: list[str]) -> str:
    if project.ecosystem == "java" and project.manager == "gradle":
        return "native-resolver"
    if project.ecosystem == "java" and project.manager == "maven":
        return "native-resolver"
    if project.ecosystem in {"go", "dotnet", "cpp"} and project.manager != "source":
        return "native-resolver"
    if _has_resolved_metadata(project):
        return "lockfile"
    if project.manager != "source" and files:
        return "manifest"
    return "source"


def _load_rows(path: Path, project: Project, root: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    module = _relative_display(project.root, root)
    rows: list[dict] = []
    for row in data:
        if isinstance(row, dict):
            item = dict(row)
            item["module"] = module
            rows.append(item)
    return rows


def _append_unresolved(rows: list[dict], project: Project, root: Path, *, raw: str, reason: str, source: str = "module") -> None:
    rows.append({
        "ecosystem": project.ecosystem,
        "manager": project.manager,
        "module": _relative_display(project.root, root),
        "source": source,
        "raw": raw,
        "name": None,
        "declared": None,
        "reason": reason,
    })


def _parse_severities(value: str) -> tuple[str, ...]:
    items = tuple(dict.fromkeys(part.strip().upper() for part in value.split(",") if part.strip()))
    if not items:
        raise argparse.ArgumentTypeError("severity list must not be empty")
    invalid = [item for item in items if item not in SUPPORTED_SEVERITIES]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"unsupported severity: {', '.join(invalid)}; allowed: {', '.join(SUPPORTED_SEVERITIES)}"
        )
    return items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-sca-auditor",
        description="Recursively build a CycloneDX SBOM and scan it with Trivy.",
    )
    parser.add_argument("path", nargs="?", default=".", help="project/repository to scan (default: current directory)")
    parser.add_argument(
        "--severity",
        type=_parse_severities,
        default=DEFAULT_SEVERITIES,
        metavar="LEVELS",
        help="vulnerability levels for the report, comma-separated (default: CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--trivy-db-update",
        choices=("yes", "no"),
        default="yes",
        metavar="yes|no",
        help="update the Trivy vulnerability database before the scan (default: yes)",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="audit output root (default: <project>/.scan-sca_osa)",
    )
    return parser




def _set_module_display_name(path: Path, display_name: str) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        component = (data.get("metadata") or {}).get("component")
        if isinstance(component, dict):
            component["name"] = display_name
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except Exception:
        return

def _write_unresolved_result(path: Path, rows: list[dict]) -> list[dict]:
    normalized = normalized_unresolved(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return normalized


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _discovery_document(projects: list[Project], root: Path) -> dict:
    modules = []
    for project in projects:
        files = _dependency_files(project)
        modules.append({
            "path": _relative_display(project.root, root),
            "ecosystem": project.ecosystem,
            "technology": _project_kind(project),
            "manager": project.manager,
            "dependency_source": _dependency_source(project, files),
            "dependency_files": files,
            "source_files": _source_evidence(project),
            "frameworks": list(project.frameworks),
        })
    return {
        "target": root.name,
        "recursive": True,
        "modules": modules,
    }


def _resolution_stats(sbom: dict) -> dict:
    gradle = 0
    for component in sbom.get("components") or []:
        if not isinstance(component, dict) or str(component.get("type") or "").lower() not in {"library", "framework"}:
            continue
        props = component.get("properties") or []
        source = None
        for prop in props:
            if isinstance(prop, dict) and prop.get("name") == "sbom-sca-auditor:version-source":
                source = str(prop.get("value") or "")
                break
        if source == "gradle-resolved":
            gradle += 1
    return {"gradle_resolved": gradle}


def _summary_document(
    *,
    root: Path,
    config: ScanConfig,
    modules: int,
    libraries: int,
    unresolved: int,
    vulnerability_data: dict,
    status: str,
    resolution_data: dict | None = None,
) -> dict:
    return {
        "status": status,
        "target": root.name,
        "configuration": {
            "severity": list(config.severities),
            "trivy_db_update": config.trivy_db_update,
        },
        "modules": modules,
        "dependencies": {
            "included": libraries,
            "unresolved": unresolved,
            "gradle_resolved": (resolution_data or {}).get("gradle_resolved", 0),
        },
        "vulnerabilities": {
            "total": vulnerability_data.get("total", 0),
            "critical": vulnerability_data.get("critical", 0),
            "high": vulnerability_data.get("high", 0),
            "medium": vulnerability_data.get("medium", 0),
            "low": vulnerability_data.get("low", 0),
            "unknown": vulnerability_data.get("unknown", 0),
            "direct": vulnerability_data.get("direct", 0),
            "transitive": vulnerability_data.get("transitive", 0),
            "unknown_relation": vulnerability_data.get("unknown_relation", 0),
        },
    }


def _run(args: argparse.Namespace) -> int:
    root = Path(args.path or ".").expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR target directory does not exist: {root}", file=sys.stderr)
        return 2

    if args.output:
        output_root = Path(args.output).expanduser().resolve()
    elif os.environ.get("SBOM_AUDITOR_DOCKER") == "1":
        output_root = Path("/output")
    else:
        output_root = root / ".scan-sca_osa"
    if output_root == root:
        print("ERROR --output must point to a dedicated directory, not the project root itself", file=sys.stderr)
        return 2

    config = ScanConfig(
        target=root,
        output_root=output_root,
        severities=tuple(args.severity),
        trivy_db_update=args.trivy_db_update == "yes",
    )

    # Only scanner-owned subdirectories are cleared. The custom output root itself
    # is never recursively deleted.
    for owned in (config.log_dir, config.result_dir, config.work_dir):
        if owned.exists():
            shutil.rmtree(owned)

    scan_root = config.output_root
    log_dir = config.log_dir
    result_dir = config.result_dir
    work_dir = config.work_dir
    module_sboms = work_dir / "module-sboms"
    module_unresolved = work_dir / "unresolved"
    command_logs = work_dir / "command-logs"
    for directory in (log_dir, result_dir, module_sboms, module_unresolved, command_logs):
        directory.mkdir(parents=True, exist_ok=True)

    reporter = JsonReporter(log_dir / "process.json", root.name)
    set_live_progress(False)
    generated: List[Tuple[str, Path]] = []
    unresolved_all: list[dict] = []
    vulnerabilities: list[dict] = []
    exit_code = 0

    try:
        print("SBOM SCA Auditor")
        print(f"Project: {root}")
        print(f"Platform: {platform_name()}")
        print(f"Severity: {','.join(config.severities)}")
        print(f"Trivy DB update: {'yes' if config.trivy_db_update else 'no'}")
        print(f"Output: {scan_root}")
        print("")
        reporter.start_step(1, "Project discovery")
        reporter.line("  Recursively searching for supported lockfiles, manifests and source files...")
        projects = detect_projects(root)
        if not projects:
            reporter.line("  No supported lockfiles, manifests or source-code ecosystems were found.")
            reporter.event("no_supported_technology_detected")
            reporter.finish("failed")
            return 2

        for idx, project in enumerate(projects, 1):
            rel = _relative_display(project.root, root)
            files = _dependency_files(project)
            evidence = _source_evidence(project)
            source = _dependency_source(project, files)
            reporter.line(f"  Found module: {rel} ({_project_kind(project)} / {project.manager})")
            if source == "lockfile":
                reporter.line(f"      Using lockfile: {', '.join(files)}")
            elif source == "manifest":
                reporter.line(f"      Using manifest: {', '.join(files)}")
            elif source == "native-resolver":
                reporter.line(f"      Native dependency resolver will be used: {project.manager}; metadata: {', '.join(files)}")
            else:
                reporter.line("      No dependency metadata found; source imports will be collected as unresolved evidence")
            reporter.event(
                "service_detected", service=rel, technology=_project_kind(project), manager=project.manager,
                source_extensions=evidence, frameworks=project.frameworks, dependency_source=source,
                dependency_files=files,
            )
            for warning in project.warnings:
                reporter.line(f"      Note: {warning}")
                reporter.event("discovery_note", service=rel, note=warning)
        reporter.line(f"  Modules detected: {len(projects)}")
        _write_json(result_dir / "discovery.json", _discovery_document(projects, root))

        print("")
        reporter.start_step(2, "Dependency collection")
        for index, project in enumerate(projects, 1):
            mid = module_id(project, root)
            out = module_sboms / f"{mid}.cdx.json"
            cmd_log = command_logs / f"{mid}.log"
            unresolved_path = module_unresolved / f"{mid}.json"
            rel = _relative_display(project.root, root)
            files = _dependency_files(project)
            source = _dependency_source(project, files)
            before_inspection = set((work_dir / "package-inspection").rglob("inspection.json")) if (work_dir / "package-inspection").exists() else set()

            reporter.line(f"  [{index}/{len(projects)}] {_project_kind(project)} / {project.manager} - {rel}")
            if source == "lockfile":
                reporter.line("      Lockfile found: using resolved versions and dependency relationships")
            elif source == "manifest":
                reporter.line("      Using dependency versions declared by the project")
            elif source == "native-resolver":
                reporter.line(f"      Native resolver mode: resolving exact dependency graph with {project.manager}")
            else:
                reporter.line("      Source mode: collecting library evidence; dependencies without a confirmed version stay unresolved")
            reporter.event("dependency_collection_started", service=rel, source=source)

            try:
                count = generate_public_project(project, out, work_dir, cmd_log, True, unresolved_out=unresolved_path)
            except Exception as exc:
                diagnosis = diagnose_log(cmd_log)
                reason = diagnosis.summary if diagnosis else str(exc)
                _append_unresolved(unresolved_all, project, root, raw=str(project.manifest), reason=reason)
                reporter.line(f"      Module SBOM failed: {reason}")
                reporter.event("module_sbom_failed", service=rel, reason=reason)
                continue

            _set_module_display_name(out, rel)
            module_rows = _load_rows(unresolved_path, project, root)
            unresolved_all.extend(module_rows)
            normalized_module = normalized_unresolved(module_rows)
            generated.append((mid, out))
            after_inspection = set((work_dir / "package-inspection").rglob("inspection.json")) if (work_dir / "package-inspection").exists() else set()
            inspected_count = len(after_inspection - before_inspection)
            if inspected_count:
                reporter.line(f"      Exact package archives inspected: {inspected_count}")
            reporter.line(f"      Libraries included: {count}; unresolved: {len(normalized_module)}")
            reporter.event(
                "module_sbom_created", service=rel, libraries=count,
                exact_package_archives_inspected=inspected_count, unresolved=len(normalized_module),
            )

        unresolved_output = result_dir / "unresolved.json"
        normalized_unresolved_rows = _write_unresolved_result(unresolved_output, unresolved_all)

        print("")
        reporter.start_step(3, "CycloneDX SBOM")
        if not generated:
            reporter.line("  NOT CREATED: no service produced a module SBOM")
            reporter.event("aggregate_sbom_not_created", reason="no module SBOMs")
            _write_json(result_dir / "summary.json", _summary_document(
                root=root, config=config, modules=len(projects), libraries=0,
                unresolved=len(normalized_unresolved_rows), vulnerability_data={}, status="failed",
            ))
            reporter.finish("failed", unresolved=len(normalized_unresolved_rows))
            return 1

        output = result_dir / "bom.cdx.json"
        merged = merge_sboms(generated, output, root.name)
        sbom_summary = stats(merged)
        resolution_summary = _resolution_stats(merged)
        reporter.line("  Created: result/bom.cdx.json")
        reporter.line(f"  Libraries: {sbom_summary['libraries']}; dependency edges: {sbom_summary['dependency_edges']}; not included: {len(normalized_unresolved_rows)}")
        if resolution_summary["gradle_resolved"]:
            reporter.line(f"  Gradle-resolved libraries: {resolution_summary['gradle_resolved']}")
        reporter.event(
            "aggregate_sbom_created", libraries=sbom_summary["libraries"],
            dependency_edges=sbom_summary["dependency_edges"], unresolved=len(normalized_unresolved_rows),
        )

        print("")
        reporter.start_step(4, "Vulnerability scan")
        raw_trivy = work_dir / "trivy-raw.json"
        trivy_log = command_logs / "trivy.log"
        try:
            if config.trivy_db_update:
                reporter.line("  Updating Trivy vulnerability database...")
            else:
                reporter.line("  Using the existing Trivy vulnerability database without updating it.")
            reporter.line(f"  Scanning severities: {','.join(config.severities)}")
            trivy = scan_trivy(
                output, raw_trivy, trivy_log,
                severities=config.severities,
                update_db=config.trivy_db_update,
                install=True,
            )
            vulnerabilities, _licenses = findings_with_paths(merged, trivy)
            write_vulnerabilities(result_dir / "vulnerabilities.json", vulnerabilities)
            vsummary = vulnerability_summary(vulnerabilities)
            counts = ", ".join(f"{level}: {vsummary[level.lower()]}" for level in config.severities)
            reporter.line(f"  Vulnerabilities: {vsummary['total']} ({counts})")
            reporter.line(f"  Relation: direct={vsummary['direct']}, transitive={vsummary['transitive']}, unknown={vsummary['unknown_relation']}")
            reporter.event("trivy_scan_completed", **vsummary)
        except Exception as exc:
            (result_dir / "vulnerabilities.json").write_text("[]\n", encoding="utf-8")
            reporter.line(f"  ERROR: Trivy scan failed: {exc}")
            reporter.event("trivy_scan_failed", reason=str(exc))
            exit_code = 1

        graph_path = result_dir / "dependency-graph.html"
        write_dependency_graph_html(graph_path, merged, vulnerabilities)
        reporter.event("dependency_graph_created", file="result/dependency-graph.html")

        print("")
        reporter.start_step(5, "Summary")
        vsummary = vulnerability_summary(vulnerabilities)
        reporter.line(f"  Libraries in SBOM: {sbom_summary['libraries']}")
        counts = ", ".join(f"{level}: {vsummary[level.lower()]}" for level in config.severities)
        reporter.line(f"  Vulnerabilities: {vsummary['total']} ({counts})")
        reporter.line(f"  Transitive vulnerabilities: {vsummary['transitive']}")
        reporter.line(f"  Libraries not included: {len(normalized_unresolved_rows)}")
        if normalized_unresolved_rows:
            current_service = None
            for row in normalized_unresolved_rows:
                if row["service"] != current_service:
                    current_service = row["service"]
                    reporter.line(f"    [{current_service}]")
                reporter.line(f"      - {row['library']} - {row['description']}")
        else:
            reporter.line("    none")
        reporter.line(f"  Results: {result_dir}")
        reporter.line(f"  Process log: {log_dir / 'process.json'}")
        final_status = "success" if exit_code == 0 else "partial"
        _write_json(result_dir / "summary.json", _summary_document(
            root=root, config=config, modules=len(projects), libraries=sbom_summary["libraries"],
            unresolved=len(normalized_unresolved_rows), vulnerability_data=vsummary, status=final_status,
            resolution_data=resolution_summary,
        ))
        reporter.event(
            "scan_summary", libraries=sbom_summary["libraries"], vulnerabilities=vsummary["total"],
            transitive_vulnerabilities=vsummary["transitive"], unresolved=len(normalized_unresolved_rows),
            result_files=["summary.json", "discovery.json", "bom.cdx.json", "vulnerabilities.json", "unresolved.json", "dependency-graph.html"],
        )
        reporter.finish(
            final_status, libraries=sbom_summary["libraries"],
            vulnerabilities=vsummary["total"], unresolved=len(normalized_unresolved_rows),
        )
        return exit_code
    finally:
        # Detailed resolver/command output is temporary. The durable log is the
        # single concise .scan-sca_osa/logs/process.json document.
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)
        if not reporter.path.exists():
            reporter.finish("failed")


def main(argv: List[str] | None = None) -> int:
    return _run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
