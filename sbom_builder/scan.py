from __future__ import annotations

import json
from collections import Counter, deque
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .tools import ensure_command, run_logged


def _norm_name(value: str) -> str:
    return value.strip().lower().replace('_', '-').replace('.', '-')


def _iter_components(items: Iterable[dict]) -> Iterable[dict]:
    for item in items or []:
        if not isinstance(item, dict):
            continue
        yield item
        children = item.get('components')
        if isinstance(children, list):
            yield from _iter_components(children)


def _graph(sbom: dict) -> tuple[str | None, Dict[str, List[str]], Dict[str, dict]]:
    metadata = sbom.get('metadata') or {}
    root = metadata.get('component') or {}
    root_ref = root.get('bom-ref') if isinstance(root, dict) else None
    edges: Dict[str, List[str]] = {}
    for dep in sbom.get('dependencies') or []:
        if not isinstance(dep, dict) or not dep.get('ref'):
            continue
        edges[str(dep['ref'])] = [str(x) for x in dep.get('dependsOn') or []]
    components = {
        str(c.get('bom-ref')): c
        for c in _iter_components(sbom.get('components') or [])
        if c.get('bom-ref')
    }
    if isinstance(root, dict) and root_ref:
        components[str(root_ref)] = root
    return str(root_ref) if root_ref else None, edges, components


def _shortest_path(root: str | None, target: str, edges: Dict[str, List[str]]) -> List[str]:
    if not root:
        return []
    q = deque([(root, [root])])
    seen = {root}
    while q:
        node, path = q.popleft()
        if node == target:
            return path
        for child in edges.get(node, []):
            if child not in seen:
                seen.add(child)
                q.append((child, path + [child]))
    return []


def _path_entry(ref: str, components: Dict[str, dict]) -> dict:
    comp = components.get(ref) or {}
    return {
        'library': str(comp.get('name') or '?'),
        'version': str(comp.get('version') or '?'),
    }


def _match_component(pkg_name: str, version: str, components: Dict[str, dict]) -> Optional[str]:
    exact: List[str] = []
    name_only: List[str] = []
    wanted = _norm_name(pkg_name)
    for ref, comp in components.items():
        name = _norm_name(str(comp.get('name') or ''))
        if name != wanted:
            continue
        name_only.append(ref)
        if version and str(comp.get('version') or '') == version:
            exact.append(ref)
    if exact:
        return exact[0]
    if len(name_only) == 1:
        return name_only[0]
    return None


def scan_trivy(
    sbom_path: Path,
    report_path: Path,
    log: Path,
    *,
    severities: tuple[str, ...] = ("CRITICAL", "HIGH"),
    update_db: bool = True,
    install: bool = True,
) -> dict:
    trivy = ensure_command("trivy", ["trivy"], log, install)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    if update_db:
        cp = run_logged(
            [trivy, "image", "--download-db-only", "--no-progress"],
            sbom_path.parent,
            log,
            check=False,
        )
        if cp.returncode != 0:
            raise RuntimeError(f"Trivy vulnerability database update failed (exit={cp.returncode})")

    cmd = [
        trivy, "sbom",
        "--scanners", "vuln",
        "--severity", ",".join(severities),
        "--format", "json",
        "--output", str(report_path),
    ]
    # The database has either just been refreshed or the user explicitly asked
    # not to update it during this scan.
    cmd.append("--skip-db-update")
    cmd.append(str(sbom_path))

    cp = run_logged(cmd, sbom_path.parent, log, check=False)
    if not report_path.exists() or report_path.stat().st_size == 0:
        raise RuntimeError(f"Trivy did not create report (exit={cp.returncode})")
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Trivy report is not valid JSON: {exc}") from exc

def findings_with_paths(sbom: dict, trivy: dict) -> tuple[List[dict], List[dict]]:
    """Return vulnerability findings enriched with the CycloneDX dependency path.

    The dependency hierarchy comes from the CycloneDX graph. Trivy supplies the
    vulnerability metadata; the wrapper correlates each finding back to the
    matching component and stores the shortest root -> component path.
    """
    root_ref, edges, components = _graph(sbom)
    vulnerabilities: List[dict] = []
    licenses: List[dict] = []

    for result in trivy.get('Results') or []:
        if not isinstance(result, dict):
            continue
        for finding in result.get('Vulnerabilities') or []:
            if not isinstance(finding, dict):
                continue
            name = str(finding.get('PkgName') or '')
            version = str(finding.get('InstalledVersion') or '')
            ref = _match_component(name, version, components)
            path_refs = _shortest_path(root_ref, ref, edges) if ref else []
            path = [_path_entry(r, components) for r in path_refs]
            relation = "transitive" if len(path) > 3 else ("direct" if len(path) >= 2 else "unknown")
            service = path[1]["library"] if len(path) >= 2 else None
            version_source = "project-metadata"
            if ref:
                props = components.get(ref, {}).get("properties") or []
                for prop in props:
                    if isinstance(prop, dict) and prop.get("name") == "sbom-sca-auditor:version-source":
                        version_source = str(prop.get("value") or version_source)
                        break
            vulnerabilities.append({
                'id': str(finding.get('VulnerabilityID') or ''),
                'severity': str(finding.get('Severity') or 'UNKNOWN'),
                'service': service,
                'library': name,
                'installed_version': version,
                'fixed_version': str(finding.get('FixedVersion') or '') or None,
                'version_source': version_source,
                'relation': relation,
                'path': path,
            })
        for finding in result.get('Licenses') or []:
            if isinstance(finding, dict):
                licenses.append(finding)

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    vulnerabilities.sort(key=lambda x: (severity_order.get(x['severity'], 9), x['library'], x['id']))
    return vulnerabilities, licenses


def vulnerability_summary(vulnerabilities: List[dict]) -> dict:
    sev = Counter(str(v.get("severity") or "UNKNOWN").upper() for v in vulnerabilities)
    relations = Counter(str(v.get("relation") or "unknown") for v in vulnerabilities)
    return {
        "total": len(vulnerabilities),
        "critical": sev.get("CRITICAL", 0),
        "high": sev.get("HIGH", 0),
        "medium": sev.get("MEDIUM", 0),
        "low": sev.get("LOW", 0),
        "unknown": sev.get("UNKNOWN", 0),
        "direct": relations.get("direct", 0),
        "transitive": relations.get("transitive", 0),
        "unknown_relation": relations.get("unknown", 0),
    }

def _english_reason(reason: str) -> str:
    """Normalize internal resolver errors into concise English audit reasons."""
    text = str(reason or '').strip()
    low = text.lower()
    if 'individually resolvable' in low and 'coherent dependency graph' in low:
        return 'The package resolves individually, but the full dependency set has version conflicts; a single verified graph could not be built'
    if 'public pypi resolution failed' in low:
        return 'The package and exact version could not be resolved through public PyPI'
    if 'public npm resolution failed' in low:
        return 'The package and exact version could not be resolved through the public npm registry'
    if 'private/vcs/unsupported dependency' in low or 'private/vcs/local dependency' in low or 'non-registry/private/vcs/local' in low:
        return 'The dependency points to a private, VCS, local, or unsupported source and could not be verified through public sources'
    if 'constraint cannot be translated safely' in low:
        return 'The version constraint could not be translated safely for the resolver; an exact version was not verified'
    if 'version is not an exact resolved version' in low:
        return 'The manifest does not contain an exact resolved version; the package was not added to the SBOM'
    if 'dependency inferred from source has no exact version' in low:
        return 'The dependency was inferred from source code, but no exact version is known; unpinned/latest packages are not downloaded or added to the SBOM'
    if 'dependency version is not exact' in low:
        return 'The dependency version is not pinned exactly; version ranges/latest are not downloaded or added to the SBOM'
    if 'exact package archive could not be downloaded and inspected safely from public pypi' in low:
        return 'An exact version is declared, but the package archive could not be downloaded and inspected safely through public PyPI'
    if 'exact package archive could not be downloaded and inspected from public npm registry' in low:
        return 'An exact version is declared, but the package archive could not be downloaded and inspected through the public npm registry'
    if 'dependency source is private/vcs/local' in low:
        return 'The dependency points to a private, VCS, or local source; this scanner does not fetch those sources'
    if 'dependency syntax/source is not an exact public package pin' in low:
        return 'The dependency is not an exact public package pin and cannot be verified for SBOM inclusion'
    if 'dependency inferred from source' in low:
        return 'The import was found in source code, but an exact package and version could not be verified'
    if 'native/private resolution failed' in low:
        return 'Native/private dependency resolution failed; only available local/public evidence was used'
    if 'could not be mapped' in low:
        return 'The dependency record could not be mapped unambiguously to a resolved lockfile component'
    if text:
        return text
    return 'The package and exact version could not be verified for SBOM inclusion'


def normalized_unresolved(rows: List[dict]) -> List[dict]:
    """Return only fields useful to an auditor: service, library, reason."""
    source_rank = {
        'scanner': 100, 'public-pypi': 90, 'public-npm': 90, 'resolver': 85,
        'dependency-metadata': 80, 'package.json': 75, 'requirements': 75,
        'source-import': 10, 'module': 5,
    }
    chosen: dict[tuple, tuple[int, dict]] = {}
    for row in rows:
        service = str(row.get('module') or '.')
        library = str(row.get('name') or row.get('raw') or '?')
        item = {
            'service': service,
            'library': library,
            'description': _english_reason(str(row.get('reason') or '')),
        }
        key = (service, library.lower())
        rank = source_rank.get(str(row.get('source') or ''), 50)
        previous = chosen.get(key)
        if previous is None or rank > previous[0]:
            chosen[key] = (rank, item)
    out = [item for _, item in chosen.values()]
    out.sort(key=lambda x: (x['service'], x['library'].lower(), x['description']))
    return out


def write_vulnerabilities(path: Path, vulnerabilities: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(vulnerabilities, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
