from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def _component_identity(c: dict) -> str:
    if c.get("purl"):
        return str(c["purl"])
    return "|".join(str(c.get(k, "")) for k in ("type", "group", "name", "version"))


def _iter_components(items: Iterable[dict]) -> Iterable[dict]:
    for c in items or []:
        yield c
        yield from _iter_components(c.get("components", []))


def _ref_for(module_id: str, original: str) -> str:
    digest = hashlib.sha256(f"{module_id}|{original}".encode()).hexdigest()[:24]
    return f"urn:sbom-sca-auditor:{module_id}:{digest}"


def _rewrite_component_tree(c: dict, refmap: Dict[str, str], module_id: str) -> dict:
    out = copy.deepcopy(c)
    old = str(out.get("bom-ref") or _component_identity(out))
    new = refmap.setdefault(old, _ref_for(module_id, old))
    out["bom-ref"] = new
    if isinstance(out.get("components"), list):
        out["components"] = [_rewrite_component_tree(x, refmap, module_id) for x in out["components"]]
    return out


def merge_sboms(inputs: List[Tuple[str, Path]], output: Path, root_name: str) -> dict:
    root_ref = f"urn:sbom-sca-auditor:root:{uuid.uuid5(uuid.NAMESPACE_URL, str(output.resolve()))}"
    final_components: List[dict] = []
    final_dependencies: List[dict] = []
    root_depends: List[str] = []

    for module_id, path in inputs:
        data = json.loads(path.read_text(encoding="utf-8"))
        refmap: Dict[str, str] = {}

        metadata = data.get("metadata") or {}
        module_root = metadata.get("component")
        if isinstance(module_root, dict):
            rewritten_root = _rewrite_component_tree(module_root, refmap, module_id)
            final_components.append(rewritten_root)
            root_depends.append(rewritten_root["bom-ref"])

        for c in data.get("components") or []:
            final_components.append(_rewrite_component_tree(c, refmap, module_id))

        for dep in data.get("dependencies") or []:
            old_ref = str(dep.get("ref", ""))
            if not old_ref:
                continue
            new_ref = refmap.setdefault(old_ref, _ref_for(module_id, old_ref))
            depends = []
            for child in dep.get("dependsOn") or []:
                child = str(child)
                depends.append(refmap.setdefault(child, _ref_for(module_id, child)))
            entry = {"ref": new_ref}
            if depends:
                entry["dependsOn"] = sorted(set(depends))
            final_dependencies.append(entry)


    # The aggregate root depends on each module root.
    final_dependencies.insert(0, {"ref": root_ref, "dependsOn": sorted(set(root_depends))})

    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": root_name,
                "version": "local",
                "bom-ref": root_ref,
            }
        },
        "components": final_components,
        "dependencies": final_dependencies,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def stats(sbom: dict) -> dict:
    comps = list(_iter_components(sbom.get("components") or []))
    unique = {_component_identity(c) for c in comps}
    dep_nodes = sbom.get("dependencies") or []
    edges = sum(len(d.get("dependsOn") or []) for d in dep_nodes)
    libraries = [c for c in comps if str(c.get("type", "")).lower() in {"library", "framework"}]
    unique_libraries = {_component_identity(c) for c in libraries}
    return {
        "components": len(comps),
        "unique_components": len(unique),
        "libraries": len(libraries),
        "unique_libraries": len(unique_libraries),
        "dependency_nodes": len(dep_nodes),
        "dependency_edges": edges,
    }
