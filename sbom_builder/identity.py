from __future__ import annotations

import hashlib
from pathlib import Path

from .model import Project


def module_id(project: Project, scan_root: Path) -> str:
    try:
        rel = project.root.relative_to(scan_root)
        label = str(rel) if str(rel) != "." else project.root.name
    except ValueError:
        label = project.root.name
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in label)
    digest = hashlib.sha1(project.key.encode()).hexdigest()[:8]
    return f"{project.ecosystem}-{project.manager}-{safe}-{digest}"
