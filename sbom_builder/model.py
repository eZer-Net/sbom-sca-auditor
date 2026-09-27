from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple


@dataclass(frozen=True)
class Project:
    ecosystem: str
    manager: str
    root: Path
    manifest: Path
    frameworks: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # Source-inferred umbrella projects can exclude nested module roots that
    # already have their own dependency metadata. This prevents double-counting
    # while still covering source files outside those modules (e.g. SPA).
    exclude_roots: Tuple[Path, ...] = field(default_factory=tuple)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}-{self.manager}-{self.root}"
