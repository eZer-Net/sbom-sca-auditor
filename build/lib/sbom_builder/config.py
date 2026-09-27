from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SUPPORTED_SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
DEFAULT_SEVERITIES = ("CRITICAL", "HIGH")


@dataclass(frozen=True)
class ScanConfig:
    target: Path
    output_root: Path
    severities: tuple[str, ...] = DEFAULT_SEVERITIES
    trivy_db_update: bool = True

    @property
    def result_dir(self) -> Path:
        return self.output_root / "result"

    @property
    def log_dir(self) -> Path:
        return self.output_root / "logs"

    @property
    def work_dir(self) -> Path:
        return self.output_root / ".work"
