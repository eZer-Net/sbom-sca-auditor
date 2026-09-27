from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, Sequence

Runner = Callable[[Sequence[str], Path, Path], object]


def install_command(name: str, package_hint: list[str], log: Path, runner: Runner) -> None:
    brew = shutil.which("brew")
    if not brew:
        raise RuntimeError(
            f"missing command: {name}. Homebrew is required for automatic installation; "
            "run scripts/install-macos.sh first"
        )
    if name == "dotnet":
        runner([brew, "install", "--cask", "dotnet-sdk"], Path.cwd(), log)
        return
    args = package_hint or [name]
    runner([brew, "install", *args], Path.cwd(), log)
