from __future__ import annotations

import platform as _platform
from pathlib import Path
from typing import Callable, Sequence

from .debian import install_command as install_debian_command, is_debian_family
from .macos import install_command as install_macos_command

Runner = Callable[[Sequence[str], Path, Path], object]


def platform_name() -> str:
    system = _platform.system()
    if system == "Darwin":
        return "macOS"
    if system == "Linux" and is_debian_family():
        return "Debian/Ubuntu Linux"
    if system == "Linux":
        return "Linux"
    return system or "Unknown"


def install_command(name: str, package_hint: list[str], log: Path, runner: Runner) -> None:
    system = _platform.system()
    if system == "Darwin":
        install_macos_command(name, package_hint, log, runner)
        return
    if system == "Linux" and is_debian_family():
        install_debian_command(name, package_hint, log, runner)
        return
    raise RuntimeError(
        f"automatic installation for '{name}' is supported only on macOS and Debian/Ubuntu; install it manually"
    )
