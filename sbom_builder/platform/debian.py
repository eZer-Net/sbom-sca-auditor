from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable, Sequence

Runner = Callable[[Sequence[str], Path, Path], object]


def is_debian_family() -> bool:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return Path("/etc/debian_version").exists()
    text = os_release.read_text(encoding="utf-8", errors="ignore").lower()
    return "id=debian" in text or "id=ubuntu" in text or "id_like=debian" in text


def _prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if sudo:
        return [sudo]
    raise RuntimeError("automatic package installation requires root privileges or sudo")


def _apt_install(packages: list[str], log: Path, runner: Runner) -> None:
    prefix = _prefix()
    runner([*prefix, "apt-get", "update"], Path.cwd(), log)
    runner([*prefix, "apt-get", "install", "-y", *packages], Path.cwd(), log)


def _install_trivy(log: Path, runner: Runner) -> None:
    prefix = _prefix()
    _apt_install(["wget", "gnupg", "ca-certificates"], log, runner)
    key_tmp = Path("/tmp/sbom-sca-auditor-trivy-public.key")
    runner([
        "wget", "-qO", str(key_tmp),
        "https://aquasecurity.github.io/trivy-repo/deb/public.key",
    ], Path.cwd(), log)
    runner([
        *prefix, "gpg", "--dearmor", "--yes",
        "--output", "/usr/share/keyrings/trivy.gpg", str(key_tmp),
    ], Path.cwd(), log)
    repo_line = "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main"
    runner([
        *prefix, "sh", "-c",
        f"printf '%s\\n' '{repo_line}' > /etc/apt/sources.list.d/trivy.list",
    ], Path.cwd(), log)
    _apt_install(["trivy"], log, runner)
    try:
        key_tmp.unlink()
    except OSError:
        pass


def _install_dotnet(log: Path, runner: Runner) -> None:
    _apt_install(["curl", "ca-certificates"], log, runner)
    script = Path("/tmp/dotnet-install.sh")
    runner(["curl", "-fsSL", "https://dot.net/v1/dotnet-install.sh", "-o", str(script)], Path.cwd(), log)
    runner(["bash", str(script), "--channel", "8.0", "--install-dir", str(Path.home() / ".dotnet")], Path.cwd(), log)


def _install_conan(log: Path, runner: Runner) -> None:
    _apt_install(["pipx", "python3-venv"], log, runner)
    runner(["pipx", "install", "conan"], Path.cwd(), log)


def _install_vcpkg(log: Path, runner: Runner) -> None:
    _apt_install(["git", "curl", "zip", "unzip", "tar", "cmake", "ninja-build", "build-essential"], log, runner)
    home = Path.home() / ".local" / "share" / "vcpkg"
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    if not home.exists():
        runner(["git", "clone", "--depth", "1", "https://github.com/microsoft/vcpkg.git", str(home)], Path.cwd(), log)
    runner(["bash", str(home / "bootstrap-vcpkg.sh"), "-disableMetrics"], home, log)
    target = bin_dir / "vcpkg"
    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(home / "vcpkg")


def install_command(name: str, package_hint: list[str], log: Path, runner: Runner) -> None:
    if name == "trivy":
        _install_trivy(log, runner)
        return
    if name == "dotnet":
        _install_dotnet(log, runner)
        return
    if name == "conan":
        _install_conan(log, runner)
        return
    if name == "vcpkg":
        _install_vcpkg(log, runner)
        return

    packages = {
        "python3": ["python3"],
        "node": ["nodejs", "npm"],
        "npm": ["nodejs", "npm"],
        "npx": ["nodejs", "npm"],
        "git": ["git"],
        "mvn": ["maven"],
        "gradle": ["default-jdk-headless", "gradle"],
        "java": ["default-jdk-headless"],
        "go": ["golang-go"],
        "cargo": ["cargo"],
        "php": ["php-cli"],
        "composer": ["composer"],
        "pipx": ["pipx"],
        "cmake": ["cmake"],
    }.get(name)
    if not packages:
        raise RuntimeError(
            f"missing command: {name}. Automatic installation is not configured for this tool on Debian/Ubuntu"
        )
    _apt_install(packages, log, runner)
