from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Sequence


EXTRA_PATHS = [
    Path.home() / ".local/bin",
    Path.home() / ".cargo/bin",
    Path.home() / ".dotnet",
    Path.home() / ".dotnet/tools",
    Path("/opt/homebrew/bin"),
    Path("/opt/homebrew/opt/openjdk/bin"),
    Path("/usr/local/bin"),
    Path("/usr/local/opt/openjdk/bin"),
]

_LIVE_PROGRESS = False


def set_live_progress(enabled: bool) -> None:
    global _LIVE_PROGRESS
    _LIVE_PROGRESS = bool(enabled)


def augmented_env(extra: Optional[dict] = None) -> dict:
    env = os.environ.copy()
    prefixes = [str(p) for p in EXTRA_PATHS if p.exists()]
    env["PATH"] = os.pathsep.join(prefixes + [env.get("PATH", "")])
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


def which(name: str) -> Optional[str]:
    return shutil.which(name, path=augmented_env().get("PATH"))


def _safe_arg(value: str) -> str:
    low = value.lower()
    sensitive = ("token=", "password=", "passwd=", "_auth=", "authorization=", "apikey=", "api-key=")
    if any(x in low for x in sensitive):
        if "=" in value:
            return value.split("=", 1)[0] + "=<redacted>"
        return "<redacted>"
    if "@" in value and "://" in value:
        scheme, rest = value.split("://", 1)
        if "@" in rest:
            return f"{scheme}://<credentials>@{rest.split('@', 1)[1]}"
    return value


def _display_command(cmd: Sequence[str]) -> str:
    rendered = [_safe_arg(str(x)) for x in cmd]
    text = " ".join(rendered)
    return text if len(text) <= 180 else text[:177] + "..."


def _progress(cmd: Sequence[str]) -> None:
    if _LIVE_PROGRESS:
        print(f"    -> {_display_command(cmd)}", flush=True)


def run_logged(
    cmd: Sequence[str],
    cwd: Path,
    log: Path,
    *,
    env: Optional[dict] = None,
    stdout_file: Optional[Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    log.parent.mkdir(parents=True, exist_ok=True)
    merged_env = augmented_env(env)
    _progress(cmd)
    with log.open("a", encoding="utf-8") as lf:
        lf.write("\n$ " + " ".join(str(x) for x in cmd) + "\n")
        lf.flush()
        if stdout_file:
            stdout_file.parent.mkdir(parents=True, exist_ok=True)
            with stdout_file.open("w", encoding="utf-8") as out:
                cp = subprocess.run(list(cmd), cwd=str(cwd), env=merged_env, stdout=out, stderr=lf, text=True)
        else:
            cp = subprocess.run(list(cmd), cwd=str(cwd), env=merged_env, stdout=lf, stderr=subprocess.STDOUT, text=True)
    if check and cp.returncode != 0:
        raise RuntimeError(f"command failed ({cp.returncode}): {' '.join(cmd)}; log: {log}")
    return cp


def capture(cmd: Sequence[str], cwd: Path, log: Path, *, env: Optional[dict] = None) -> str:
    log.parent.mkdir(parents=True, exist_ok=True)
    merged_env = augmented_env(env)
    _progress(cmd)
    cp = subprocess.run(list(cmd), cwd=str(cwd), env=merged_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    with log.open("a", encoding="utf-8") as lf:
        lf.write("\n$ " + " ".join(str(x) for x in cmd) + "\n")
        if cp.stdout:
            lf.write(cp.stdout)
            if not cp.stdout.endswith("\n"):
                lf.write("\n")
        lf.write(cp.stderr or "")
    if cp.returncode != 0:
        raise RuntimeError(f"command failed ({cp.returncode}): {' '.join(cmd)}; log: {log}")
    return cp.stdout.strip()


def ensure_command(name: str, package_args: list[str], log: Path, allow_install: bool) -> str:
    """Return a command path, optionally installing it with the current OS adapter."""
    path = which(name)
    if path:
        return path
    if not allow_install:
        raise RuntimeError(f"missing command: {name}")

    from .platform import install_command as platform_install_command

    platform_install_command(name, package_args, log, run_logged)
    path = which(name)
    if not path:
        raise RuntimeError(f"installation finished but command is still missing: {name}")
    return path
