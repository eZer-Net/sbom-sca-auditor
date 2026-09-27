from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class FailureDiagnosis:
    code: str
    summary: str
    hint: Optional[str] = None


def _extract_ssh_target(text: str) -> tuple[str | None, str | None, str | None]:
    """Return (user, host, port) from an ssh:// URL found in command output."""
    match = re.search(r"ssh://(?:(?P<user>[^@/\s]+)@)?(?P<host>[^:/\s]+)(?::(?P<port>\d+))?", text)
    if not match:
        return None, None, None
    return match.group("user") or "git", match.group("host"), match.group("port")


def diagnose_log(log: Path) -> FailureDiagnosis | None:
    if not log.exists():
        return None
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    low = text.lower()

    if "host key verification failed" in low:
        user, host, port = _extract_ssh_target(text)
        hint = None
        if host:
            port_arg = f" -p {port}" if port else ""
            hint = f"verify SSH trust/access first: ssh -Tv{port_arg} {user or 'git'}@{host}"
        return FailureDiagnosis(
            "PRIVATE_GIT_SSH_HOST_KEY",
            "private Git dependency could not be fetched because SSH host-key verification failed",
            hint,
        )

    if "permission denied (publickey)" in low:
        user, host, port = _extract_ssh_target(text)
        hint = None
        if host:
            port_arg = f" -p {port}" if port else ""
            hint = f"check your SSH key/agent and repository permissions: ssh -Tv{port_arg} {user or 'git'}@{host}"
        return FailureDiagnosis(
            "PRIVATE_GIT_SSH_AUTH",
            "private Git dependency could not be fetched because SSH authentication failed",
            hint,
        )

    if "could not read from remote repository" in low:
        return FailureDiagnosis(
            "PRIVATE_GIT_ACCESS",
            "Git dependency could not be read; repository URL, credentials, VPN/network access or permissions may be invalid",
        )

    if any(marker in low for marker in ("e401", "401 unauthorized", "authentication required")):
        return FailureDiagnosis(
            "REGISTRY_AUTH",
            "package registry authentication failed",
            "check the package-manager registry configuration and credentials for the current user",
        )

    if any(marker in low for marker in ("e403", "403 forbidden")):
        return FailureDiagnosis(
            "REGISTRY_FORBIDDEN",
            "package registry denied access to a dependency",
            "check repository/package permissions and registry credentials",
        )

    if any(marker in low for marker in ("no matching distribution found", "no candidates at all for", "couldn't find any versions")):
        return FailureDiagnosis(
            "DEPENDENCY_NOT_RESOLVABLE",
            "a declared dependency/version is unavailable from the configured registries",
            "check the dependency version and private registry configuration",
        )

    if "your lockfile needs to be updated" in low or "frozen lockfile" in low and "error" in low:
        return FailureDiagnosis(
            "LOCKFILE_MISMATCH",
            "the lockfile does not match the dependency manifest",
            "regenerate/commit the lockfile with the package manager used by the project",
        )

    return None
