"""Capture generic local environment facts. No network."""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gaingate.workspace import dump_yaml

# Local version probes only. Never used as a target fingerprint catalog.
_TOOLCHAIN_COMMANDS: tuple[tuple[str, list[str]], ...] = (
    ("python", [sys.executable, "--version"]),
    ("go", ["go", "version"]),
    ("rustc", ["rustc", "--version"]),
    ("gcc", ["gcc", "--version"]),
    ("clang", ["clang", "--version"]),
    ("node", ["node", "--version"]),
    ("java", ["java", "-version"]),
)


def _first_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[0] if lines else ""


def _probe_version(argv: list[str]) -> str | None:
    binary = argv[0]
    if binary != sys.executable and shutil.which(binary) is None:
        return None
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or "") + (result.stderr or "")
    line = _first_line(text)
    return line or None


def _os_name() -> str:
    os_release = Path("/etc/os-release")
    if os_release.is_file():
        fields: dict[str, str] = {}
        for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                fields[key] = value.strip().strip('"')
        pretty = fields.get("PRETTY_NAME") or fields.get("NAME")
        if pretty:
            return pretty
    return f"{platform.system()} {platform.release()}".strip()


def _kernel() -> str:
    return f"{platform.system()} {platform.release()}".strip()


def _lsm_or_sandbox() -> str:
    facts: list[str] = []
    lsm_file = Path("/sys/kernel/security/lsm")
    if lsm_file.is_file():
        listing = lsm_file.read_text(encoding="utf-8", errors="replace").strip()
        if listing:
            facts.append(f"lsm={listing}")
    apparmor = Path("/sys/module/apparmor/parameters/enabled")
    if apparmor.is_file():
        value = apparmor.read_text(encoding="utf-8", errors="replace").strip()
        facts.append(f"apparmor={value or 'present'}")
    selinux = Path("/sys/fs/selinux/enforce")
    if selinux.is_file():
        value = selinux.read_text(encoding="utf-8", errors="replace").strip()
        facts.append(f"selinux_enforce={value}")
    if not facts:
        return "none recorded"
    return ", ".join(facts)


def collect_env() -> dict[str, Any]:
    toolchain: dict[str, str] = {}
    for name, argv in _TOOLCHAIN_COMMANDS:
        version = _probe_version(argv)
        if version:
            toolchain[name] = version
    recorded_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    return {
        "kernel": _kernel(),
        "os": _os_name(),
        "toolchain": toolchain,
        "lsm_or_sandbox": _lsm_or_sandbox(),
        "recorded_at": recorded_at,
    }


def record_env(case: Path) -> dict[str, Any]:
    record = collect_env()
    header = "# Local environment facts recorded by `gaingate env`. No network."
    dump_yaml(case / "env.yaml", record, header=header)
    return record
