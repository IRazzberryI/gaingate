"""Helpers for locating and reading a GainGate case workspace."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

CASE_MARKERS = ("gate.yaml", "pin.yaml", "hops.yaml", "env.yaml", "report.md")
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
SAFE_CASE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_CASE_ID_LEN = 128
EXAMPLE_DIR = Path(__file__).resolve().parent / "examples" / "notes-api"




def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_case_id_for_filename(case_id: str) -> str:
    """Return a single path-safe token for use in a pack zip name."""
    raw = (case_id or "").strip()
    if raw in {".", ".."} or not raw:
        return "case"
    if SAFE_CASE_ID_RE.fullmatch(raw) and ".." not in raw:
        return raw[:MAX_CASE_ID_LEN]
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in raw)
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")
    cleaned = re.sub(r"_+", "_", cleaned).strip("._-")
    return (cleaned or "case")[:MAX_CASE_ID_LEN]


def case_id_is_safe(case_id: str) -> bool:
    raw = (case_id or "").strip()
    if not raw or raw in {".", ".."} or ".." in raw:
        return False
    if len(raw) > MAX_CASE_ID_LEN:
        return False
    return bool(SAFE_CASE_ID_RE.fullmatch(raw))

class WorkspaceError(Exception):
    """The case directory is missing or is not a GainGate workspace."""


def case_dir(explicit: str | None) -> Path:
    path = Path(explicit or ".").expanduser().resolve()
    if not path.is_dir():
        raise WorkspaceError(f"case directory does not exist: {path}")
    if not (path / "gate.yaml").is_file():
        raise WorkspaceError(
            f"{path} is not a GainGate case directory (missing gate.yaml). "
            "Run `gaingate init` first, or pass --case-dir."
        )
    return path


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise WorkspaceError(f"missing file: {path}")
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise WorkspaceError(f"{path} must contain a YAML mapping at the top level")
    return data


def dump_yaml(path: Path, data: dict[str, Any], header: str | None = None) -> None:
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    if header:
        text = header.rstrip() + "\n\n" + body
    else:
        text = body
    path.write_text(text, encoding="utf-8")


def load_hops(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    hops = data.get("hops") or []
    if not isinstance(hops, list):
        raise WorkspaceError(f"{path}: 'hops' must be a list")
    return hops


def resolve_executed_evidence(
    case: Path, evidence: str, *, hop_id: str | None = None
) -> str:
    """Return a case-relative evidence path for an EXECUTED hop.

    The given path must be case-relative (no absolute path, no ``..``
    components). After symlink resolution it must be a non-empty file
    inside ``<case>/evidence/``, and must not be a hard link (``st_nlink`` must be 1). Raises WorkspaceError otherwise. This
    checks location, link count, and size; it does not verify that the
    file is a truthful record of the step.
    """
    raw = (evidence or "").strip()
    prefix = f"EXECUTED hop {hop_id}: " if hop_id else ""

    if not raw:
        raise WorkspaceError(
            f"{prefix}EXECUTED hops require --evidence pointing at a "
            "non-empty file inside evidence/"
        )

    given = Path(raw)
    if given.is_absolute():
        raise WorkspaceError(
            f"{prefix}evidence path must be case-relative and inside "
            "evidence/ (absolute path rejected)"
        )
    if ".." in given.parts:
        raise WorkspaceError(
            f"{prefix}evidence path must not contain '..' (got {raw})"
        )

    case_resolved = case.expanduser().resolve()
    evidence_root = (case_resolved / "evidence").resolve()
    if not evidence_root.is_dir() or not evidence_root.is_relative_to(case_resolved):
        raise WorkspaceError(
            f"{prefix}evidence path must resolve inside evidence/ "
            f"(evidence directory is missing or escapes the case): {raw}"
        )

    candidate = case_resolved / given
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise WorkspaceError(f"{prefix}evidence file not found: {raw}") from None

    if not resolved.is_file():
        raise WorkspaceError(f"{prefix}evidence file not found: {raw}")

    if not resolved.is_relative_to(evidence_root) or not resolved.is_relative_to(
        case_resolved
    ):
        raise WorkspaceError(
            f"{prefix}evidence path must resolve inside evidence/ "
            f"(path or symlink escapes the case directory): {raw}"
        )

    st = resolved.stat()
    if st.st_nlink > 1:
        raise WorkspaceError(
            f"{prefix}evidence file must not be a hard link "
            f"(st_nlink={st.st_nlink}): {raw}"
        )
    if st.st_size == 0:
        raise WorkspaceError(f"{prefix}evidence file is empty (0 bytes): {raw}")

    return resolved.relative_to(case_resolved).as_posix()
