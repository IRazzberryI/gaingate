"""Append a labeled reproduction hop to the hop log."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from gaingate.workspace import (
    WorkspaceError,
    dump_yaml,
    load_hops,
    resolve_executed_evidence,
    sha256_file,
)

VALID_LABELS = ("EXECUTED", "SOURCE_ASSERTED", "NOT_FEASIBLE")


def add_hop(
    case: Path,
    *,
    hop_id: str,
    description: str,
    label: str,
    evidence: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    hop_id = (hop_id or "").strip()
    description = (description or "").strip()
    label = (label or "").strip().upper()
    evidence = (evidence or "").strip() or None
    reason = (reason or "").strip() or None

    if not hop_id:
        raise WorkspaceError("a hop --id is required")
    if not description:
        raise WorkspaceError("a hop --description is required")
    if label not in VALID_LABELS:
        raise WorkspaceError(
            f"label must be one of {', '.join(VALID_LABELS)} (got {label or 'empty'})"
        )

    if label == "EXECUTED":
        if not evidence:
            raise WorkspaceError(
                "EXECUTED hops require --evidence pointing at a non-empty file "
                "inside evidence/"
            )
        evidence = resolve_executed_evidence(case, evidence, hop_id=hop_id)
        evidence_sha256 = sha256_file((case / evidence).resolve())
    else:
        evidence_sha256 = None
    if label in ("SOURCE_ASSERTED", "NOT_FEASIBLE") and not reason:
        raise WorkspaceError(
            f"{label} hops require --reason (the tool will not imply why the step was not run)"
        )

    hops = load_hops(case / "hops.yaml")
    if any(str(h.get("id", "")).strip() == hop_id for h in hops):
        raise WorkspaceError(f"hop id {hop_id!r} already exists in hops.yaml")

    entry: dict[str, Any] = {
        "id": hop_id,
        "description": description,
        "label": label,
    }
    if evidence:
        entry["evidence"] = evidence
    if evidence_sha256:
        entry["evidence_sha256"] = evidence_sha256
    if reason:
        entry["reason"] = reason
    hops.append(entry)
    header = (
        "# Hop log. Labels: EXECUTED | SOURCE_ASSERTED | NOT_FEASIBLE\n"
        "# The tool does not run hops. EXECUTED requires a non-empty evidence\n"
        "# file inside evidence/ and stores its sha256; validate and pack re-check\n"
        "# that digest. The tool does not verify that the file is truthful."
    )
    dump_yaml(case / "hops.yaml", {"hops": hops}, header=header)
    return entry
