from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from gaingate.cli import main
from gaingate.hopcmd import add_hop
from gaingate.workspace import WorkspaceError, sha256_file


def test_add_executed_with_evidence(case: Path, evidence_file: Path) -> None:
    entry = add_hop(
        case,
        hop_id="H1",
        description="Set up two isolated tenants",
        label="EXECUTED",
        evidence="evidence/h1.log",
    )
    assert entry["label"] == "EXECUTED"
    assert entry["evidence"] == "evidence/h1.log"
    hops = yaml.safe_load((case / "hops.yaml").read_text(encoding="utf-8"))["hops"]
    assert hops[0]["id"] == "H1"
    assert hops[0]["evidence"] == "evidence/h1.log"
    assert not Path(hops[0]["evidence"]).is_absolute()
    assert hops[0]["evidence_sha256"] == sha256_file(evidence_file)
    assert entry["evidence_sha256"] == hops[0]["evidence_sha256"]


def test_add_executed_without_evidence_rejected(case: Path) -> None:
    with pytest.raises(WorkspaceError, match="require --evidence"):
        add_hop(
            case,
            hop_id="H1",
            description="missing evidence",
            label="EXECUTED",
        )


def test_add_executed_missing_file_rejected(case: Path) -> None:
    with pytest.raises(WorkspaceError, match="evidence file not found"):
        add_hop(
            case,
            hop_id="H1",
            description="missing file",
            label="EXECUTED",
            evidence="evidence/does-not-exist.log",
        )


def test_add_not_feasible_requires_reason(case: Path) -> None:
    with pytest.raises(WorkspaceError, match="require --reason"):
        add_hop(
            case,
            hop_id="H4",
            description="historical release",
            label="NOT_FEASIBLE",
        )


def test_add_source_asserted_with_reason(case: Path) -> None:
    entry = add_hop(
        case,
        hop_id="H2",
        description="Inferred from source",
        label="SOURCE_ASSERTED",
        reason="Read in source only; not run",
    )
    assert entry["label"] == "SOURCE_ASSERTED"


def test_add_rejects_duplicate_id(case: Path, evidence_file: Path) -> None:
    add_hop(
        case,
        hop_id="H1",
        description="first",
        label="EXECUTED",
        evidence="evidence/h1.log",
    )
    with pytest.raises(WorkspaceError, match="already exists"):
        add_hop(
            case,
            hop_id="H1",
            description="again",
            label="EXECUTED",
            evidence="evidence/h1.log",
        )


def test_hop_add_cli(case: Path, evidence_file: Path) -> None:
    rc = main(
        [
            "hop",
            "add",
            "--case-dir",
            str(case),
            "--id",
            "H1",
            "--description",
            "Set up two isolated tenants",
            "--label",
            "EXECUTED",
            "--evidence",
            "evidence/h1.log",
        ]
    )
    assert rc == 0



def test_add_executed_rejects_absolute_outside_path(case: Path, tmp_path: Path) -> None:
    empty = Path("/tmp/empty.log")
    empty.write_text("", encoding="utf-8")
    assert empty.stat().st_size == 0
    with pytest.raises(WorkspaceError, match="absolute path rejected"):
        add_hop(
            case,
            hop_id="H1",
            description="outside empty file",
            label="EXECUTED",
            evidence=str(empty),
        )
    outside = tmp_path / "outside_nonempty.log"
    outside.write_text("not in the case\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="absolute path rejected"):
        add_hop(
            case,
            hop_id="H1",
            description="outside non-empty file",
            label="EXECUTED",
            evidence=str(outside),
        )
    hops = yaml.safe_load((case / "hops.yaml").read_text(encoding="utf-8"))["hops"]
    assert hops == []


def test_add_executed_rejects_dotdot_and_symlink_escape(
    case: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "escaped.log"
    outside.write_text("escaped content\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match=r"must not contain '\.\.'"):
        add_hop(
            case,
            hop_id="H1",
            description="dotdot escape",
            label="EXECUTED",
            evidence="../escaped.log",
        )
    link = case / "evidence" / "h1.log"
    link.symlink_to(outside)
    with pytest.raises(WorkspaceError, match="escapes the case directory"):
        add_hop(
            case,
            hop_id="H1",
            description="symlink escape",
            label="EXECUTED",
            evidence="evidence/h1.log",
        )


def test_add_executed_rejects_empty_file(case: Path) -> None:
    empty = case / "evidence" / "empty.log"
    empty.write_text("", encoding="utf-8")
    assert empty.stat().st_size == 0
    with pytest.raises(WorkspaceError, match="empty"):
        add_hop(
            case,
            hop_id="H1",
            description="empty evidence",
            label="EXECUTED",
            evidence="evidence/empty.log",
        )
