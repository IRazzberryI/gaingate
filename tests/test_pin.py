from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from gaingate.cli import main
from gaingate.pincmd import hash_file, record_pin, run_ls_remote
from gaingate.workspace import WorkspaceError

AAAA = "a" * 40
BBBB = "b" * 64


def test_pin_offline_records_operator_sha(case: Path) -> None:
    record = record_pin(
        case,
        tag="v9.9.9",
        sha=AAAA,
        origin="https://git.example.invalid/example-org/notes-api.git",
        offline=True,
        artifact_sha256=BBBB,
        case_id="SYN-0001",
        subject="notes-api",
    )
    assert record["commit_sha"] == AAAA
    assert record["artifact_sha256"] == BBBB
    assert record["release_tag"] == "v9.9.9"
    assert record["pin_method"] == "offline_operator_supplied"
    assert record["confirmed"] is False
    assert "ls_remote" not in record
    assert record["operator_stated_origin"].endswith("notes-api.git")
    assert any("not confirmed" in w for w in record["warnings"])
    saved = yaml.safe_load((case / "pin.yaml").read_text(encoding="utf-8"))
    assert saved["commit_sha"] == AAAA


def test_pin_offline_requires_sha(case: Path) -> None:
    with pytest.raises(WorkspaceError, match="must pass --sha"):
        record_pin(case, tag="v9.9.9", sha=None, origin=None, offline=True)


def test_pin_without_origin_does_not_call_git(case: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> str:
        raise AssertionError("git ls-remote must not run without an operator-supplied origin")

    monkeypatch.setattr("gaingate.pincmd.run_ls_remote", boom)
    record = record_pin(case, tag="v9.9.9", sha=AAAA, origin=None, offline=False)
    assert record["pin_method"] == "offline_operator_supplied"
    assert record["confirmed"] is False


def test_pin_offline_with_origin_still_skips_network(case: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> str:
        raise AssertionError("git ls-remote must not run when --offline is set")

    monkeypatch.setattr("gaingate.pincmd.run_ls_remote", boom)
    record = record_pin(
        case,
        tag="v9.9.9",
        sha=AAAA,
        origin="https://git.example.invalid/example-org/notes-api.git",
        offline=True,
    )
    assert record["pin_method"] == "offline_operator_supplied"
    assert record["operator_stated_origin"].startswith("https://git.example.invalid/")


def test_pin_rejects_short_sha(case: Path) -> None:
    with pytest.raises(WorkspaceError, match="40-character"):
        record_pin(case, tag="v9.9.9", sha="abc", origin=None, offline=True)


def test_pin_hashes_local_artifact_file(case: Path, tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"synthetic-artifact")
    expected = hash_file(artifact)
    record = record_pin(
        case,
        tag="v9.9.9",
        sha=AAAA,
        origin=None,
        offline=True,
        artifact_file=str(artifact),
    )
    assert record["artifact_sha256"] == expected
    assert len(expected) == 64


def test_pin_ls_remote_mocked(case: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_ls(origin: str, tag: str, timeout: int = 30) -> str:
        assert origin == "https://git.example.invalid/example-org/notes-api.git"
        assert tag == "v9.9.9"
        return AAAA

    monkeypatch.setattr("gaingate.pincmd.run_ls_remote", fake_ls)
    record = record_pin(
        case,
        tag="v9.9.9",
        sha=None,
        origin="https://git.example.invalid/example-org/notes-api.git",
        offline=False,
    )
    assert record["commit_sha"] == AAAA
    assert record["pin_method"] == "git_ls_remote_user_url"
    assert record["confirmed"] is True
    rec = record["ls_remote"]
    assert rec["origin"] == "https://git.example.invalid/example-org/notes-api.git"
    assert rec["result"] == AAAA
    assert rec["tag"] == "v9.9.9"
    assert rec["recorded_at"]


def test_pin_ls_remote_mismatch(case: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gaingate.pincmd.run_ls_remote", lambda *_a, **_k: "c" * 40)
    with pytest.raises(WorkspaceError, match="does not match"):
        record_pin(
            case,
            tag="v9.9.9",
            sha=AAAA,
            origin="https://git.example.invalid/example-org/notes-api.git",
            offline=False,
        )


def test_run_ls_remote_refuses_empty_origin() -> None:
    with pytest.raises(WorkspaceError, match="operator-supplied"):
        run_ls_remote("", "v9.9.9")


def test_pin_cli_offline(case: Path) -> None:
    rc = main(
        [
            "pin",
            "--offline",
            "--case-dir",
            str(case),
            "--tag",
            "v9.9.9",
            "--sha",
            AAAA,
            "--artifact-sha256",
            BBBB,
        ]
    )
    assert rc == 0
    text = (case / "pin.yaml").read_text(encoding="utf-8")
    assert AAAA in text
