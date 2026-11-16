from __future__ import annotations

from pathlib import Path

import pytest

from gaingate.cli import main
from gaingate.examplecmd import synth_example
from gaingate.gatecmd import validate_gate
from gaingate.workspace import WorkspaceError


def test_example_synth_copies_pass_and_fails(tmp_path: Path) -> None:
    dest = synth_example(tmp_path / "demo")
    assert (dest / "README.md").is_file()
    assert "synthetic" in (dest / "README.md").read_text(encoding="utf-8").lower()
    assert "not a real project" in (dest / "README.md").read_text(encoding="utf-8").lower()
    for leaf in ("pass", "fail-baseline", "fail-required-hop"):
        assert (dest / leaf / "gate.yaml").is_file()


def test_example_synth_pass_validates(tmp_path: Path) -> None:
    dest = synth_example(tmp_path / "demo")
    assert validate_gate(dest / "pass").passed
    assert not validate_gate(dest / "fail-baseline").passed
    assert not validate_gate(dest / "fail-required-hop").passed


def test_example_synth_cli(tmp_path: Path) -> None:
    dest = tmp_path / "from-cli"
    assert main(["example", "synth", str(dest)]) == 0
    assert (dest / "pass" / "gate.yaml").is_file()


def test_example_synth_refuses_nonempty(tmp_path: Path) -> None:
    dest = tmp_path / "taken"
    dest.mkdir()
    (dest / "already.txt").write_text("nope\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="not empty"):
        synth_example(dest)
