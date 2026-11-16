from __future__ import annotations

from pathlib import Path

import pytest

from gaingate.cli import main
from gaingate.initcmd import init_case
from gaingate.workspace import WorkspaceError


def test_init_creates_templates(tmp_path: Path) -> None:
    dest = init_case(tmp_path / "fresh")
    for name in (
        "gate.yaml",
        "pin.yaml",
        "hops.yaml",
        "env.yaml",
        "report.md",
        "confound_registry.yaml",
    ):
        assert (dest / name).is_file()
    assert (dest / "evidence").is_dir()


def test_init_cli(tmp_path: Path) -> None:
    dest = tmp_path / "cli-case"
    assert main(["init", str(dest)]) == 0
    assert (dest / "gate.yaml").is_file()


def test_init_refuses_existing_case(tmp_path: Path) -> None:
    dest = init_case(tmp_path / "once")
    with pytest.raises(WorkspaceError, match="already looks like a case"):
        init_case(dest)
