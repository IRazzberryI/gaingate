"""Shared fixtures. Tests stay offline."""

from __future__ import annotations

from pathlib import Path

import pytest

from gaingate.initcmd import init_case


@pytest.fixture
def case(tmp_path: Path) -> Path:
    return init_case(tmp_path / "case")


@pytest.fixture
def evidence_file(case: Path) -> Path:
    path = case / "evidence" / "h1.log"
    path.write_text("synthetic evidence\n", encoding="utf-8")
    return path
