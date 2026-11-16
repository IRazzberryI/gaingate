from __future__ import annotations

from pathlib import Path

import yaml

from gaingate.cli import main
from gaingate.envcmd import record_env


def test_env_records_local_facts_and_skips_identity(case: Path) -> None:
    record = record_env(case)
    assert record["kernel"]
    assert record["os"]
    assert "python" in record["toolchain"]
    assert record["recorded_at"]
    assert "hostname" not in record
    assert "user" not in record
    assert "username" not in record
    saved = yaml.safe_load((case / "env.yaml").read_text(encoding="utf-8"))
    assert saved["kernel"] == record["kernel"]


def test_env_cli(case: Path) -> None:
    assert main(["env", "--case-dir", str(case)]) == 0
    assert "recorded_at" in (case / "env.yaml").read_text(encoding="utf-8")
