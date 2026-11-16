"""Acceptance tests for the v0.1.3 follow-up (TOCTOU pack, non-ASCII caps, case_id)."""

from __future__ import annotations

import hashlib
import io
import shutil
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
import yaml

from gaingate.cli import main
from gaingate.gatecmd import validate_gate
from gaingate.packcmd import pack_case
from gaingate.workspace import (
    EXAMPLE_DIR,
    MAX_CASE_ID_LEN,
    WorkspaceError,
    dump_yaml,
    sanitize_case_id_for_filename,
)


def _example(name: str, dest: Path) -> Path:
    shutil.copytree(EXAMPLE_DIR / name, dest)
    return dest


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_pack_toctou_swap_between_validate_and_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GG-V012-01: a swap after validate_gate must not produce a PASS pack
    # whose zip bytes differ from the stored digest.
    case = _example("pass", tmp_path / "toctou")
    target = case / "evidence" / "h2_cross_tenant_read.log"
    original = target.read_bytes()
    original_digest = hashlib.sha256(original).hexdigest()
    swapped = b"TOCTOU-SWAPPED-BYTES-AFTER-HASH\n"

    from gaingate.gatecmd import validate_gate as real_validate

    def swap_after_validate(case_dir: Path):
        verdict = real_validate(case_dir)
        target.write_bytes(swapped)
        return verdict

    monkeypatch.setattr("gaingate.packcmd.validate_gate", swap_after_validate)

    try:
        written = pack_case(case, output=tmp_path / "out")
    except WorkspaceError as exc:
        assert "sha256" in str(exc).lower() or "digest" in str(exc).lower()
        assert target.read_bytes() == swapped
        return

    with zipfile.ZipFile(written["zip"]) as zf:
        packed = zf.read("evidence/h2_cross_tenant_read.log")
    packed_digest = hashlib.sha256(packed).hexdigest()
    if written.get("passed"):
        assert packed == original
        assert packed_digest == original_digest
        assert b"TOCTOU-SWAPPED" not in packed
    else:
        # Pack may fail instead of shipping a PASS with swapped bytes.
        assert packed_digest == original_digest or packed == swapped


def test_case_id_dot_and_dotdot_rejected(tmp_path: Path) -> None:
    for value in (".", ".."):
        case = _example("pass", tmp_path / f"id_{value.replace('.', 'dot')}")
        gate = _load(case / "gate.yaml")
        gate["case_id"] = value
        dump_yaml(case / "gate.yaml", gate)
        verdict = validate_gate(case)
        assert not verdict.passed
        assert any(f.rule == "case_id_invalid" for f in verdict.findings)
        out = case / "pack_out"
        rc, _, err = _cli(["pack", "--case-dir", str(case), "--output", str(out)])
        assert "Traceback" not in err
        assert rc == 1
        zips = list(out.glob("gaingate-pack-*.zip"))
        assert len(zips) == 1
        assert zips[0].resolve().parent == out.resolve()
        assert zips[0].name != "gaingate-pack-..zip"
        assert zips[0].name != "gaingate-pack-.zip"


def test_case_id_longer_than_128_rejected_before_pack_write(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "longid")
    gate = _load(case / "gate.yaml")
    gate["case_id"] = "A" * (MAX_CASE_ID_LEN + 1)
    dump_yaml(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule == "case_id_invalid" for f in verdict.findings)
    out = case / "pack_out"
    rc, _, err = _cli(["pack", "--case-dir", str(case), "--output", str(out)])
    assert "Traceback" not in err
    assert "File name too long" not in err
    assert rc == 1
    zips = list(out.glob("gaingate-pack-*.zip"))
    assert len(zips) == 1
    assert zips[0].resolve().parent == out.resolve()
    assert len(zips[0].name) < 255
    assert len(sanitize_case_id_for_filename("A" * 5000)) == MAX_CASE_ID_LEN


@pytest.mark.parametrize(
    "action",
    [
        "suм",  # Cyrillic м U+043C
        "leт",  # Cyrillic т U+0442
        "marк",  # Cyrillic к U+043A
        "iн",  # Cyrillic н U+043D
        "réad",
        "re\u0301ad",
        "café",
        "cafe\u0301",
    ],
)
def test_non_ascii_capability_needs_human_review(tmp_path: Path, action: str) -> None:
    # GG-V012-02: any non-ASCII capability string after NFKC/Cf strip is flagged
    # and does not count as a strict gain, even with distinct ASCII free text.
    case = _example("pass", tmp_path / "cap")
    gate = _load(case / "gate.yaml")
    gate["gained"] = [
        {
            "action": action,
            "resource": "notes",
            "constraint": "owner is tenant B",
        }
    ]
    gate["gained_capability"] = (
        "read a note owned by tenant B, using only tenant-A credentials"
    )
    dump_yaml(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule == "capability_needs_human_review" for f in verdict.findings)
