from __future__ import annotations

import json
import re
import shutil
import zipfile
from pathlib import Path

from gaingate.cli import main
from gaingate.packcmd import PACK_FOOTER, pack_case
from gaingate.workspace import EXAMPLE_DIR


def test_pack_contains_verdict_pin_env_hops(tmp_path: Path) -> None:
    case = tmp_path / "pass"
    shutil.copytree(EXAMPLE_DIR / "pass", case)
    written = pack_case(case)
    md = written["markdown"].read_text(encoding="utf-8")
    payload = json.loads(written["json"].read_text(encoding="utf-8"))

    assert "GainGate verdict: PASS" in md
    assert "Provenance pin" in md
    assert "Environment facts" in md
    assert "Hop log" in md
    assert "H1" in md and "H2" in md and "H3" in md
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in md
    assert PACK_FOOTER in md
    assert payload["verdict"]["status"] == "PASS"
    assert payload["pin"]["release_tag"] == "v9.9.9"
    assert payload["env"]["kernel"]
    assert {h["id"] for h in payload["hops"]} >= {"H1", "H2", "H3", "H4"}
    assert payload["disclaimer"] == PACK_FOOTER


def test_pack_does_not_invent_hops(tmp_path: Path) -> None:
    case = tmp_path / "empty"
    shutil.copytree(EXAMPLE_DIR / "fail-baseline", case)
    # Drop hops and confirm the pack does not fabricate replacements.
    (case / "hops.yaml").write_text("hops: []\n", encoding="utf-8")
    written = pack_case(case)
    md = written["markdown"].read_text(encoding="utf-8")
    payload = json.loads(written["json"].read_text(encoding="utf-8"))
    assert payload["hops"] == []
    assert "does not invent missing steps" in md


def test_pack_records_fail_verdict(tmp_path: Path) -> None:
    case = tmp_path / "fail"
    shutil.copytree(EXAMPLE_DIR / "fail-baseline", case)
    written = pack_case(case)
    md = written["markdown"].read_text(encoding="utf-8")
    payload = json.loads(written["json"].read_text(encoding="utf-8"))
    assert "GainGate verdict: FAIL" in md
    assert payload["verdict"]["status"] == "FAIL"
    assert "gained_capability_must_strictly_exceed_baseline" in md


def test_pack_zip_and_cli(tmp_path: Path) -> None:
    case = tmp_path / "pass"
    shutil.copytree(EXAMPLE_DIR / "pass", case)
    out = tmp_path / "out"
    rc = main(["pack", "--case-dir", str(case), "--output", str(out)])
    assert rc == 0
    zips = list(out.glob("gaingate-pack-*.zip"))
    assert len(zips) == 1
    with zipfile.ZipFile(zips[0]) as zf:
        names = set(zf.namelist())
    assert "gate.yaml" in names
    assert "pack/evidence_pack.md" in names
    assert "evidence/h1_setup.log" in names



def _assert_no_absolute_paths(text: str) -> None:
    # Shareable pack output must not contain host-absolute or home paths.
    assert not re.search(r"(?m)(^|[\\s=:\\\"'`])(/tmp/|/home/|/Users/)", text)
    for line in text.splitlines():
        stripped = line.strip().lstrip("- ").lstrip()
        if stripped.startswith("/"):
            raise AssertionError(f"absolute path leaked into pack: {line!r}")


def test_pack_contains_evidence_files_and_no_absolute_paths(tmp_path: Path) -> None:
    case = tmp_path / "pass"
    shutil.copytree(EXAMPLE_DIR / "pass", case)
    written = pack_case(case)
    md = written["markdown"].read_text(encoding="utf-8")
    payload_text = written["json"].read_text(encoding="utf-8")
    payload = json.loads(payload_text)

    expected = [
        "evidence/h1_setup.log",
        "evidence/h2_cross_tenant_read.log",
        "evidence/h3_content_compare.log",
    ]
    with zipfile.ZipFile(written["zip"]) as zf:
        names = set(zf.namelist())
        hops_yaml = zf.read("hops.yaml").decode("utf-8")
        pack_md = zf.read("pack/evidence_pack.md").decode("utf-8")
        pack_json = zf.read("pack/evidence_pack.json").decode("utf-8")
        for name in expected:
            assert name in names
            info = zf.getinfo(name)
            assert info.file_size > 0
        for name in names:
            assert not name.startswith("/")
            assert ".." not in Path(name).parts

    for hop in payload["hops"]:
        evidence = hop.get("evidence")
        if evidence:
            assert not Path(evidence).is_absolute()
            assert ".." not in Path(evidence).parts

    for blob in (md, payload_text, hops_yaml, pack_md, pack_json):
        _assert_no_absolute_paths(blob)
        assert "evidence paths present" not in blob or "non-empty evidence files present under evidence/" in blob


def test_pack_does_not_claim_or_leak_invalid_evidence(tmp_path: Path) -> None:
    case = tmp_path / "pass"
    shutil.copytree(EXAMPLE_DIR / "pass", case)
    empty = Path("/tmp/empty.log")
    empty.write_text("", encoding="utf-8")
    hops = (case / "hops.yaml").read_text(encoding="utf-8")
    hops = hops.replace("evidence/h1_setup.log", str(empty), 1)
    (case / "hops.yaml").write_text(hops, encoding="utf-8")
    written = pack_case(case)
    md = written["markdown"].read_text(encoding="utf-8")
    payload = json.loads(written["json"].read_text(encoding="utf-8"))
    assert "GainGate verdict: FAIL" in md
    assert "evidence paths present" not in md
    assert "missing or invalid" in md
    assert str(empty) not in md
    assert "/tmp/" not in md
    with zipfile.ZipFile(written["zip"]) as zf:
        hops_yaml = zf.read("hops.yaml").decode("utf-8")
        pack_md = zf.read("pack/evidence_pack.md").decode("utf-8")
        pack_json = zf.read("pack/evidence_pack.json").decode("utf-8")
    for blob in (hops_yaml, pack_md, pack_json, json.dumps(payload)):
        assert "/tmp/" not in blob
        assert str(empty) not in blob
        assert "evidence paths present" not in blob
