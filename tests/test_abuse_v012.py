"""Acceptance tests for the v0.1.1 abuse cases, replayed against this tree.

Steps follow the hunter repros. Fixed cases must FAIL or be rejected.
Documented lows (07, 08, 09, 10, 12) assert the desired rejection and are
marked xfail as known limitations.
"""

from __future__ import annotations

import io
import os
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
import yaml

from gaingate.cli import main
from gaingate.gatecmd import validate_gate
from gaingate.hopcmd import add_hop
from gaingate.packcmd import pack_case
from gaingate.workspace import EXAMPLE_DIR, WorkspaceError, dump_yaml, sha256_file


def _example(name: str, dest: Path) -> Path:
    shutil.copytree(EXAMPLE_DIR / name, dest)
    return dest


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _dump(path: Path, data: dict) -> None:
    dump_yaml(path, data)


def _cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_abuse_01_swap_after_check_fails(tmp_path: Path) -> None:
    # GG-ABUSE-01: overwrite evidence after a PASS; validate and pack must FAIL.
    case = _example("pass", tmp_path / "swap")
    rc, stdout, _ = _cli(["gate", "validate", "--case-dir", str(case)])
    assert rc == 0
    assert "PASS" in stdout
    (case / "evidence" / "h2_cross_tenant_read.log").write_text(
        "FORGED EVIDENCE — not the original hop output.\n", encoding="utf-8"
    )
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any("digest_mismatch" in f.rule for f in verdict.findings)
    rc, stdout, _ = _cli(["pack", "--case-dir", str(case), "--output", str(case / "pack_out")])
    assert rc == 1
    md = (case / "pack_out" / "evidence_pack.md").read_text(encoding="utf-8")
    assert "GainGate verdict: FAIL" in md


def test_abuse_01_swap_after_hop_add_fails(tmp_path: Path) -> None:
    demo = _example("pass", tmp_path / "swap_add")
    (demo / "evidence" / "h5.log").write_text("original hop output\n", encoding="utf-8")
    add_hop(
        demo,
        hop_id="H5",
        description="logged step",
        label="EXECUTED",
        evidence="evidence/h5.log",
    )
    (demo / "evidence" / "h5.log").write_text("SWAPPED after hop add\n", encoding="utf-8")
    verdict = validate_gate(demo)
    assert not verdict.passed
    assert any("digest_mismatch" in f.rule for f in verdict.findings)


def test_abuse_02_hardlink_rejected(tmp_path: Path) -> None:
    # GG-ABUSE-02: hard link from evidence/ to an outside file is rejected.
    case = _example("pass", tmp_path / "hard")
    outside = tmp_path / "outside.log"
    outside.write_text("HARD-LINKED OUTSIDE CONTENT\n", encoding="utf-8")
    target = case / "evidence" / "h5_hard.log"
    os.link(outside, target)
    with pytest.raises(WorkspaceError, match="hard link"):
        add_hop(
            case,
            hop_id="H5",
            description="hardlinked",
            label="EXECUTED",
            evidence="evidence/h5_hard.log",
        )
    # Existing required hop replaced by a hard link of the same bytes.
    original = case / "evidence" / "h1_setup.log"
    same_bytes = tmp_path / "same_as_h1.log"
    same_bytes.write_bytes(original.read_bytes())
    original.unlink()
    os.link(same_bytes, original)
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any("hard link" in f.detail for f in verdict.findings)


def test_abuse_03_duplicate_hop_ids_fail(tmp_path: Path) -> None:
    # GG-ABUSE-03: a dummy EXECUTED H2 must not shadow a SOURCE_ASSERTED H2.
    case = _example("pass", tmp_path / "dup")
    data = _load(case / "hops.yaml")
    for hop in data["hops"]:
        if hop["id"] == "H2":
            hop["label"] = "SOURCE_ASSERTED"
            hop["reason"] = "the real step was only read in source"
            hop.pop("evidence", None)
            hop.pop("evidence_sha256", None)
            hop["description"] = "REAL cross-tenant step (asserted only)"
    data["hops"].append(
        {
            "id": "H2",
            "description": "dummy executed hop that shadows the real H2",
            "label": "EXECUTED",
            "evidence": "evidence/h1_setup.log",
            "evidence_sha256": sha256_file(case / "evidence" / "h1_setup.log"),
        }
    )
    _dump(case / "hops.yaml", data)
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule == "duplicate_hop_id" for f in verdict.findings)
    rc, stdout, _ = _cli(["gate", "validate", "--case-dir", str(case)])
    assert rc == 1
    assert "all EXECUTED" not in stdout


def test_abuse_04_hand_set_confirmed_is_not_claimed(tmp_path: Path) -> None:
    # GG-ABUSE-04: hand-edited confirmed:true must not appear as ls-remote confirmation.
    case = _example("pass", tmp_path / "pinlie")
    pin = _load(case / "pin.yaml")
    pin["confirmed"] = True
    pin["pin_method"] = "git_ls_remote_user_url"
    pin["warnings"] = []
    _dump(case / "pin.yaml", pin)
    written = pack_case(case, output=case / "pack_out")
    md = written["markdown"].read_text(encoding="utf-8")
    import json

    data = json.loads(written["json"].read_text(encoding="utf-8"))
    assert "Confirmed via git ls-remote: True" not in md
    assert "Confirmed via git ls-remote: False" in md
    assert data["pin"]["confirmed"] is False
    # The example pin is valid (repo + commit), so this case can still PASS.
    # The lie is only about the confirmation claim.


def test_abuse_05_empty_pin_fails(tmp_path: Path) -> None:
    # GG-ABUSE-05: PASS requires a pin that names a repository and a commit.
    case = _example("pass", tmp_path / "nopin")
    (case / "pin.yaml").write_text("{}\n", encoding="utf-8")
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule in {"pin_missing", "pin_incomplete"} for f in verdict.findings)
    rc, stdout, _ = _cli(["gate", "validate", "--case-dir", str(case)])
    assert rc == 1
    assert "FAIL" in stdout


def test_abuse_06_case_id_zip_stays_inside_output(tmp_path: Path) -> None:
    # GG-ABUSE-06: unsanitized case_id must not write a zip outside --output.
    case = _example("pass", tmp_path / "caseid")
    gate = _load(case / "gate.yaml")
    gate["case_id"] = "x/../../ESCAPED_FROM_CASEID"
    _dump(case / "gate.yaml", gate)
    out = case / "pack_out"
    out.mkdir()
    (out / "gaingate-pack-x").mkdir()
    escaped = case / "ESCAPED_FROM_CASEID.zip"
    rc, stdout, stderr = _cli(["pack", "--case-dir", str(case), "--output", str(out)])
    assert "Traceback" not in stderr
    assert rc in {1, 2}
    assert not escaped.exists()
    zips = list(out.glob("gaingate-pack-*.zip"))
    assert len(zips) == 1
    assert zips[0].resolve().parent == out.resolve()
    assert ".." not in zips[0].name
    assert "/" not in zips[0].name


def test_abuse_11_homoglyph_is_not_a_strict_gain(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "homo")
    gate = _load(case / "gate.yaml")
    # Cyrillic 'е' in action; same resource and constraint as baseline.
    gate["gained"] = [
        {"action": "rеad", "resource": "notes", "constraint": "owner is tenant A"}
    ]
    gate["gained_capability"] = "read notes owned by tenant A only (via lookalike)"
    _dump(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed
    rules = [f.rule for f in verdict.findings]
    assert "capability_needs_human_review" in rules or (
        "gained_capability_must_strictly_exceed_baseline" in rules
    )


def test_abuse_11_zwsp_is_normalized(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "zwsp")
    gate = _load(case / "gate.yaml")
    gate["gained"] = [
        {"action": "read\u200b", "resource": "notes", "constraint": "owner is tenant A"}
    ]
    gate["gained_capability"] = "read notes owned by tenant A only\u200b"
    _dump(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(
        f.rule == "gained_capability_must_strictly_exceed_baseline"
        or f.rule == "capability_needs_human_review"
        for f in verdict.findings
    )


def test_abuse_11_near_duplicate_constraint_is_not_a_strict_gain(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "neardup")
    gate = _load(case / "gate.yaml")
    gate["gained"] = [
        {
            "action": "read",
            "resource": "notes",
            "constraint": "owner is tenant A (checked)",
        }
    ]
    gate["gained_capability"] = "read notes owned by tenant A only (checked)"
    _dump(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(
        f.rule in {
            "capability_needs_human_review",
            "gained_capability_must_strictly_exceed_baseline",
        }
        for f in verdict.findings
    )


def test_abuse_13_pack_exits_nonzero_on_fail(tmp_path: Path) -> None:
    # GG-ABUSE-13: pack still writes a FAIL pack, but exits 1, and embeds
    # version, timestamp, and a content hash.
    case = _example("fail-baseline", tmp_path / "packfail")
    out = tmp_path / "out"
    rc, stdout, _ = _cli(["pack", "--case-dir", str(case), "--output", str(out)])
    assert rc == 1
    import json

    payload = json.loads((out / "evidence_pack.json").read_text(encoding="utf-8"))
    md = (out / "evidence_pack.md").read_text(encoding="utf-8")
    assert payload["verdict"]["status"] == "FAIL"
    assert payload["tool_version"]
    assert payload["pack_written_at"]
    assert payload["pack_content_sha256"]
    assert len(payload["pack_content_sha256"]) == 64
    assert "Pack content sha256:" in md
    sidecar = out / "evidence_pack.sha256"
    assert sidecar.is_file()
    assert sidecar.read_text(encoding="utf-8").split()[0]


def test_abuse_13_pass_pack_embeds_hash_and_exits_zero(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "packpass")
    out = tmp_path / "out"
    rc, _, _ = _cli(["pack", "--case-dir", str(case), "--output", str(out)])
    assert rc == 0
    import json

    payload = json.loads((out / "evidence_pack.json").read_text(encoding="utf-8"))
    assert payload["verdict"]["status"] == "PASS"
    assert payload["pack_content_sha256"]
    assert (out / "evidence_pack.sha256").is_file()


# --- Documented lows: desired rejection, known limitation in v0.1.2 ---

_XFAIL_DOC = "known limitation: documented in README Not checked section"


@pytest.mark.xfail(reason=f"GG-ABUSE-07: {_XFAIL_DOC}", strict=False)
def test_abuse_07_newline_in_evidence_filename_rejected(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "newline")
    ev_dir = case / "evidence"
    src = ev_dir / "h1_setup.log"
    dest = ev_dir / "h1\nsetup.log"
    dest.write_bytes(src.read_bytes())
    data = _load(case / "hops.yaml")
    for hop in data["hops"]:
        if hop.get("id") == "H1":
            hop["evidence"] = "evidence/h1\nsetup.log"
            hop["evidence_sha256"] = sha256_file(dest)
    _dump(case / "hops.yaml", data)
    verdict = validate_gate(case)
    assert not verdict.passed


@pytest.mark.xfail(reason=f"GG-ABUSE-08: {_XFAIL_DOC}", strict=False)
def test_abuse_08_shared_evidence_file_rejected(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "shared")
    data = _load(case / "hops.yaml")
    h1_digest = sha256_file(case / "evidence" / "h1_setup.log")
    for hop in data["hops"]:
        if hop.get("id") == "H2":
            hop["evidence"] = "evidence/h1_setup.log"
            hop["evidence_sha256"] = h1_digest
    _dump(case / "hops.yaml", data)
    verdict = validate_gate(case)
    assert not verdict.passed


@pytest.mark.xfail(reason=f"GG-ABUSE-09: {_XFAIL_DOC}", strict=False)
def test_abuse_09_whitespace_only_evidence_rejected(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "ws")
    path = case / "evidence" / "h1_setup.log"
    path.write_text("\n", encoding="utf-8")
    data = _load(case / "hops.yaml")
    for hop in data["hops"]:
        if hop.get("id") == "H1":
            hop["evidence_sha256"] = sha256_file(path)
    _dump(case / "hops.yaml", data)
    verdict = validate_gate(case)
    assert not verdict.passed


@pytest.mark.xfail(reason=f"GG-ABUSE-10: {_XFAIL_DOC}", strict=False)
def test_abuse_10_dropped_gain_hops_rejected(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "drop")
    data = _load(case / "hops.yaml")
    for hop in data["hops"]:
        if hop.get("id") in {"H2", "H3"}:
            hop["label"] = "SOURCE_ASSERTED"
            hop["reason"] = "not run; dropped from required_hops"
            hop.pop("evidence", None)
            hop.pop("evidence_sha256", None)
    _dump(case / "hops.yaml", data)
    gate = _load(case / "gate.yaml")
    gate["required_hops"] = ["H1"]
    _dump(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed


@pytest.mark.xfail(reason=f"GG-ABUSE-12: {_XFAIL_DOC}", strict=False)
def test_abuse_12_placeholder_confound_reason_rejected(tmp_path: Path) -> None:
    case = _example("pass", tmp_path / "placeholder")
    gate = _load(case / "gate.yaml")
    for item in gate["confounds"]:
        item["reason"] = "n/a"
    _dump(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert not verdict.passed
