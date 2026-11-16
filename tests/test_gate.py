from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from gaingate.cli import main
from gaingate.gatecmd import validate_gate
from gaingate.workspace import EXAMPLE_DIR, dump_yaml


def _example(name: str, tmp_path: Path) -> Path:
    dest = tmp_path / name
    shutil.copytree(EXAMPLE_DIR / name, dest)
    return dest


def test_notes_api_pass(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    verdict = validate_gate(case)
    assert verdict.passed
    assert verdict.status == "PASS"
    assert verdict.synthetic
    text = main_stdout(case)
    assert "GainGate verdict: PASS" in text
    assert "SYN-0001 (synthetic)" in text


def main_stdout(case: Path) -> str:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["gate", "validate", "--case-dir", str(case)])
    # caller checks rc separately when needed
    _ = rc
    return buf.getvalue()


def test_notes_api_pass_cli_exit_zero(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    assert main(["gate", "validate", "--case-dir", str(case)]) == 0


def test_fail_baseline_not_exceeded(tmp_path: Path) -> None:
    case = _example("fail-baseline", tmp_path)
    verdict = validate_gate(case)
    assert not verdict.passed
    rules = [f.rule for f in verdict.findings]
    assert "gained_capability_must_strictly_exceed_baseline" in rules
    assert main(["gate", "validate", "--case-dir", str(case)]) == 1


def test_fail_required_hop_source_asserted(tmp_path: Path) -> None:
    case = _example("fail-required-hop", tmp_path)
    verdict = validate_gate(case)
    assert not verdict.passed
    rules = [f.rule for f in verdict.findings]
    assert "required_hop_not_executed" in rules


def test_fail_uncleared_confound(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    gate = yaml.safe_load((case / "gate.yaml").read_text(encoding="utf-8"))
    gate["confounds"][0]["cleared"] = False
    gate["confounds"][0]["reason"] = ""
    dump_yaml(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    rules = [f.rule for f in verdict.findings]
    assert "confound_not_cleared" in rules
    assert "confound_missing_reason" in rules


def test_fail_cleared_confound_without_reason(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    gate = yaml.safe_load((case / "gate.yaml").read_text(encoding="utf-8"))
    gate["confounds"][1]["reason"] = ""
    dump_yaml(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert any(f.rule == "confound_missing_reason" for f in verdict.findings)


def test_fail_missing_required_fields(case: Path) -> None:
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule == "required_field_missing" for f in verdict.findings)
    assert any(f.rule == "claim_must_name_required_hops" for f in verdict.findings)


def test_fail_identical_capability_text(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    gate = yaml.safe_load((case / "gate.yaml").read_text(encoding="utf-8"))
    gate["gained_capability"] = gate["baseline_capability"]
    dump_yaml(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert any(
        f.rule == "gained_capability_must_strictly_exceed_baseline"
        for f in verdict.findings
    )


def test_fail_required_hop_not_feasible(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    hops = yaml.safe_load((case / "hops.yaml").read_text(encoding="utf-8"))
    # Make the claim depend on H4, which is NOT_FEASIBLE in the walkthrough.
    gate = yaml.safe_load((case / "gate.yaml").read_text(encoding="utf-8"))
    gate["required_hops"] = ["H1", "H2", "H3", "H4"]
    dump_yaml(case / "gate.yaml", gate)
    verdict = validate_gate(case)
    assert any(f.rule == "required_hop_not_executed" for f in verdict.findings)


def test_fail_missing_evidence_on_required_hop(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    (case / "evidence" / "h2_cross_tenant_read.log").unlink()
    verdict = validate_gate(case)
    assert any(f.rule == "required_hop_evidence_missing" for f in verdict.findings)



def _rewrite_hop_evidence(case: Path, hop_id: str, evidence: str) -> None:
    hops_path = case / "hops.yaml"
    data = yaml.safe_load(hops_path.read_text(encoding="utf-8"))
    for hop in data["hops"]:
        if hop.get("id") == hop_id:
            hop["evidence"] = evidence
            hop["label"] = "EXECUTED"
    dump_yaml(hops_path, data)


def test_validate_rejects_absolute_outside_evidence(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    empty = Path("/tmp/empty.log")
    empty.write_text("", encoding="utf-8")
    _rewrite_hop_evidence(case, "H1", str(empty))
    verdict = validate_gate(case)
    assert not verdict.passed
    assert verdict.status == "FAIL"
    assert any(f.rule == "required_hop_evidence_invalid" for f in verdict.findings)

    outside = tmp_path / "outside_nonempty.log"
    outside.write_text("non-empty but outside the case\n", encoding="utf-8")
    case2 = _example("pass", tmp_path / "abs")
    _rewrite_hop_evidence(case2, "H1", str(outside))
    verdict2 = validate_gate(case2)
    assert not verdict2.passed
    assert any(f.rule == "required_hop_evidence_invalid" for f in verdict2.findings)


def test_validate_rejects_dotdot_and_symlink_escape(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    outside = tmp_path / "escaped.log"
    outside.write_text("escaped content\n", encoding="utf-8")
    _rewrite_hop_evidence(case, "H1", "../escaped.log")
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule == "required_hop_evidence_invalid" for f in verdict.findings)

    case2 = _example("pass", tmp_path / "sym")
    link = case2 / "evidence" / "alias.log"
    link.symlink_to(outside)
    _rewrite_hop_evidence(case2, "H1", "evidence/alias.log")
    verdict2 = validate_gate(case2)
    assert not verdict2.passed
    assert any(f.rule == "required_hop_evidence_invalid" for f in verdict2.findings)


def test_validate_rejects_empty_evidence_file(tmp_path: Path) -> None:
    case = _example("pass", tmp_path)
    empty = case / "evidence" / "empty.log"
    empty.write_text("", encoding="utf-8")
    _rewrite_hop_evidence(case, "H1", "evidence/empty.log")
    verdict = validate_gate(case)
    assert not verdict.passed
    assert any(f.rule == "required_hop_evidence_invalid" for f in verdict.findings)
