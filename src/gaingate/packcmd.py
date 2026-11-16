"""Render a Markdown + JSON evidence pack from a case workspace."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from gaingate import __version__
from gaingate.gatecmd import Verdict, format_verdict, validate_gate
from gaingate.pincmd import derive_ls_remote_confirmation
from gaingate.workspace import (
    CASE_MARKERS,
    WorkspaceError,
    load_yaml,
    resolve_executed_evidence,
    sanitize_case_id_for_filename,
    sha256_bytes,
    sha256_file,
)

OMITTED_EVIDENCE = (
    "(omitted: evidence path is not a non-empty file inside evidence/)"
)

PACK_FOOTER = (
    "A PASS verdict means only that the operator's stated gain exceeded "
    "their stated baseline, on a pin that names a repository and a commit, "
    "with required hops labeled EXECUTED and accompanied by non-empty "
    "evidence files inside the case folder whose stored sha256 still matches. "
    "Eligibility and disclosure are out of band and are not decided by this "
    "tool. 'Confirmed via git ls-remote' is shown only when pin recorded its "
    "own ls-remote result and that record is still consistent."
)


def _safe_load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return load_yaml(path)
    except Exception:
        return {"_error": f"could not parse {path.name}"}


def _verdict_dict(verdict: Verdict) -> dict[str, Any]:
    return {
        "status": verdict.status,
        "case_id": verdict.case_id,
        "synthetic": verdict.synthetic,
        "findings": [{"rule": f.rule, "detail": f.detail} for f in verdict.findings],
        "attacker_position": verdict.attacker_position,
        "baseline_capability": verdict.baseline_capability,
        "gained_capability": verdict.gained_capability,
        "control_present": verdict.control_present,
        "control_location": verdict.control_location,
        "required_hops": verdict.required_hops,
    }


def build_pack_payload(case: Path, verdict: Verdict) -> dict[str, Any]:
    report_path = case / "report.md"
    report = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
    return {
        "tool": "gaingate",
        "pack_written_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "verdict": _verdict_dict(verdict),
        "pin": _safe_load(case / "pin.yaml"),
        "env": _safe_load(case / "env.yaml"),
        "hops": verdict.hops,
        "gate": _safe_load(case / "gate.yaml"),
        "operator_report": report,
        "disclaimer": PACK_FOOTER,
    }


def render_markdown(payload: dict[str, Any], verdict_text: str) -> str:
    pin = payload.get("pin") or {}
    env = payload.get("env") or {}
    hops = payload.get("hops") or []
    lines = [
        "# GainGate evidence pack",
        "",
        verdict_text.rstrip(),
        "",
        "## Provenance pin",
        "",
        f"- Case id: {pin.get('case_id') or ''}",
        f"- Subject: {pin.get('subject') or ''}",
        f"- Operator-stated origin: {pin.get('operator_stated_origin') or '(none)'}",
        f"- Release tag: {pin.get('release_tag') or ''}",
        f"- Commit SHA: {pin.get('commit_sha') or ''}",
        f"- Artifact sha256: {pin.get('artifact_sha256') or '(none)'}",
        f"- Pin method: {pin.get('pin_method') or ''}",
        f"- Confirmed via git ls-remote: {pin.get('confirmed')}",
        f"- Pack tool version: {payload.get('tool_version') or ''}",
        f"- Pack written at: {payload.get('pack_written_at') or ''}",
        f"- Pack content sha256: {payload.get('pack_content_sha256') or ''}",
    ]
    warnings = pin.get("warnings") or []
    if warnings:
        lines.append("- Warnings:")
        for warning in warnings:
            lines.append(f"  - {warning}")
    lines += [
        "",
        "## Environment facts",
        "",
        f"- Kernel: {env.get('kernel') or ''}",
        f"- OS: {env.get('os') or ''}",
        f"- LSM / sandbox: {env.get('lsm_or_sandbox') or ''}",
        f"- Recorded at: {env.get('recorded_at') or ''}",
    ]
    toolchain = env.get("toolchain") or {}
    if isinstance(toolchain, dict) and toolchain:
        lines.append("- Toolchain:")
        for name, version in toolchain.items():
            lines.append(f"  - {name}: {version}")
    lines += ["", "## Hop log", ""]
    if not hops:
        lines.append("No hops were recorded. The pack does not invent missing steps.")
    else:
        for hop in hops:
            if not isinstance(hop, dict):
                continue
            hop_id = hop.get("id") or "?"
            label = hop.get("label") or "unlabeled"
            desc = hop.get("description") or ""
            lines.append(f"- {hop_id} [{label}]: {desc}")
            if hop.get("evidence"):
                lines.append(f"  - evidence: {hop['evidence']}")
            if hop.get("evidence_sha256"):
                lines.append(f"  - evidence_sha256: {hop['evidence_sha256']}")
            if hop.get("reason"):
                lines.append(f"  - reason: {hop['reason']}")
    report = (payload.get("operator_report") or "").strip()
    lines += ["", "## Operator report", ""]
    if report:
        lines.append(report)
    else:
        lines.append("(report.md was empty. The pack does not invent a narrative.)")
    lines += ["", "## Disclaimer", "", PACK_FOOTER, ""]
    return "\n".join(lines)


def _iter_case_files(case: Path) -> list[Path]:
    files: list[Path] = []
    for marker in CASE_MARKERS:
        path = case / marker
        if path.is_file():
            files.append(path)
    registry = case / "confound_registry.yaml"
    if registry.is_file():
        files.append(registry)
    evidence = case / "evidence"
    case_resolved = case.resolve()
    evidence_root = evidence.resolve() if evidence.is_dir() else None
    if (
        evidence_root is not None
        and evidence_root.is_dir()
        and evidence_root.is_relative_to(case_resolved)
    ):
        for path in sorted(evidence.rglob("*")):
            if not path.is_file():
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                continue
            # Copy only real, non-empty files that stay inside evidence/.
            if (
                resolved.is_file()
                and resolved.is_relative_to(evidence_root)
                and resolved.stat().st_size > 0
            ):
                files.append(path)
    return files


def pack_safe_evidence_path(case: Path, evidence: str | None) -> str:
    """Return a case-relative path, or a placeholder that leaks no host path."""
    raw = "" if evidence is None else str(evidence).strip()
    if not raw:
        return ""
    try:
        return resolve_executed_evidence(case, raw)
    except WorkspaceError:
        given = Path(raw)
        if given.is_absolute() or ".." in given.parts:
            return OMITTED_EVIDENCE
        parts = given.parts
        if parts and parts[0] == "evidence":
            return Path(*parts).as_posix()
        return OMITTED_EVIDENCE


def sanitize_hops_for_pack(case: Path, hops: list[Any]) -> list[dict[str, Any]]:
    """Copy hops with evidence paths rewritten to case-relative or omitted."""
    out: list[dict[str, Any]] = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        entry = dict(hop)
        if "evidence" in entry:
            entry["evidence"] = pack_safe_evidence_path(case, entry.get("evidence"))
        out.append(entry)
    return out


def _hops_yaml_for_pack(hops: list[dict[str, Any]]) -> str:
    header = (
        "# Hop log. Labels: EXECUTED | SOURCE_ASSERTED | NOT_FEASIBLE\n"
        "# Evidence paths in this pack are case-relative."
    )
    body = yaml.safe_dump({"hops": hops}, sort_keys=False, allow_unicode=True)
    return header + "\n\n" + body



def _display_pin(pin: dict[str, Any]) -> dict[str, Any]:
    """Copy pin.yaml and replace confirmed with the derived ls-remote value."""
    if not isinstance(pin, dict):
        return {}
    display = dict(pin)
    display["confirmed"] = derive_ls_remote_confirmation(pin)
    return display


def _read_executed_evidence_buffers(
    case: Path, hops: list[Any], *, require_digest_match: bool
) -> dict[str, bytes]:
    """Read each EXECUTED evidence file once, hash that buffer, and compare.

    The same buffer is later written into the zip. The file is not opened again.
    If ``require_digest_match`` is true and a stored digest does not match,
    raise WorkspaceError so a PASS pack cannot ship unverified bytes.
    """
    buffers: dict[str, bytes] = {}
    mismatches: list[str] = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        if str(hop.get("label") or "").strip().upper() != "EXECUTED":
            continue
        evidence = str(hop.get("evidence") or "").strip()
        if not evidence:
            continue
        try:
            rel = resolve_executed_evidence(case, evidence)
        except WorkspaceError:
            continue
        if rel not in buffers:
            buffers[rel] = (case / rel).read_bytes()
        stored = str(hop.get("evidence_sha256") or "").strip().lower()
        if stored and sha256_bytes(buffers[rel]) != stored:
            hop_id = str(hop.get("id") or "?").strip() or "?"
            mismatches.append(hop_id)
    if mismatches and require_digest_match:
        raise WorkspaceError(
            "pack refused: evidence sha256 does not match the bytes being "
            "packed for hop " + ", ".join(mismatches)
        )
    return buffers


def _stage_case_file_buffers(
    case: Path,
    hops_yaml_text: str,
    evidence_buffers: dict[str, bytes],
) -> dict[str, bytes]:
    """One in-memory snapshot of files that will go in the zip (except pack/)."""
    staged = dict(evidence_buffers)
    staged["hops.yaml"] = hops_yaml_text.encode("utf-8")
    for path in _iter_case_files(case):
        rel = path.relative_to(case).as_posix()
        if rel in staged:
            continue
        staged[rel] = path.read_bytes()
    return staged


def _pack_content_sha256(
    staged: dict[str, bytes],
    verdict_status: str,
) -> str:
    parts: list[bytes] = []

    def add(label: str, data: bytes) -> None:
        parts.append(label.encode("utf-8"))
        parts.append(b"\0")
        parts.append(str(len(data)).encode("ascii"))
        parts.append(b"\0")
        parts.append(data)
        parts.append(b"\n")

    add("tool_version", __version__.encode("utf-8"))
    add("verdict", verdict_status.encode("utf-8"))
    for rel in sorted(staged):
        add(rel, staged[rel])
    return sha256_bytes(b"".join(parts))


def pack_case(case: Path, output: str | Path | None = None) -> dict[str, Any]:
    try:
        return _pack_case_inner(case, output)
    except WorkspaceError:
        raise
    except OSError as exc:
        raise WorkspaceError(f"could not write the evidence pack: {exc}") from exc


def _pack_case_inner(case: Path, output: str | Path | None = None) -> dict[str, Any]:
    verdict = validate_gate(case)
    # Validate the zip name before writing anything, then snapshot evidence
    # bytes once so the digest check and the zip member are the same buffer.
    dest = Path(output).expanduser().resolve() if output else (case / "pack").resolve()
    safe_id = sanitize_case_id_for_filename(verdict.case_id or "case")
    if safe_id in {".", ".."} or not safe_id:
        safe_id = "case"
    zip_name = f"gaingate-pack-{safe_id}.zip"
    if Path(zip_name).name != zip_name:
        zip_name = "gaingate-pack-case.zip"
    zip_path = (dest / zip_name).resolve()
    dest_resolved = dest
    dest_resolved.mkdir(parents=True, exist_ok=True)
    if zip_path.parent != dest_resolved:
        raise WorkspaceError("pack refused: zip path would be written outside --output")

    evidence_buffers = _read_executed_evidence_buffers(
        case, verdict.hops, require_digest_match=verdict.passed
    )
    payload = build_pack_payload(case, verdict)
    payload["pin"] = _display_pin(payload.get("pin") or {})
    payload["tool_version"] = __version__
    sanitized_hops = sanitize_hops_for_pack(case, verdict.hops)
    payload["hops"] = sanitized_hops
    hops_yaml_text = _hops_yaml_for_pack(sanitized_hops)
    staged = _stage_case_file_buffers(case, hops_yaml_text, evidence_buffers)
    payload["pack_content_sha256"] = _pack_content_sha256(staged, verdict.status)
    verdict_text = format_verdict(verdict)
    # Never claim evidence is present unless every required EXECUTED hop
    # has a real, non-empty file under evidence/ that will go in the zip.
    missing = _missing_required_evidence(case, verdict)
    if missing:
        if "evidence files present under evidence/" in verdict_text or "evidence paths present" in verdict_text:
            raise WorkspaceError(
                "pack refused: verdict text would claim evidence is present, "
                "but these required evidence files are missing or invalid: "
                + ", ".join(missing)
            )
        # Be explicit in the shareable pack when evidence is absent.
        verdict_text = (
            verdict_text.rstrip()
            + "\nEvidence status: missing or invalid for "
            + ", ".join(missing)
            + " (pack does not claim evidence paths are present).\n"
        )
    markdown = render_markdown(payload, verdict_text)

    md_path = dest / "evidence_pack.md"
    json_path = dest / "evidence_pack.json"
    md_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel, data in staged.items():
                zf.writestr(rel, data)
            zf.write(md_path, arcname="pack/evidence_pack.md")
            zf.write(json_path, arcname="pack/evidence_pack.json")
    except OSError as exc:
        raise WorkspaceError(f"could not write pack zip: {exc}") from exc

    sidecar = dest / "evidence_pack.sha256"
    sidecar.write_text(f"{sha256_file(zip_path)}  {zip_name}\n", encoding="utf-8")

    return {
        "markdown": md_path,
        "json": json_path,
        "zip": zip_path,
        "sha256": sidecar,
        "passed": verdict.passed,
    }


def _missing_required_evidence(case: Path, verdict: Verdict) -> list[str]:
    """Return required hop ids whose evidence is not a packable file."""
    missing: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}
    for hop in verdict.hops:
        if not isinstance(hop, dict):
            continue
        hop_id = str(hop.get("id", "")).strip()
        if hop_id and hop_id not in by_id:
            by_id[hop_id] = hop
    for hop_id in verdict.required_hops:
        hop = by_id.get(hop_id) or {}
        label = str(hop.get("label") or "").strip().upper()
        if label != "EXECUTED":
            continue
        evidence = hop.get("evidence")
        try:
            rel = resolve_executed_evidence(case, str(evidence or ""), hop_id=hop_id)
        except WorkspaceError:
            missing.append(hop_id)
            continue
        if not (case / rel).is_file():
            missing.append(hop_id)
    return missing
