"""Validate a finding against the differential-impact gate."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gaingate.pincmd import COMMIT_SHA_RE
from gaingate.workspace import (
    WorkspaceError,
    case_id_is_safe,
    load_hops,
    load_yaml,
    resolve_executed_evidence,
    sha256_file,
)

REQUIRED_TEXT_FIELDS = (
    ("case_id", "case_id"),
    ("subject", "subject"),
    ("attacker_position", "attacker_position"),
    ("baseline_capability", "baseline_capability"),
    ("gained_capability", "gained_capability"),
    ("control_present", "control_present"),
    ("control_location", "control_location"),
    ("repro_time", "repro_time"),
)

# Common Latin lookalikes (Cyrillic, Greek) used after lowercasing.
_CONFUSABLE_TO_LATIN = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "һ": "h",
        "ԁ": "d",
        "ɡ": "g",
        "ԛ": "q",
        "ԝ": "w",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "ο": "o",
        "υ": "u",
        "ν": "v",
        "η": "n",
        "τ": "t",
        "ρ": "p",
        "χ": "x",
        "κ": "k",
        "μ": "u",
        "σ": "o",
    }
)
_BRACKET_NOTE = re.compile(r"[\(\[\{].*?[\)\]\}]")
_PUNCT = re.compile(r"[^\w\s]", re.UNICODE)


@dataclass
class Finding:
    rule: str
    detail: str


@dataclass
class Verdict:
    passed: bool
    findings: list[Finding] = field(default_factory=list)
    case_id: str = ""
    synthetic: bool = False
    attacker_position: str = ""
    baseline_capability: str = ""
    gained_capability: str = ""
    control_present: str = ""
    control_location: str = ""
    confounds: list[dict[str, Any]] = field(default_factory=list)
    required_hops: list[str] = field(default_factory=list)
    hops: list[dict[str, Any]] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.passed else "FAIL"


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _strip_format(text: str) -> str:
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def _norm(value: Any) -> str:
    text = "" if value is None else str(value)
    text = unicodedata.normalize("NFKC", text)
    text = _strip_format(text)
    return " ".join(text.lower().split())


def _has_non_ascii(text: str) -> bool:
    return any(ord(c) > 127 for c in text)


def _fold_confusables(text: str) -> str:
    return text.translate(_CONFUSABLE_TO_LATIN)


def _core_text(text: str) -> str:
    folded = _fold_confusables(text)
    stripped = _BRACKET_NOTE.sub(" ", folded)
    stripped = _PUNCT.sub(" ", stripped)
    return " ".join(stripped.split())


def _is_near_duplicate(left: str, right: str) -> bool:
    if left == right:
        return False
    core_left, core_right = _core_text(left), _core_text(right)
    return bool(core_left and core_right and core_left == core_right)


def _not_strict_gain(
    gained: tuple[str, str, str], baseline: tuple[str, str, str]
) -> str | None:
    if gained == baseline:
        return "equal"
    gained_fold = tuple(_fold_confusables(part) for part in gained)
    baseline_fold = tuple(_fold_confusables(part) for part in baseline)
    if gained_fold == baseline_fold:
        return "unicode_confusable"
    if all(
        g == b or _is_near_duplicate(g, b) for g, b in zip(gained_fold, baseline_fold)
    ):
        return "near_duplicate"
    return None


def _cap_key(item: Any) -> tuple[str, str, str] | None:
    if not isinstance(item, dict):
        return None
    action = _norm(item.get("action"))
    resource = _norm(item.get("resource"))
    constraint = _norm(item.get("constraint"))
    if not action or not resource:
        return None
    return (action, resource, constraint)


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1"):
            return True
        if lowered in ("false", "no", "0"):
            return False
    return None


def _check_pin(case: Path, fail) -> None:
    pin_path = case / "pin.yaml"
    if not pin_path.is_file():
        fail("pin_missing", "PASS requires a pin that names a repository and a commit SHA")
        return
    try:
        pin = load_yaml(pin_path)
    except WorkspaceError as exc:
        fail("pin_missing", f"pin.yaml could not be read: {exc}")
        return
    origin = _text(pin.get("operator_stated_origin"))
    commit = _text(pin.get("commit_sha")).lower()
    if not origin and not COMMIT_SHA_RE.fullmatch(commit):
        fail(
            "pin_missing",
            "pin.yaml does not name a repository or a valid commit SHA",
        )
        return
    if not origin:
        fail(
            "pin_incomplete",
            "pin.yaml has no operator_stated_origin (repository)",
        )
    if not COMMIT_SHA_RE.fullmatch(commit):
        fail(
            "pin_incomplete",
            "pin.yaml has no valid 40-character commit SHA",
        )


def _record_evidence_check(
    case: Path,
    hop: dict[str, Any],
    *,
    required: bool,
    fail,
) -> None:
    """Re-check an EXECUTED hop's evidence path and stored sha256."""
    hop_id = _text(hop.get("id")) or "(unnamed)"
    evidence = _text(hop.get("evidence"))
    if not evidence:
        rule = (
            "required_hop_evidence_missing"
            if required
            else "executed_hop_evidence_invalid"
        )
        fail(rule, f"hop {hop_id} is EXECUTED but has no evidence path")
        return
    try:
        rel = resolve_executed_evidence(case, evidence)
    except WorkspaceError as exc:
        message = str(exc)
        if required and "not found" in message:
            fail(
                "required_hop_evidence_missing",
                f"required hop {hop_id}: evidence file not found: {evidence}",
            )
        elif required:
            fail("required_hop_evidence_invalid", f"required hop {hop_id}: {message}")
        else:
            fail("executed_hop_evidence_invalid", message)
        return

    stored = _text(hop.get("evidence_sha256")).lower()
    if not stored:
        rule = (
            "required_hop_evidence_digest_missing"
            if required
            else "executed_hop_evidence_digest_missing"
        )
        fail(rule, f"hop {hop_id} is EXECUTED but has no evidence_sha256")
        return
    actual = sha256_file((case / rel).resolve())
    if stored != actual:
        rule = (
            "required_hop_evidence_digest_mismatch"
            if required
            else "executed_hop_evidence_digest_mismatch"
        )
        fail(
            rule,
            f"hop {hop_id}: evidence sha256 does not match the file on disk",
        )


def validate_gate(case: Path) -> Verdict:
    gate = load_yaml(case / "gate.yaml")
    hops = load_hops(case / "hops.yaml") if (case / "hops.yaml").is_file() else []

    case_id = _text(gate.get("case_id"))
    synthetic = bool(gate.get("synthetic")) or case_id.upper().startswith("SYN-")
    required_hops = gate.get("required_hops") or []
    if not isinstance(required_hops, list):
        required_hops = []
    required_ids = [_text(x) for x in required_hops if _text(x)]
    confounds = gate.get("confounds") or []
    if not isinstance(confounds, list):
        confounds = []

    verdict = Verdict(
        passed=True,
        case_id=case_id,
        synthetic=synthetic,
        attacker_position=_text(gate.get("attacker_position")),
        baseline_capability=_text(gate.get("baseline_capability")),
        gained_capability=_text(gate.get("gained_capability")),
        control_present=_text(gate.get("control_present")),
        control_location=_text(gate.get("control_location")),
        confounds=confounds,
        required_hops=required_ids,
        hops=hops,
    )

    def fail(rule: str, detail: str) -> None:
        verdict.passed = False
        verdict.findings.append(Finding(rule=rule, detail=detail))

    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    for hop in hops:
        hop_id = _text(hop.get("id"))
        if not hop_id:
            continue
        if hop_id in seen_ids and hop_id not in duplicate_ids:
            duplicate_ids.append(hop_id)
        seen_ids.add(hop_id)
    if duplicate_ids:
        fail(
            "duplicate_hop_id",
            "hops.yaml contains duplicate hop id(s): " + ", ".join(duplicate_ids),
        )

    # First occurrence wins so a later dummy EXECUTED row cannot shadow
    # an earlier label once we have already recorded the duplicate.
    hops_by_id: dict[str, dict[str, Any]] = {}
    for hop in hops:
        hop_id = _text(hop.get("id"))
        if hop_id and hop_id not in hops_by_id:
            hops_by_id[hop_id] = hop

    if case_id and not case_id_is_safe(case_id):
        fail(
            "case_id_invalid",
            "case_id must use only letters, digits, dot, underscore, or hyphen, "
            "must not be '.' or '..', and must be at most 128 characters",
        )

    _check_pin(case, fail)

    for key, label in REQUIRED_TEXT_FIELDS:
        if not _text(gate.get(key)):
            fail("required_field_missing", f"required field {label} is empty")

    baseline_items = gate.get("baseline") or []
    gained_items = gate.get("gained") or []
    if not isinstance(baseline_items, list) or not baseline_items:
        fail("required_field_missing", "structured baseline list is empty")
        baseline_keys: set[tuple[str, str, str]] = set()
    else:
        baseline_keys = set()
        for item in baseline_items:
            key = _cap_key(item)
            if key is None:
                fail(
                    "required_field_missing",
                    "each baseline entry needs action and resource",
                )
            else:
                baseline_keys.add(key)

    if not isinstance(gained_items, list) or not gained_items:
        fail("required_field_missing", "structured gained list is empty")
        gained_keys: set[tuple[str, str, str]] = set()
    else:
        gained_keys = set()
        for item in gained_items:
            key = _cap_key(item)
            if key is None:
                fail(
                    "required_field_missing",
                    "each gained entry needs action and resource",
                )
            else:
                gained_keys.add(key)

    non_ascii_caps = [
        key
        for key in list(baseline_keys) + list(gained_keys)
        if any(_has_non_ascii(part) for part in key)
    ]
    if non_ascii_caps:
        fail(
            "capability_needs_human_review",
            "a baseline or gained capability string contains a non-ASCII "
            "character after normalization and does not count as a strict gain",
        )

    genuine_new: set[tuple[str, str, str]] = set()
    for gained_key in gained_keys - baseline_keys:
        if any(_has_non_ascii(part) for part in gained_key):
            continue
        review = None
        for baseline_key in baseline_keys:
            kind = _not_strict_gain(gained_key, baseline_key)
            if kind in ("unicode_confusable", "near_duplicate"):
                review = kind
                break
        if review:
            fail(
                "capability_needs_human_review",
                "gained capability "
                f"{gained_key} is a {review} of a baseline capability "
                "and does not count as a strict gain",
            )
        else:
            genuine_new.add(gained_key)

    baseline_text = _norm(gate.get("baseline_capability"))
    gained_text = _norm(gate.get("gained_capability"))
    if _has_non_ascii(baseline_text) or _has_non_ascii(gained_text):
        fail(
            "capability_needs_human_review",
            "a baseline or gained capability string contains a non-ASCII "
            "character after normalization and does not count as a strict gain",
        )
        # Non-ASCII free text cannot satisfy the strict-gain text check.
        texts_differ = False
        text_review = None
    else:
        text_review = None
        if baseline_text and gained_text:
            if baseline_text == gained_text:
                texts_differ = False
            elif _fold_confusables(baseline_text) == _fold_confusables(gained_text):
                texts_differ = False
                text_review = "unicode_confusable"
            elif _is_near_duplicate(baseline_text, gained_text):
                texts_differ = False
                text_review = "near_duplicate"
            else:
                texts_differ = True
        else:
            texts_differ = False
    if text_review:
        fail(
            "capability_needs_human_review",
            f"free-text gained_capability is a {text_review} of baseline_capability "
            "and does not count as a strict gain",
        )
    if not genuine_new or not texts_differ:
        if not genuine_new:
            reason = (
                "the structured gained list does not contain any capability "
                "beyond baseline; no new capability was shown."
            )
        else:
            reason = "baseline_capability and gained_capability text are the same."
        fail("gained_capability_must_strictly_exceed_baseline", reason)

    if not isinstance(confounds, list):
        fail("required_field_missing", "confounds must be a list")
    else:
        for item in confounds:
            if not isinstance(item, dict):
                fail("required_field_missing", "each confound must be a mapping")
                continue
            name = _text(item.get("name")) or "(unnamed confound)"
            cleared = _as_bool(item.get("cleared"))
            reason = _text(item.get("reason"))
            if cleared is not True:
                fail(
                    "confound_not_cleared",
                    f"confound {name!r} is not marked cleared",
                )
            if not reason:
                fail(
                    "confound_missing_reason",
                    f"confound {name!r} has no one-line reason",
                )

    if not required_ids:
        fail(
            "claim_must_name_required_hops",
            "the claim must name at least one required hop that this gain depends on",
        )
    for hop_id in required_ids:
        hop = hops_by_id.get(hop_id)
        if hop is None:
            fail("required_hop_missing", f"required hop {hop_id} is not in hops.yaml")
            continue
        label = _text(hop.get("label")).upper()
        if label != "EXECUTED":
            fail(
                "required_hop_not_executed",
                f"required hop {hop_id} is labeled {label or 'unlabeled'}; "
                "a hop the claim depends on may not be SOURCE_ASSERTED or NOT_FEASIBLE",
            )
            continue
        evidence = _text(hop.get("evidence"))
        if not evidence:
            fail(
                "required_hop_evidence_missing",
                f"required hop {hop_id} is EXECUTED but has no evidence path",
            )
            continue
        _record_evidence_check(case, hop, required=True, fail=fail)

    # Re-check every EXECUTED hop, including ones the claim does not
    # depend on, so a stored path is never trusted at face value.
    required_set = set(required_ids)
    for hop in hops:
        hop_id = _text(hop.get("id"))
        if hop_id in required_set:
            continue
        if _text(hop.get("label")).upper() != "EXECUTED":
            continue
        _record_evidence_check(case, hop, required=False, fail=fail)

    return verdict


def format_verdict(verdict: Verdict) -> str:
    case = verdict.case_id or "(missing case_id)"
    if verdict.synthetic:
        case = f"{case} (synthetic)"
    lines = [f"GainGate verdict: {verdict.status}", f"Case: {case}"]
    if not verdict.passed:
        # Print every failing rule so the operator can fix them in one pass.
        for finding in verdict.findings:
            lines.append(f"Rule broken: {finding.rule}")
            lines.append(f"Reason: {finding.detail}")
    lines.append(f"Attacker position: {verdict.attacker_position or '(empty)'}")
    lines.append(f"Baseline capability : {verdict.baseline_capability or '(empty)'}")
    lines.append(f"Gained capability   : {verdict.gained_capability or '(empty)'}")
    lines.append(f"Control present     : {verdict.control_present or '(empty)'}")
    if verdict.control_location:
        lines.append(
            f"Control location    : operator-named layer "
            f"{verdict.control_location!r} (not auto-detected)"
        )
    if verdict.confounds:
        lines.append("Confounds:")
        for item in verdict.confounds:
            if not isinstance(item, dict):
                continue
            name = _text(item.get("name")) or "(unnamed)"
            cleared = _as_bool(item.get("cleared"))
            reason = _text(item.get("reason"))
            flag = "cleared" if cleared else "not cleared"
            suffix = f" {reason}" if reason else ""
            lines.append(f"  - {name}: {flag}:{suffix}")
    if verdict.required_hops:
        hop_bits = []
        by_id: dict[str, dict[str, Any]] = {}
        for hop in verdict.hops:
            if not isinstance(hop, dict):
                continue
            hop_id = str(hop.get("id", "")).strip()
            if hop_id and hop_id not in by_id:
                by_id[hop_id] = hop
        all_executed = True
        for hop_id in verdict.required_hops:
            hop = by_id.get(hop_id) or {}
            label = _text(hop.get("label")).upper() or "MISSING"
            if label != "EXECUTED":
                all_executed = False
            hop_bits.append(f"{hop_id} ({label})")
        joined = ", ".join(verdict.required_hops)
        if verdict.passed and all_executed:
            lines.append(
                f"Hops required by this claim: {joined} — all EXECUTED, non-empty evidence files present under evidence/"
            )
        else:
            lines.append("Hops required by this claim: " + ", ".join(hop_bits))
    return "\n".join(lines) + "\n"


def validate_or_raise(case: Path) -> Verdict:
    if not (case / "gate.yaml").is_file():
        raise WorkspaceError(f"missing gate.yaml in {case}")
    return validate_gate(case)
