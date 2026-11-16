"""Record release tag, commit SHA, and optional artifact digest."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import re
import subprocess
from pathlib import Path
from typing import Any

from gaingate.workspace import WorkspaceError, dump_yaml, load_yaml

COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ARTIFACT_SHA_RE = re.compile(r"^[0-9a-f]{64}$")

OFFLINE_WARNING = (
    "Tag and SHA were recorded from operator input and were not confirmed "
    "with git ls-remote."
)


def derive_ls_remote_confirmation(pin: dict[str, Any]) -> bool:
    """True only when pin recorded its own ls-remote result and it is consistent.

    A hand-edited ``confirmed: true`` is ignored.
    """
    if not isinstance(pin, dict):
        return False
    if (pin.get("pin_method") or "").strip() != "git_ls_remote_user_url":
        return False
    rec = pin.get("ls_remote")
    if not isinstance(rec, dict):
        return False
    recorded_at = str(rec.get("recorded_at") or "").strip()
    origin = str(rec.get("origin") or "").strip()
    result = str(rec.get("result") or "").strip().lower()
    tag = str(rec.get("tag") or "").strip()
    if not recorded_at or not origin or not tag:
        return False
    if not COMMIT_SHA_RE.fullmatch(result):
        return False
    if origin != str(pin.get("operator_stated_origin") or "").strip():
        return False
    if result != str(pin.get("commit_sha") or "").strip().lower():
        return False
    if tag != str(pin.get("release_tag") or "").strip():
        return False
    return True


def _normalize_sha(value: str, kind: str) -> str:
    sha = value.strip().lower()
    if kind == "commit" and not COMMIT_SHA_RE.fullmatch(sha):
        raise WorkspaceError(
            "commit SHA must be a 40-character lowercase hex string"
        )
    if kind == "artifact" and not ARTIFACT_SHA_RE.fullmatch(sha):
        raise WorkspaceError(
            "artifact sha256 must be a 64-character lowercase hex string"
        )
    return sha


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_ls_remote(origin: str, tag: str, timeout: int = 30) -> str:
    """Confirm a tag SHA against an operator-supplied URL only.

    Never call this with a hardcoded or default remote.
    """
    if not origin or not origin.strip():
        raise WorkspaceError("an operator-supplied --origin URL is required for git ls-remote")
    if not tag or not tag.strip():
        raise WorkspaceError("a release tag is required for git ls-remote")

    # Prefer the peeled commit SHA when the tag is annotated.
    refs = [f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"]
    result = subprocess.run(
        ["git", "ls-remote", origin.strip(), *refs],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip() or "git ls-remote failed"
        raise WorkspaceError(f"git ls-remote failed against the supplied origin: {err}")

    peeled = None
    unpeeled = None
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        sha, ref = parts[0].lower(), parts[1]
        if not COMMIT_SHA_RE.fullmatch(sha):
            continue
        if ref.endswith("^{}"):
            peeled = sha
        else:
            unpeeled = sha
    sha = peeled or unpeeled
    if not sha:
        raise WorkspaceError(
            f"git ls-remote did not return a SHA for tag {tag!r} at the supplied origin"
        )
    return sha


def record_pin(
    case: Path,
    *,
    tag: str,
    sha: str | None,
    origin: str | None,
    offline: bool,
    artifact_sha256: str | None = None,
    artifact_file: str | None = None,
    case_id: str | None = None,
    subject: str | None = None,
) -> dict[str, Any]:
    if not tag or not tag.strip():
        raise WorkspaceError("a release tag is required (--tag)")

    existing = load_yaml(case / "pin.yaml")
    warnings: list[str] = []
    origin_value = (origin or existing.get("operator_stated_origin") or "").strip()

    if artifact_file:
        path = Path(artifact_file).expanduser()
        if not path.is_file():
            raise WorkspaceError(f"artifact file not found: {path}")
        computed = hash_file(path)
        if artifact_sha256:
            supplied = _normalize_sha(artifact_sha256, "artifact")
            if supplied != computed:
                raise WorkspaceError(
                    "supplied --artifact-sha256 does not match the hash of --artifact-file"
                )
        artifact_sha256 = computed
    elif artifact_sha256:
        artifact_sha256 = _normalize_sha(artifact_sha256, "artifact")
    else:
        artifact_sha256 = (existing.get("artifact_sha256") or "") or ""

    ls_remote = None
    if offline or not origin:
        if not offline and not origin:
            # No URL and not explicitly offline: still do not touch the network.
            warnings.append(
                "No --origin was supplied, so git ls-remote was not used. "
                "Pass --offline to record this choice explicitly, or pass "
                "--origin with a repository URL you supply."
            )
        if not sha:
            raise WorkspaceError(
                "in offline mode you must pass --sha with the commit you already verified"
            )
        commit_sha = _normalize_sha(sha, "commit")
        pin_method = "offline_operator_supplied"
        confirmed = False
        warnings.append(OFFLINE_WARNING)
        if origin_value and not origin:
            # Keep a previously stored origin as operator-stated, unused for network.
            pass
        elif origin and offline:
            # Operator stated an origin but asked to stay offline: record, do not fetch.
            origin_value = origin.strip()
    else:
        # Online confirmation path: only against the operator-supplied URL.
        remote_sha = run_ls_remote(origin, tag.strip())
        if sha:
            commit_sha = _normalize_sha(sha, "commit")
            if commit_sha != remote_sha:
                raise WorkspaceError(
                    "operator-supplied SHA does not match git ls-remote for this tag "
                    f"({commit_sha} != {remote_sha})"
                )
        else:
            commit_sha = remote_sha
        pin_method = "git_ls_remote_user_url"
        confirmed = True
        origin_value = origin.strip()
        ls_remote = {
            "recorded_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "origin": origin_value,
            "result": remote_sha,
            "tag": tag.strip(),
        }

    record = {
        "case_id": case_id if case_id is not None else existing.get("case_id") or "",
        "subject": subject if subject is not None else existing.get("subject") or "",
        "operator_stated_origin": origin_value,
        "release_tag": tag.strip(),
        "commit_sha": commit_sha,
        "artifact_sha256": artifact_sha256 or "",
        "pin_method": pin_method,
        "confirmed": confirmed,
        "warnings": warnings,
    }
    if ls_remote:
        record["ls_remote"] = ls_remote
    header = (
        "# Provenance pin recorded by `gaingate pin`.\n"
        "# The tool never ships a default remote."
    )
    dump_yaml(case / "pin.yaml", record, header=header)
    return record
