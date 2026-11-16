# GainGate

A local CLI and template kit that pins the exact artifact you tested, structures a clean-room reproduction, and fails any finding whose demonstrated capability does not strictly exceed the attacker's baseline.

*Stop writing reports for impact you did not actually gain.*

GainGate is a discipline tool. It does not find bugs, run the system under test, or decide whether a finding is eligible for anything. It records provenance, checks that evidence files exist, are non-empty, sit inside the case folder, are not hard links, and still match the sha256 stored at `hop add` (it does not verify that those files are truthful), and packs that record into a shareable file set.

## What this is not

v1 stays clear of all of the following:

- It is not a scanner, fuzzer, crawler, or exploit assistant. It does not craft payloads, launch targets, or fill in hops from logs.
- It does not ship a target list, a fingerprint database, or a catalog of known-vulnerable versions.
- It does not talk to disclosure programs, score eligibility, or submit, upload, or message anyone.
- It does not treat a `PASS` verdict as "ready to disclose." `PASS` means only that your stated gain exceeded your stated baseline, on a pin that names a repository and a commit, with every required hop labeled `EXECUTED` and accompanied by a non-empty evidence file inside the case whose stored sha256 still matches. Eligibility and disclosure are a separate, human decision, out of band.
- It does not use the network unless you explicitly pass a repository URL to `gaingate pin` and omit `--offline`. There is no default remote and no built-in upstream.

If you want a tool that discovers vulnerabilities for you, this is the wrong product.

## Install

Python 3.10 or newer. From a checkout:

```bash
python -m pip install -e ".[dev]"
```

No network services are required to run the CLI or the tests.

## Quick start

The shipped walkthrough is fictional. It uses a toy two-tenant service called `notes-api`, case id `SYN-0001`, tag `v9.9.9`, and placeholder hashes. It is not a real project.

```bash
gaingate example synth ./notes-api-demo
gaingate gate validate --case-dir ./notes-api-demo/pass
gaingate gate validate --case-dir ./notes-api-demo/fail-baseline
gaingate pack --case-dir ./notes-api-demo/pass
```

Start a new case of your own:

```bash
gaingate init ./my-case
# edit gate.yaml, then pin the artifact before you reproduce
gaingate pin --offline --case-dir ./my-case \
  --tag v1.2.3 \
  --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --origin https://git.example.invalid/example-org/notes-api.git \
  --artifact-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
gaingate env --case-dir ./my-case
gaingate hop add --case-dir ./my-case \
  --id H1 --description "Set up two isolated tenants" \
  --label EXECUTED --evidence evidence/h1_setup.log
gaingate gate validate --case-dir ./my-case
gaingate pack --case-dir ./my-case
```

## Commands

### `gaingate init <case-dir>`

Creates a case workspace with empty templates: `gate.yaml`, `pin.yaml`, `hops.yaml`, `env.yaml`, `report.md`, and a copy of the generic confound registry. Also creates an `evidence/` directory for files you attach.

### `gaingate pin [--offline]`

Records `release tag → commit SHA`, an operator-stated repository URL, and an optional artifact `sha256`. Recommended default: `--offline`. In that mode you paste the SHA you already verified; the tool only records it and warns that the tag was not confirmed with `git ls-remote`. A `PASS` still requires the pin to name a repository and a commit.

To optionally confirm a tag, pass `--origin` with a repository URL you supply and omit `--offline`. The tool will run `git ls-remote` against that URL only and will store its own record of that call (timestamp, origin, and result). The pack line "Confirmed via git ls-remote" is shown as true only when that record is present and still consistent with the pin; a hand-edited `confirmed: true` is ignored. The tool never ships a default remote, a program catalog, or an "official upstream." If you do not pass a URL, or you use `--offline`, the tool does not talk to the network.

You may also pass `--artifact-file` to hash a local file and store the digest.

### `gaingate env`

Records local facts: kernel, OS, toolchain versions that are present, and LSM / sandbox features if they are visible on the machine. No network. Host names and user names are not recorded.

### `gaingate hop add`

Appends one hop to `hops.yaml`. The label must be one of:

- `EXECUTED` — you ran this step. An evidence path is required. The path must be case-relative, and the file must exist, be non-empty, resolve inside the case's `evidence/` directory, and not be a hard link (`st_nlink` must be 1). Absolute paths, `..` traversal, and symlinks that escape the case are rejected. The tool stores a sha256 of the file; `gate validate` and `pack` re-hash it and fail on a mismatch.
- `SOURCE_ASSERTED` — you inferred the step from source and did not run it.
- `NOT_FEASIBLE` — you did not run it and are saying so. A reason is required.

The tool does not execute the hop, and it does not verify that the evidence file is a truthful record of the step. It only checks that an `EXECUTED` label has a non-empty, non-hard-linked evidence file that sits inside the case folder and still matches the stored sha256. Duplicate hop ids are rejected by `hop add` and cause `gate validate` and `pack` to fail.

### `gaingate gate validate`

Reads `gate.yaml` (and the hop log) and prints `PASS` or `FAIL`. Exit status is zero only on `PASS`. The verdict is `PASS` only when all of the following hold:

1. Every required field is filled, and `case_id` uses only letters, digits, dot, underscore, or hyphen, is not `.` or `..`, and is at most 128 characters.
2. Demonstrated gained capability **strictly exceeds** baseline. Comparison is mechanical after NFKC normalization and stripping of Unicode format characters (including zero-width spaces). The structured `gained` list must contain at least one `(action, resource, constraint)` record that is not in `baseline`, and the free-text statements must not be the same. Any capability string (baseline or gained) that still contains a non-ASCII character after that normalization is flagged `capability_needs_human_review` and does not count as a strict gain. Lookalike detection is best-effort: non-ASCII capabilities are flagged for human review, and ASCII-only lookalikes are not detected. Near-duplicates (for example the same ASCII text plus a bracketed note, or a trailing punctuation-only change) are also flagged and do not count as a strict gain.
3. Every named confound is marked `cleared: true` and has a one-line reason.
4. The claim names at least one required hop, hop ids in the log are unique, and every required hop is labeled `EXECUTED` with a non-empty, non-hard-linked evidence file inside the case's `evidence/` directory whose stored sha256 still matches. `gate validate` re-checks those files and digests and does not trust a previously stored path. A claim that depends on a `SOURCE_ASSERTED` or `NOT_FEASIBLE` hop fails.
5. `pin.yaml` names a repository (`operator_stated_origin`) and a valid commit SHA.

Otherwise the command exits non-zero and prints each failing rule.

### `gaingate pack`

Renders a Markdown and JSON evidence pack from the case files, including the gate verdict, pin record, env facts, and hop log. It reads each EXECUTED evidence file once, hashes that buffer, checks it against the stored sha256, and writes the same buffer into the zip. Other pack paths are case-relative (never absolute or home paths). The zip is always written inside `--output` (which is created if needed), using a sanitized `case_id` in the filename, and that name is chosen before any pack files are written. The pack embeds the tool version, a timestamp, and a content hash, and writes `evidence_pack.sha256` for the zip so a later, stale copy can be identified. If any required evidence is missing or invalid, the pack says so and does not claim that evidence is present. `pack` exits 0 only on a PASS verdict; a FAIL pack is still written, but the process exits 1. It does not invent missing steps. A short footer states that eligibility and disclosure are out of band.

### `gaingate example synth <dest-dir>`

Copies the fictional `notes-api` walkthrough into a new directory so you can inspect a pass and two failures without using any real case.

## Gate file (required fields)

Edit `gate.yaml` in the case directory. Required fields:

- Attacker position — who the actor is, and what they are already allowed to do
- Baseline capability — what that position can already achieve without the claimed defect (free text plus a structured list)
- Gained capability — what the reproduction actually demonstrated, not what the source suggests (free text plus a structured list)
- Control present — the rule, check, or boundary that was supposed to stop the gain
- Control location — the component or layer, named by you (not auto-detected)
- Repro time — when the runs were performed
- Confound list — each entry has `cleared: true|false` and a short reason
- Required hops — the hop ids this claim depends on

The generic confound registry shipped with the templates lists common, non-specific confounds (shared fixture IDs, a cached privileged session, a mislabeled user in setup, and a wrong artifact). Use those, drop any that do not apply, or add your own. Every confound you leave in the list must be cleared with a reason.

## What `PASS` means

`PASS` is not a recommendation to disclose, and it is not a statement about eligibility, severity, or reward. It means only: the operator's own stated gain exceeded their own stated baseline, on a pin that names a repository and a commit, with required hops labeled `EXECUTED` and accompanied by non-empty evidence files inside the case folder whose stored sha256 still matches. The tool does not grade the honesty or truth of those files. "Confirmed via git ls-remote" is not implied by PASS; that line is true only when `pin` stored its own ls-remote record and the record is still consistent.


## Not checked

These limits are known and are not enforced in this release:

- Evidence filenames that contain control characters or newlines are not rejected, and a malformed YAML file may print a traceback instead of a short error.
- Two required `EXECUTED` hops may share one evidence file (the same path, or a symlink that stays inside `evidence/`).
- A file whose size is greater than zero counts as non-empty, including a file that contains only whitespace.
- Required hops are only the ids listed in `gate.yaml`; the tool does not require every hop mentioned in the claim narrative to be on that list.
- Confound reasons are checked for ordinary non-emptiness only; placeholder or zero-width-only reasons are not rejected, and an empty confound list is allowed.
- Any non-empty `operator_stated_origin` string counts as naming a repository.
- An old PASS zip still matches its own sidecar after the case is later edited, because there is no `pack verify`. Re-run `gate validate` (or `pack`) on the current case instead.
- Hop ids that differ only in case (for example `h2` and `H2`) can coexist; they do not override each other and are not treated as duplicates.
- Case files are plain YAML and are not signed. Someone who hand-writes a complete, internally consistent `ls_remote` record in `pin.yaml` can make the pack show "Confirmed via git ls-remote: True" without that call having happened. The tool checks consistency, not authenticity. The same applies to any case file: GainGate checks the operator's own files and does not defend against an operator who deliberately forges them.

## License

MIT. See `LICENSE`.

GainGate is Ra1nzZ's project; the code and docs were written with AI assistance and reviewed before release.

**Optional template pack.** GainGate itself is free and MIT-licensed, and everything described above works without paying anything. If you want ready-made starting points, an optional template pack is available for US$9 (paid in crypto) at https://gaingate-by-ra1nzz.bytesell.app/products/gaingate-template-pack-1-0. It contains six case templates, two fictional worked examples (one PASS, one honest FAIL) and a guide to writing a differential-impact claim; the full file list is below, copied from the pack's own CONTENTS.md. Everything in it is also something you could write yourself from this README. The pack adds templates only: it does not change what the CLI checks, does not make evidence tamper-proof, and does not improve lookalike detection beyond what's described above. If the pack doesn't match this description, email samedaykits@gmail.com and you'll get a full refund. This doesn't limit any rights you have under your local consumer law.

### Pack contents

#### GainGate Template Pack 1.0

This pack is a set of case templates and fictional worked examples for use with GainGate v0.1.3. It is written to save setup time. It does not add checks to the tool and it does not change what PASS means.

PASS means only that the operator's own stated gain exceeded their own stated baseline, on a pin that names a repository and a commit, with required hops labeled EXECUTED and accompanied by non-empty evidence files inside the case folder whose stored sha256 still matches. PASS is not a recommendation to disclose, and it is not a statement about eligibility, severity, or reward.

Lookalike detection in GainGate v0.1.3 is best-effort: non-ASCII capabilities are flagged for human review, and ASCII-only lookalikes are not detected. Case files are not signed. This pack does not claim tamper-proofing. There is no pack verify. Every target in this pack is fictional: repository URLs use .invalid hosts, and commit and artifact values use the placeholder SHAs aaaa… and bbbb… only.

The archive unpacks into the folder gaingate-template-pack-1.0/. Paths below are relative to that folder.

##### Files

- `CONTENTS.md` — This file list, with a one-line purpose for each file.
- `LICENSE.md` — Terms of use for this pack: a buyer may use, copy and modify the templates for their own security reports, including paid client work; they may not resell or redistribute the pack, or substantial parts of it, as templates. The GainGate CLI is separately MIT-licensed. There is no warranty. Refund terms are included.
- `NOTICE.md` — States that every example is fictional, that the pack adds no GainGate checks, and that claims stay within the v0.1.3 README.
- `guides/writing-a-differential-impact-claim.md` — A short guide to stating baseline versus gained capability, confounds, hops, and pins so the existing v0.1.3 checks can run.
- `templates/authz-access-boundary/gate.yaml` — Skeleton gate for an access-boundary (authz / IDOR-style) claim, with example baseline and gained fields.
- `templates/authz-access-boundary/hops.yaml` — Skeleton hop log for the access-boundary template; hops start as SOURCE_ASSERTED until the operator attaches evidence.
- `templates/authz-access-boundary/pin.yaml` — Placeholder pin for the access-boundary template, using a .invalid origin and the placeholder SHAs aaaa… and bbbb….
- `templates/authz-access-boundary/NOTES.md` — Baseline-versus-gained notes, confound checklist, and what counts as evidence for an access-boundary claim.
- `templates/authz-access-boundary/evidence/README.md` — Tells the operator to place non-empty, case-relative evidence files in this folder.
- `templates/path-traversal/gate.yaml` — Skeleton gate for a path-traversal claim, with example baseline and gained fields.
- `templates/path-traversal/hops.yaml` — Skeleton hop log for the path-traversal template; hops start as SOURCE_ASSERTED until the operator attaches evidence.
- `templates/path-traversal/pin.yaml` — Placeholder pin for the path-traversal template, using a .invalid origin and the placeholder SHAs aaaa… and bbbb….
- `templates/path-traversal/NOTES.md` — Baseline-versus-gained notes, confound checklist, and what counts as evidence for a path-traversal claim.
- `templates/path-traversal/evidence/README.md` — Tells the operator to place non-empty, case-relative evidence files in this folder.
- `templates/ssrf-internal-service/gate.yaml` — Skeleton gate for an SSRF-to-internal-service claim, with example baseline and gained fields.
- `templates/ssrf-internal-service/hops.yaml` — Skeleton hop log for the SSRF template; hops start as SOURCE_ASSERTED until the operator attaches evidence.
- `templates/ssrf-internal-service/pin.yaml` — Placeholder pin for the SSRF template, using a .invalid origin and the placeholder SHAs aaaa… and bbbb….
- `templates/ssrf-internal-service/NOTES.md` — Baseline-versus-gained notes, confound checklist, and what counts as evidence for an SSRF-to-internal-service claim.
- `templates/ssrf-internal-service/evidence/README.md` — Tells the operator to place non-empty, case-relative evidence files in this folder.
- `templates/deserialization/gate.yaml` — Skeleton gate for a deserialization claim, with example baseline and gained fields.
- `templates/deserialization/hops.yaml` — Skeleton hop log for the deserialization template; hops start as SOURCE_ASSERTED until the operator attaches evidence.
- `templates/deserialization/pin.yaml` — Placeholder pin for the deserialization template, using a .invalid origin and the placeholder SHAs aaaa… and bbbb….
- `templates/deserialization/NOTES.md` — Baseline-versus-gained notes, confound checklist, and what counts as evidence for a deserialization claim.
- `templates/deserialization/evidence/README.md` — Tells the operator to place non-empty, case-relative evidence files in this folder.
- `templates/supply-chain-package-integrity/gate.yaml` — Skeleton gate for a supply-chain / package-integrity claim, with example baseline and gained fields.
- `templates/supply-chain-package-integrity/hops.yaml` — Skeleton hop log for the supply-chain template; hops start as SOURCE_ASSERTED until the operator attaches evidence.
- `templates/supply-chain-package-integrity/pin.yaml` — Placeholder pin for the supply-chain template, using a .invalid origin and the placeholder SHAs aaaa… and bbbb….
- `templates/supply-chain-package-integrity/NOTES.md` — Baseline-versus-gained notes, confound checklist, and what counts as evidence for a package-integrity claim.
- `templates/supply-chain-package-integrity/evidence/README.md` — Tells the operator to place non-empty, case-relative evidence files in this folder.
- `templates/injection/gate.yaml` — Skeleton gate for an injection claim, with example baseline and gained fields.
- `templates/injection/hops.yaml` — Skeleton hop log for the injection template; hops start as SOURCE_ASSERTED until the operator attaches evidence.
- `templates/injection/pin.yaml` — Placeholder pin for the injection template, using a .invalid origin and the placeholder SHAs aaaa… and bbbb….
- `templates/injection/NOTES.md` — Baseline-versus-gained notes, confound checklist, and what counts as evidence for an injection claim.
- `templates/injection/evidence/README.md` — Tells the operator to place non-empty, case-relative evidence files in this folder.
- `examples/quiltboard-pass/gate.yaml` — Gate file for the fictional QuiltBoard PASS example, in which a workspace-alpha user reads a workspace-beta card.
- `examples/quiltboard-pass/pin.yaml` — Offline pin for the QuiltBoard PASS example, using git.example.invalid and the placeholder SHAs aaaa… and bbbb….
- `examples/quiltboard-pass/hops.yaml` — Executed hop log for the QuiltBoard PASS example, with sha256 digests of the evidence files in this folder.
- `examples/quiltboard-pass/env.yaml` — Fictional local environment record for the QuiltBoard PASS example; no host names or user names.
- `examples/quiltboard-pass/report.md` — Short operator narrative for the QuiltBoard PASS example, marked as fictional.
- `examples/quiltboard-pass/evidence/h1_setup.log` — Fictional setup log that records two isolated QuiltBoard workspaces and one card in each.
- `examples/quiltboard-pass/evidence/h2_cross_workspace_read.log` — Fictional request log in which the workspace-alpha user retrieves a workspace-beta card.
- `examples/quiltboard-pass/evidence/h3_content_compare.log` — Fictional comparison log showing the response body matches the workspace-beta card from setup.
- `examples/quiltboard-fail-baseline/gate.yaml` — Gate file for the fictional QuiltBoard honest-FAIL example, in which the actor only reads their own card through an alternate URL.
- `examples/quiltboard-fail-baseline/pin.yaml` — Offline pin for the QuiltBoard honest-FAIL example, using git.example.invalid and the placeholder SHAs aaaa… and bbbb….
- `examples/quiltboard-fail-baseline/hops.yaml` — Executed hop log for the QuiltBoard honest-FAIL example, with sha256 digests of the evidence files in this folder.
- `examples/quiltboard-fail-baseline/env.yaml` — Fictional local environment record for the QuiltBoard honest-FAIL example; no host names or user names.
- `examples/quiltboard-fail-baseline/report.md` — Short operator narrative for the QuiltBoard honest-FAIL example, marked as fictional.
- `examples/quiltboard-fail-baseline/evidence/h1_setup.log` — Fictional setup log that records workspace-alpha and one card in it.
- `examples/quiltboard-fail-baseline/evidence/h2_alternate_url_own_card.log` — Fictional request log in which the workspace-alpha user retrieves their own card through an alternate URL.
