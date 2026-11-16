# Changelog

## 0.1.3

- `pack` reads each EXECUTED evidence file once, hashes that buffer, compares it to the stored sha256, and writes the same buffer into the zip with `ZipFile.writestr`. A mismatch during a would-be PASS pack is refused. `case_id` is sanitized and the zip path is chosen before any pack files are written.
- Any baseline or gained capability string that still contains a non-ASCII character after NFKC normalization and format-character stripping is flagged `capability_needs_human_review` and does not count as a strict gain.
- `case_id` values of `.` and `..`, and ids longer than 128 characters, are rejected.
- README "Not checked" now also records: any non-empty repository string counts as naming a repository; an old PASS zip still matches its own sidecar after the case is edited (there is no `pack verify`); hop ids that differ only in case can coexist and do not override each other.

## 0.1.2

- `hop add` and `gate validate` reject duplicate hop ids (`duplicate_hop_id`).
- `gaingate pin` stores its own `ls_remote` record (timestamp, origin, result, tag) when it actually runs `git ls-remote`. Packs show "Confirmed via git ls-remote" only when that record is present and consistent; a hand-set `confirmed: true` is ignored.
- `PASS` requires a pin that names a repository (`operator_stated_origin`) and a valid commit SHA. README and the pack footer match this rule.
- `hop add` stores `evidence_sha256` for each `EXECUTED` hop. `gate validate` and `pack` re-hash the file and fail on a missing or mismatched digest.
- Evidence files with `st_nlink > 1` (hard links) are rejected.
- `case_id` must use a safe token (`[A-Za-z0-9._-]+`). The pack zip is always written inside `--output`, which is created if needed, and zip-open errors are reported as tool errors rather than raw tracebacks.
- Capability comparison NFKC-normalizes text, strips Unicode format characters, and treats non-ASCII confusables and near-duplicates (for example a bracketed note) as needing human review; those do not count as a strict gain.
- `pack` exits 1 when the verdict is FAIL (the pack is still written). Each pack embeds the tool version, a timestamp, and a content hash, and writes `evidence_pack.sha256` for the zip.
- Not fixed in this release, and documented under README "Not checked": control characters in evidence filenames and raw YAML tracebacks; two hops sharing one evidence file; whitespace-only evidence files; gain hops omitted from `required_hops`; placeholder or zero-width confound reasons.

## 0.1.1

- `hop add` and `gate validate` require an `EXECUTED` hop's evidence path to resolve, after symlink resolution, to a non-empty file inside `<case>/evidence/`. Absolute paths, `..` traversal, escaping symlinks, missing files, and empty files are rejected. `gate validate` re-checks stored paths rather than trusting them. Accepted paths are stored case-relative.
- `pack` copies those evidence files into the zip, writes only case-relative paths, and will not claim that evidence is present when a required file is missing or invalid.
- README wording now matches what the tool actually checks: existence, non-emptiness, and location of evidence files, not the truth of the claim.

## 0.1.0

- First local MVP: `init`, `pin`, `env`, `hop add`, `gate validate`, `pack`, and `example synth`.
- Ships a fictional `notes-api` walkthrough with one passing case and two failing cases.
- Core is MIT licensed. The tool is offline by default.
