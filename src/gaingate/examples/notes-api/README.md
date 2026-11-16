# Fictional walkthrough: notes-api

**This is a synthetic example. It is not a real project, not a real
vulnerability, and not a real report.** Identifiers such as `SYN-0001`,
the origin `https://git.example.invalid/example-org/notes-api.git`, tag
`v9.9.9`, and the repeated `a` / `b` hashes are placeholders.

The toy service is a two-tenant notes API. An authenticated user in
tenant A is already allowed to read notes that belong to tenant A.

Three case directories are included:

- `pass/` — the reproduction shows a tenant-A user reading a tenant-B
  note. Required hops are all `EXECUTED` with evidence, and every
  named confound is cleared. `gaingate gate validate` should print `PASS`.
- `fail-baseline/` — the reproduction only shows a tenant-A user reading
  a tenant-A note through an alternate URL. That is already in baseline,
  so the gate should print `FAIL`.
- `fail-required-hop/` — the claimed gain would exceed baseline, but one
  hop the claim depends on is labeled `SOURCE_ASSERTED` rather than
  `EXECUTED`. The gate should print `FAIL`.

Try:

```bash
gaingate gate validate --case-dir ./pass
gaingate gate validate --case-dir ./fail-baseline
gaingate gate validate --case-dir ./fail-required-hop
gaingate pack --case-dir ./pass
```
