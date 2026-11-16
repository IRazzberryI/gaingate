"""Command-line entry point for GainGate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gaingate import __version__
from gaingate.envcmd import record_env
from gaingate.examplecmd import synth_example
from gaingate.gatecmd import format_verdict, validate_gate
from gaingate.hopcmd import VALID_LABELS, add_hop
from gaingate.initcmd import init_case
from gaingate.packcmd import pack_case
from gaingate.pincmd import record_pin
from gaingate.workspace import WorkspaceError, case_dir


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gaingate",
        description=(
            "Pin the artifact you tested, structure a clean-room reproduction, "
            "and fail any finding whose demonstrated capability does not "
            "strictly exceed the attacker's baseline."
        ),
    )
    parser.add_argument("--version", action="version", version=f"gaingate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create a case workspace from empty templates")
    p_init.add_argument("case_dir", help="directory to create")

    p_pin = sub.add_parser(
        "pin",
        help="record release tag, commit SHA, and optional artifact digest",
    )
    p_pin.add_argument(
        "--offline",
        action="store_true",
        help="record operator-supplied SHA only; do not talk to the network (recommended)",
    )
    p_pin.add_argument("--tag", required=True, help="release tag that you tested")
    p_pin.add_argument("--sha", help="commit SHA (required with --offline)")
    p_pin.add_argument(
        "--origin",
        help="operator-supplied repository URL; used only if --offline is not set",
    )
    p_pin.add_argument("--artifact-sha256", dest="artifact_sha256", help="artifact digest")
    p_pin.add_argument(
        "--artifact-file",
        dest="artifact_file",
        help="local file whose sha256 should be recorded",
    )
    p_pin.add_argument("--case-id", dest="case_id", help="override case id in pin.yaml")
    p_pin.add_argument("--subject", help="override subject in pin.yaml")
    p_pin.add_argument("--case-dir", dest="case_dir", default=".", help="case workspace")

    p_env = sub.add_parser("env", help="record local OS, kernel, and toolchain facts")
    p_env.add_argument("--case-dir", dest="case_dir", default=".", help="case workspace")

    p_hop = sub.add_parser("hop", help="reproduction hop log")
    hop_sub = p_hop.add_subparsers(dest="hop_command", required=True)
    p_hop_add = hop_sub.add_parser("add", help="append one hop")
    p_hop_add.add_argument("--id", dest="hop_id", required=True, help="hop id, for example H1")
    p_hop_add.add_argument("--description", required=True, help="short description of the step")
    p_hop_add.add_argument(
        "--label",
        required=True,
        choices=VALID_LABELS,
        help="EXECUTED, SOURCE_ASSERTED, or NOT_FEASIBLE",
    )
    p_hop_add.add_argument("--evidence", help="path to a local evidence file (required for EXECUTED)")
    p_hop_add.add_argument("--reason", help="required for SOURCE_ASSERTED and NOT_FEASIBLE")
    p_hop_add.add_argument("--case-dir", dest="case_dir", default=".", help="case workspace")

    p_gate = sub.add_parser("gate", help="differential-impact gate")
    gate_sub = p_gate.add_subparsers(dest="gate_command", required=True)
    p_gate_val = gate_sub.add_parser("validate", help="grade the finding; exit 0 only on PASS")
    p_gate_val.add_argument("--case-dir", dest="case_dir", default=".", help="case workspace")

    p_pack = sub.add_parser("pack", help="write a Markdown, JSON, and zip evidence pack")
    p_pack.add_argument("--case-dir", dest="case_dir", default=".", help="case workspace")
    p_pack.add_argument("--output", help="directory to write the pack into (default: <case>/pack)")

    p_ex = sub.add_parser("example", help="shipped fictional walkthrough")
    ex_sub = p_ex.add_subparsers(dest="example_command", required=True)
    p_ex_synth = ex_sub.add_parser(
        "synth",
        help="copy the fictional notes-api pass and fail cases into a new directory",
    )
    p_ex_synth.add_argument("dest_dir", help="directory to create")

    return parser


def _run(args: argparse.Namespace) -> int:
    if args.command == "init":
        dest = init_case(args.case_dir)
        print(f"Initialized GainGate case workspace at {dest}")
        return 0

    if args.command == "example" and args.example_command == "synth":
        dest = synth_example(args.dest_dir)
        print(f"Copied fictional notes-api walkthrough to {dest}")
        print("Cases: pass, fail-baseline, fail-required-hop")
        return 0

    if args.command == "pin":
        case = case_dir(args.case_dir)
        record = record_pin(
            case,
            tag=args.tag,
            sha=args.sha,
            origin=args.origin,
            offline=args.offline,
            artifact_sha256=args.artifact_sha256,
            artifact_file=args.artifact_file,
            case_id=args.case_id,
            subject=args.subject,
        )
        print(json.dumps(record, indent=2, ensure_ascii=False))
        return 0

    if args.command == "env":
        case = case_dir(args.case_dir)
        record = record_env(case)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        return 0

    if args.command == "hop" and args.hop_command == "add":
        case = case_dir(args.case_dir)
        entry = add_hop(
            case,
            hop_id=args.hop_id,
            description=args.description,
            label=args.label,
            evidence=args.evidence,
            reason=args.reason,
        )
        print(json.dumps(entry, indent=2, ensure_ascii=False))
        return 0

    if args.command == "gate" and args.gate_command == "validate":
        case = case_dir(args.case_dir)
        verdict = validate_gate(case)
        sys.stdout.write(format_verdict(verdict))
        return 0 if verdict.passed else 1

    if args.command == "pack":
        case = case_dir(args.case_dir)
        written = pack_case(case, output=args.output)
        print(f"Wrote {written['markdown']}")
        print(f"Wrote {written['json']}")
        print(f"Wrote {written['zip']}")
        if written.get("sha256"):
            print(f"Wrote {written['sha256']}")
        return 0 if written.get("passed") else 1

    raise WorkspaceError(f"unrecognized command: {getattr(args, 'command', None)}")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except WorkspaceError as exc:
        print(f"gaingate: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
