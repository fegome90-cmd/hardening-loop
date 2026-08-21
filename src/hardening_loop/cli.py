import argparse
import json
import os
import sys

from .admission import KnowledgeAdmissionGate
from .models import (
    AdmissionStatus,
    PhaseName,
    VerificationStatus,
    sha256_dict,
    utc_now_iso,
)
from .runner import HardeningRunner
from .schema_validator import SchemaValidationError


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardening-loop",
        description="Algorithmic Code Hardening Loop v0.3 — Minimal CLI Runner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: run
    run_parser = subparsers.add_parser("run", help="Execute hardening phases on a target file/module")
    run_parser.add_argument("--target", required=True, help="Path to target code or module")
    run_parser.add_argument(
        "--phase",
        default="all",
        choices=["all", "question", "delete", "simplify", "verify", "codify"],
        help="Hardening phase to execute (default: all)",
    )
    run_parser.add_argument("--output", default="./evidence/run-001", help="Output evidence directory")
    run_parser.add_argument("--json", action="store_true", help="Emit raw JSON manifest to stdout for agents")
    run_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress verbose banners")

    # Subcommand: review (Knowledge Admission Gate Aduana)
    review_parser = subparsers.add_parser("review", help="Review a Knowledge Candidate in the Admission Gate")
    review_parser.add_argument("candidate_file", help="Path to knowledge_candidate.yaml file")
    decision_group = review_parser.add_mutually_exclusive_group(required=True)
    decision_group.add_argument("--admit", action="store_true", help="Admit candidate into accepted knowledge")
    decision_group.add_argument("--reject", action="store_true", help="Reject candidate")
    review_parser.add_argument("--reviewer", required=True, help="Identifier of the human/curator reviewer")
    review_parser.add_argument("--notes", default="", help="Review notes or justification")
    review_parser.add_argument("--json", action="store_true", help="Emit review result as JSON")
    review_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential text")

    return parser


def handle_run(args: argparse.Namespace) -> int:
    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(f"Error: Target path '{target}' does not exist.", file=sys.stderr)
        return 1

    try:
        runner = HardeningRunner(target_path=target, output_dir=args.output)
        if not args.quiet and not args.json:
            print("=== Algorithmic Code Hardening Loop v0.3 ===")
            print(f"Target: {target}")
            print(f"Output: {os.path.abspath(args.output)}")
            print(f"Initial State: {runner.work_unit.state.value}")

        if args.phase == "all":
            envelopes = runner.run_all()
            if args.json:
                canonical_blocks = [e.canonical.to_dict() for e in envelopes]
                canonical_manifest_digest = sha256_dict({"phases": canonical_blocks})
                manifest = {
                    "canonical_manifest_digest": canonical_manifest_digest,
                    "work_unit": runner.work_unit.to_dict(),
                    "envelopes": [e.to_dict() for e in envelopes],
                    "completed_at": utc_now_iso(),
                    "final_status": "PASS" if all(e.status == VerificationStatus.PASS for e in envelopes) else "WARN",
                }
                print(json.dumps(manifest, indent=2, sort_keys=True))
            else:
                for env in envelopes:
                    print(
                        f"[{env.phase.value.upper()}] Status: {env.status.value} | Output Hash: {env.output_hash[:12]}... | ID: {env.evidence_id}"
                    )
                if not args.quiet:
                    print(f"Final State: {runner.work_unit.state.value}")
                    print(f"Evidence artifacts successfully generated in {os.path.abspath(args.output)}")
        else:
            phase_enum = PhaseName(args.phase)
            env = runner.run_phase(phase_enum)
            if args.json:
                print(json.dumps(env.to_dict(), indent=2, sort_keys=True))
            else:
                print(
                    f"[{env.phase.value.upper()}] Status: {env.status.value} | Output Hash: {env.output_hash[:12]}... | ID: {env.evidence_id}"
                )
                if not args.quiet:
                    print(f"Final State: {runner.work_unit.state.value}")
                    print(f"Evidence artifacts successfully generated in {os.path.abspath(args.output)}")

        # Strict POSIX return code: 0 on PASS, 1 on any check failure
        all_passed = all(e.status == VerificationStatus.PASS for e in runner.envelopes)
        return 0 if all_passed else 1

    except SchemaValidationError as e:
        print(f"Schema Validation Violation: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Runtime Execution Error: {e}", file=sys.stderr)
        return 1


def handle_review(args: argparse.Namespace) -> int:
    file_path = os.path.abspath(args.candidate_file)
    if not os.path.exists(file_path):
        print(f"Error: Candidate file '{file_path}' does not exist.", file=sys.stderr)
        return 1

    with open(file_path, encoding="utf-8") as f:
        content = f.read()

    decision = AdmissionStatus.ACCEPTED if args.admit else AdmissionStatus.REJECTED
    try:
        import yaml

        raw_items = yaml.safe_load(content)
        if isinstance(raw_items, list):
            reviewed_items = []
            for item in raw_items:
                c = KnowledgeAdmissionGate.load_candidate_yaml(yaml.dump(item))
                c = KnowledgeAdmissionGate.review_candidate(c, decision, args.reviewer, args.notes)
                reviewed_items.append(c.to_dict())
            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(reviewed_items, f, sort_keys=False, allow_unicode=True)
        else:
            c = KnowledgeAdmissionGate.load_candidate_yaml(content)
            c = KnowledgeAdmissionGate.review_candidate(c, decision, args.reviewer, args.notes)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(KnowledgeAdmissionGate.export_candidate_yaml(c))

        if args.json:
            res = {
                "decision": decision.value,
                "reviewer": args.reviewer,
                "file": file_path,
                "status": "SUCCESS",
            }
            print(json.dumps(res, indent=2, sort_keys=True))
        elif not args.quiet:
            print(f"Knowledge Admission Gate Decision Recorded: {decision.value}")
            print(f"Reviewer: {args.reviewer}")
            print(f"Updated File: {file_path}")
        return 0
    except SchemaValidationError as e:
        print(f"Schema Validation Violation in Admission: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error during admission review: {e}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return handle_run(args)
    elif args.command == "review":
        return handle_review(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
