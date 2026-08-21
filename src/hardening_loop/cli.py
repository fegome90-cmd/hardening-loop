"""Command-line interface for Algorithmic Code Hardening Loop."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .admission import KnowledgeAdmissionGate
from .models import (
    AdmissionStatus,
    PhaseName,
    VerificationStatus,
    sha256_dict,
    utc_now_iso,
)
from .runner import HardeningRunner
from .sandbox import PathSandboxError, assert_within_workspace
from .schema_validator import SchemaValidationError, SchemaValidator


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
    run_parser.add_argument("--workspace-root", default=None, help="Root directory confining authorized file access")
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
    review_parser.add_argument("--workspace-root", default=None, help="Root directory confining authorized file access")
    review_parser.add_argument("--json", action="store_true", help="Emit review result as JSON")
    review_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential text")

    # Subcommand: inspect (Cryptographic Integrity & Anti-Tampering Audit)
    inspect_parser = subparsers.add_parser("inspect", help="Inspect and cryptographically verify an evidence directory")
    inspect_parser.add_argument("evidence_dir", help="Path to evidence directory containing evidence_manifest.json")
    inspect_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access"
    )
    inspect_parser.add_argument("--json", action="store_true", help="Emit inspection report as JSON")
    inspect_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    # Subcommand: validate (Standalone JSON/YAML Schema Validator)
    validate_parser = subparsers.add_parser("validate", help="Validate an artifact against normative JSON Schemas")
    validate_parser.add_argument("file_path", help="Path to JSON or YAML artifact to validate")
    validate_parser.add_argument(
        "--schema",
        choices=["evidence_envelope", "knowledge_candidate", "work_unit"],
        default=None,
        help="Explicit schema name to validate against (autodetected if omitted)",
    )
    validate_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access"
    )
    validate_parser.add_argument("--json", action="store_true", help="Emit validation result as JSON")
    validate_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    # Subcommand: telemetry (Observability, Latencies, Throughput, and Memory)
    telemetry_parser = subparsers.add_parser(
        "telemetry", help="Display performance telemetry, latencies, and throughput"
    )
    telemetry_parser.add_argument("evidence_dir", help="Path to evidence directory containing evidence_manifest.json")
    telemetry_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access"
    )
    telemetry_parser.add_argument("--json", action="store_true", help="Emit telemetry metrics as JSON")
    telemetry_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    return parser


def handle_run(args: argparse.Namespace) -> int:
    try:
        target = assert_within_workspace(args.target, args.workspace_root)
        output_dir = assert_within_workspace(args.output, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    if not os.path.exists(target):
        print(f"Error: Target path '{target}' does not exist.", file=sys.stderr)
        return 1

    try:
        runner = HardeningRunner(target_path=target, output_dir=output_dir)
        if not args.quiet and not args.json:
            print("=== Algorithmic Code Hardening Loop v0.3 ===")
            print(f"Target: {target}")
            print(f"Output: {output_dir}")
            print(f"Initial State: {runner.work_unit.state.value}")

        if args.phase == "all":
            envelopes = runner.run_all()
            if args.json:
                canonical_blocks = [e.canonical.to_dict() for e in envelopes]
                manifest = {
                    "canonical_manifest_digest": sha256_dict({"phases": canonical_blocks}),
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
                    print(f"Evidence artifacts successfully generated in {output_dir}")
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
                    print(f"Evidence artifacts successfully generated in {output_dir}")

        all_passed = all(e.status == VerificationStatus.PASS for e in runner.envelopes)
        return 0 if all_passed else 1

    except SchemaValidationError as e:
        print(f"Schema Validation Violation: {e}", file=sys.stderr)
        return 2
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Runtime Execution Error: {e}", file=sys.stderr)
        return 1


def handle_review(args: argparse.Namespace) -> int:
    try:
        file_path = assert_within_workspace(args.candidate_file, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

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


def handle_inspect(args: argparse.Namespace) -> int:
    try:
        evidence_dir = assert_within_workspace(args.evidence_dir, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    manifest_path = os.path.join(evidence_dir, "evidence_manifest.json")
    if not os.path.exists(manifest_path):
        print(f"Error: Manifest file '{manifest_path}' not found.", file=sys.stderr)
        return 1

    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

        expected_digest = manifest.get("canonical_manifest_digest")
        envelopes = manifest.get("envelopes", [])

        # 1. Validate each envelope against normative JSON Schema
        for env in envelopes:
            SchemaValidator.validate_or_raise("evidence_envelope", env)

        # 2. Recalculate canonical manifest digest
        canonical_blocks = [env["canonical_evidence"] for env in envelopes]
        calculated_digest = sha256_dict({"phases": canonical_blocks})

        tamper_detected = calculated_digest != expected_digest

        report = {
            "evidence_dir": evidence_dir,
            "manifest_file": manifest_path,
            "total_envelopes_verified": len(envelopes),
            "expected_manifest_digest": expected_digest,
            "calculated_manifest_digest": calculated_digest,
            "tamper_detected": tamper_detected,
            "integrity_status": "INTEGRITY_PASS" if not tamper_detected else "TAMPER_DETECTED",
        }

        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        elif not args.quiet:
            print("=== Evidence Cryptographic Integrity Report ===")
            print(f"Directory: {evidence_dir}")
            print(f"Envelopes Verified: {len(envelopes)}")
            print(f"Integrity Status: {report['integrity_status']}")
            if tamper_detected:
                print(
                    f"[FAIL-CLOSED] Cryptographic digest mismatch! Expected {expected_digest}, got {calculated_digest}"
                )

        return 0 if not tamper_detected else 2

    except SchemaValidationError as e:
        print(f"Schema Validation Violation during inspect: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error inspecting evidence directory: {e}", file=sys.stderr)
        return 1


def handle_validate(args: argparse.Namespace) -> int:
    try:
        file_path = assert_within_workspace(args.file_path, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    if not os.path.exists(file_path):
        print(f"Error: Target file '{file_path}' does not exist.", file=sys.stderr)
        return 1

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Parse JSON or YAML
        payload: Any = None
        if file_path.endswith((".yaml", ".yml")):
            import yaml

            payload = yaml.safe_load(content)
        else:
            payload = json.loads(content)

        # Autodetect schema name if not provided
        schema_name = args.schema
        if not schema_name:
            if isinstance(payload, list) or "candidate_id" in content or file_path.endswith(".yaml"):
                schema_name = "knowledge_candidate"
            elif "work_unit_id" in content:
                schema_name = "work_unit"
            elif "canonical_evidence" in content:
                schema_name = "evidence_envelope"
            else:
                schema_name = "evidence_envelope"

        if isinstance(payload, list):
            for item in payload:
                SchemaValidator.validate_or_raise(schema_name, item)
        else:
            SchemaValidator.validate_or_raise(schema_name, payload)

        if args.json:
            res = {
                "file": file_path,
                "schema": schema_name,
                "status": "VALID",
            }
            print(json.dumps(res, indent=2, sort_keys=True))
        elif not args.quiet:
            print(f"✓ Schema Validation Passed: '{file_path}' conforms to '{schema_name}.schema.json'")

        return 0

    except SchemaValidationError as e:
        print(f"Schema Validation Violation: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error validating file: {e}", file=sys.stderr)
        return 1


def handle_telemetry(args: argparse.Namespace) -> int:
    try:
        evidence_dir = assert_within_workspace(args.evidence_dir, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    manifest_path = os.path.join(evidence_dir, "evidence_manifest.json")
    if not os.path.exists(manifest_path):
        print(f"Error: Manifest file '{manifest_path}' not found.", file=sys.stderr)
        return 1

    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

        telemetry = manifest.get("runtime_telemetry", {})
        if args.json:
            print(json.dumps(telemetry, indent=2, sort_keys=True))
        elif not args.quiet:
            print("=== Hardening Loop Telemetry & Observability Report ===")
            print(f"Evidence Directory: {evidence_dir}")
            print(f"Total Duration:     {telemetry.get('total_duration_ms', 0)} ms")
            print(f"Total LOC Analyzed: {telemetry.get('total_loc_analyzed', 0)} lines")
            print(f"Throughput:         {telemetry.get('throughput_loc_per_sec', 0)} LOC/sec")
            print(f"Peak Memory (RSS):  {telemetry.get('peak_memory_mb', 0)} MB")
            print(f"Final Status:       {telemetry.get('final_status', 'UNKNOWN')}")
            print("-" * 55)
            print("Phase Durations:")
            durations = telemetry.get("phase_durations_ms", {})
            for phase, duration in durations.items():
                print(f"  - {phase:<10}: {duration:>8.3f} ms")
        return 0
    except Exception as e:
        print(f"Error reading telemetry: {e}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return handle_run(args)
    elif args.command == "review":
        return handle_review(args)
    elif args.command == "inspect":
        return handle_inspect(args)
    elif args.command == "validate":
        return handle_validate(args)
    elif args.command == "telemetry":
        return handle_telemetry(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
