"""Command-line interface for Algorithmic Code Hardening Loop."""

import argparse
import hashlib
import json
import os
import sys

import yaml

from .admission import KnowledgeAdmissionGate
from .models import (
    AdmissionStatus,
    PhaseName,
    sha256_dict,
    utc_now_iso,
)
from .posthog_sink import PostHogSinkError, PostHogTelemetrySink
from .runner import HardeningRunner, aggregate_final_status
from .sandbox import PathSandboxError, assert_within_workspace
from .schema_validator import SchemaValidationError, SchemaValidator
from .telemetry import verify_manifest_integrity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardening-loop",
        description="Algorithmic Code Hardening Loop (Musk/Zechner Framework)",
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
    run_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access (default: current dir)"
    )
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
    review_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access (default: current dir)"
    )
    review_parser.add_argument("--json", action="store_true", help="Emit review result as JSON")
    review_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential text")

    # Subcommand: inspect (Cryptographic Integrity & Physical File Anti-Tampering Audit)
    inspect_parser = subparsers.add_parser("inspect", help="Inspect and cryptographically verify an evidence directory")
    inspect_parser.add_argument("evidence_dir", help="Path to evidence directory containing evidence_manifest.json")
    inspect_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access (default: current dir)"
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
        "--workspace-root", default=None, help="Root directory confining authorized file access (default: current dir)"
    )
    validate_parser.add_argument("--json", action="store_true", help="Emit validation result as JSON")
    validate_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    # Subcommand: telemetry (Observability, Latencies, Throughput, and Memory)
    telemetry_parser = subparsers.add_parser(
        "telemetry", help="Display performance telemetry, latencies, and throughput"
    )
    telemetry_parser.add_argument("evidence_dir", help="Path to evidence directory containing evidence_manifest.json")
    telemetry_parser.add_argument(
        "--workspace-root", default=None, help="Root directory confining authorized file access (default: current dir)"
    )
    telemetry_parser.add_argument("--posthog", action="store_true", help="Export telemetry batch to PostHog Cloud")
    telemetry_parser.add_argument("--api-key", default=None, help="PostHog API Key / Project Token")
    telemetry_parser.add_argument(
        "--dry-run", action="store_true", help="Simulate export without sending network request"
    )
    telemetry_parser.add_argument("--json", action="store_true", help="Emit telemetry metrics as JSON")
    telemetry_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    return parser


# Backward compatibility alias
create_parser = build_parser


def handle_run(args: argparse.Namespace) -> int:
    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        return 1

    try:
        target = assert_within_workspace(args.target, args.workspace_root)
        output_dir = assert_within_workspace(args.output, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    runner = HardeningRunner(target_path=target, output_dir=output_dir)

    try:
        if not args.quiet and not args.json:
            print("=== Algorithmic Code Hardening Loop v0.3 ===")
            print(f"Target: {target}")
            print(f"Output: {output_dir}")
            print(f"Initial State: {runner.work_unit.state.value}")

        if args.phase == "all":
            envelopes = runner.run_all()
            final_status = aggregate_final_status(envelopes)
            if args.json:
                canonical_blocks = [e.canonical.to_dict() for e in envelopes]
                manifest = {
                    "canonical_manifest_digest": sha256_dict({"phases": canonical_blocks}),
                    "work_unit": runner.work_unit.to_dict(),
                    "envelopes": [e.to_dict() for e in envelopes],
                    "completed_at": utc_now_iso(),
                    "final_status": final_status,
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

        final_status = aggregate_final_status(runner.envelopes)
        return 1 if final_status in ("FAIL", "BLOCKED", "ERROR") else 0

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
    if not os.path.exists(args.candidate_file):
        print(f"Error: Candidate file '{args.candidate_file}' does not exist.", file=sys.stderr)
        return 1

    try:
        file_path = assert_within_workspace(args.candidate_file, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        raw_yaml = yaml.safe_load(content)
        candidates_data = raw_yaml if isinstance(raw_yaml, list) else [raw_yaml]

        decision = AdmissionStatus.ACCEPTED if args.admit else AdmissionStatus.REJECTED
        reviewed_candidates = []

        for c_data in candidates_data:
            yaml_str = yaml.dump(c_data, sort_keys=False)
            candidate = KnowledgeAdmissionGate.load_candidate_yaml(yaml_str)
            reviewed = KnowledgeAdmissionGate.review_candidate(
                candidate=candidate,
                decision=decision,
                reviewer=args.reviewer,
                notes=args.notes,
            )
            reviewed_candidates.append(reviewed.to_dict())

        # Write back updated candidate YAML
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(
                reviewed_candidates if len(reviewed_candidates) > 1 else reviewed_candidates[0],
                f,
                sort_keys=False,
                allow_unicode=True,
            )

        review_result = {
            "decision": decision.value,
            "reviewer": args.reviewer,
            "notes": args.notes,
            "candidates_reviewed": len(reviewed_candidates),
            "candidates": reviewed_candidates,
        }

        if args.json:
            print(json.dumps(review_result, indent=2, sort_keys=True))
        elif not args.quiet:
            print("=== Knowledge Admission Gate Review Result ===")
            print(f"File: {file_path}")
            print(f"Decision: {decision.value}")
            print(f"Reviewer: {args.reviewer}")
            print(f"Candidates Reviewed: {len(reviewed_candidates)}")
            print("Knowledge state successfully transitioned and persisted.")

        return 0

    except SchemaValidationError as e:
        print(f"Schema Validation Violation during review: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Review Error: {e}", file=sys.stderr)
        return 1


def handle_inspect(args: argparse.Namespace) -> int:
    """Inspects and cryptographically verifies an evidence directory and physical files on disk."""
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
        artifacts = manifest.get("artifacts", [])

        tamper_detected = False
        tamper_details: list[str] = []

        # 1. Validate manifest against normative JSON schema
        try:
            SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", manifest)
        except SchemaValidationError as e:
            tamper_detected = True
            tamper_details.append(f"Manifest schema validation violation: {e}")

        # 2. Cryptographically verify manifest integrity hash over the entire document
        is_hash_valid, hash_msg = verify_manifest_integrity(manifest)
        if not is_hash_valid:
            tamper_detected = True
            tamper_details.append(hash_msg)

        # 3. Validate each envelope against normative JSON Schema if present
        for env in envelopes:
            SchemaValidator.validate_or_raise("evidence_envelope", env)

        # 4. Enforce presence and recalculation of canonical manifest digest over envelopes (Finding 2)
        if not expected_digest:
            tamper_detected = True
            tamper_details.append("Manifest is missing required 'canonical_manifest_digest'")
            calculated_digest = ""
        elif not envelopes:
            tamper_detected = True
            tamper_details.append("Manifest is missing required 'envelopes' list")
            calculated_digest = ""
        else:
            canonical_blocks = [env["canonical_evidence"] for env in envelopes]
            calculated_digest = sha256_dict({"phases": canonical_blocks})
            if calculated_digest != expected_digest:
                tamper_detected = True
                tamper_details.append(
                    f"Manifest canonical digest mismatch: expected {expected_digest}, calculated {calculated_digest}"
                )

        # 5. Physically verify every artifact file on disk against its SHA-256 digest (Ley XI & Ley VIII)
        verified_artifacts_count = 0
        if not artifacts:
            tamper_detected = True
            tamper_details.append("Manifest contains no registered artifacts (artifacts list missing or empty)")
        else:
            ev_real = os.path.realpath(evidence_dir)
            for art in artifacts:
                rel_path = art.get("path", "")
                expected_sha = art.get("sha256", "")

                # Path traversal and escaping verification
                if not rel_path or rel_path.startswith("/") or ".." in rel_path.split("/") or "\\" in rel_path:
                    tamper_detected = True
                    tamper_details.append(f"Unsafe artifact path '{rel_path}' escapes evidence boundary")
                    continue

                full_art_path = os.path.realpath(os.path.join(evidence_dir, rel_path))
                if os.path.commonpath((full_art_path, ev_real)) != ev_real:
                    tamper_detected = True
                    tamper_details.append(f"Artifact path '{rel_path}' escapes evidence directory boundary")
                    continue

                if not os.path.exists(full_art_path):
                    tamper_detected = True
                    tamper_details.append(f"Missing physical artifact on disk: {rel_path}")
                    continue

                try:
                    with open(full_art_path, "rb") as af:
                        actual_sha = hashlib.sha256(af.read()).hexdigest()
                    if actual_sha != expected_sha:
                        tamper_detected = True
                        tamper_details.append(
                            f"Corrupted artifact '{rel_path}': expected SHA-256 {expected_sha[:12]}..., got {actual_sha[:12]}..."
                        )
                    else:
                        verified_artifacts_count += 1
                except OSError as e:
                    tamper_detected = True
                    tamper_details.append(f"Failed to read artifact '{rel_path}': {e}")

        report = {
            "evidence_dir": evidence_dir,
            "manifest_file": manifest_path,
            "total_envelopes_verified": len(envelopes),
            "total_physical_artifacts_verified": verified_artifacts_count,
            "expected_manifest_digest": expected_digest,
            "calculated_manifest_digest": calculated_digest,
            "tamper_detected": tamper_detected,
            "tamper_details": tamper_details,
            "integrity_status": "INTEGRITY_PASS" if not tamper_detected else "TAMPER_DETECTED",
        }

        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        elif not args.quiet:
            print("=== Evidence Cryptographic Integrity Report ===")
            print(f"Directory: {evidence_dir}")
            print(f"Envelopes Verified: {len(envelopes)}")
            print(f"Physical Artifacts Verified: {verified_artifacts_count}")
            print(f"Integrity Status: {report['integrity_status']}")
            if tamper_detected:
                print("[FAIL-CLOSED] Tampering detected:\n - " + "\n - ".join(tamper_details))

        return 0 if not tamper_detected else 2

    except SchemaValidationError as e:
        print(f"Schema Validation Violation during inspect: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error inspecting evidence directory: {e}", file=sys.stderr)
        return 1


def handle_validate(args: argparse.Namespace) -> int:
    if not os.path.exists(args.file_path):
        print(f"Error: Target artifact file '{args.file_path}' does not exist.", file=sys.stderr)
        return 1

    try:
        file_path = assert_within_workspace(args.file_path, args.workspace_root)
    except PathSandboxError as e:
        print(f"Path Sandbox Violation: {e}", file=sys.stderr)
        return 2

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Load payload from JSON or YAML
        if file_path.endswith((".yaml", ".yml")):
            payload = yaml.safe_load(content)
        else:
            payload = json.loads(content)

        # Autodetect schema name if not specified
        schema_name = args.schema
        if not schema_name:
            if isinstance(payload, dict) and "canonical_evidence" in payload:
                schema_name = "evidence_envelope"
            elif isinstance(payload, dict) and "rule_proposal" in payload:
                schema_name = "knowledge_candidate"
            elif isinstance(payload, dict) and "work_unit_id" in payload:
                schema_name = "work_unit"
            elif isinstance(payload, list) and len(payload) > 0 and "rule_proposal" in payload[0]:
                schema_name = "knowledge_candidate"
                payload = payload[0]  # validate first candidate in list
            else:
                schema_name = "evidence_envelope"

        SchemaValidator.validate_or_raise(schema_name, payload)

        result = {
            "file": file_path,
            "schema": schema_name,
            "status": "VALID",
            "message": f"Artifact conforms strictly to {schema_name}.schema.json",
        }

        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif not args.quiet:
            print("=== Artifact Schema Validation ===")
            print(f"File: {file_path}")
            print(f"Schema: {schema_name}")
            print("Status: VALID")

        return 0

    except SchemaValidationError as e:
        print(f"Schema Validation Violation: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Validation Error: {e}", file=sys.stderr)
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
        posthog_result = None

        if args.posthog or args.dry_run:
            sink = PostHogTelemetrySink(api_key=args.api_key)
            posthog_result = sink.export(manifest, dry_run=args.dry_run)

        if args.json:
            if posthog_result:
                print(json.dumps(posthog_result, indent=2, sort_keys=True))
            else:
                print(json.dumps(telemetry, indent=2, sort_keys=True))
        elif not args.quiet:
            print("=== Hardening Loop Telemetry & Observability Report ===")
            print(f"Directory: {evidence_dir}")
            print(f"Total Duration: {telemetry.get('total_duration_ms', 0)} ms")
            print(f"Total LOC Analyzed: {telemetry.get('total_loc_analyzed', 0)}")
            print(f"Total AST Nodes Visited: {telemetry.get('total_ast_nodes_visited', 0)}")
            print(f"Throughput: {telemetry.get('throughput_loc_per_sec', 0)} LOC/s")
            print(f"Peak Memory RSS: {telemetry.get('peak_memory_mb', 0)} MB")
            print(f"Memory Delta RSS: {telemetry.get('memory_delta_mb', 0)} MB")
            print(f"Final Status: {telemetry.get('final_status', 'UNKNOWN')}")
            print("\n--- Phase Breakdown (ms) ---")
            for phase, dur in telemetry.get("phase_durations_ms", {}).items():
                print(f"  {phase.upper():<10}: {dur:>8.2f} ms")

            if posthog_result:
                print(
                    f"\n[PostHog] Status: {posthog_result['status']} | Events: {posthog_result.get('events_count', 0)}"
                )

        return 0

    except PostHogSinkError as e:
        print(f"PostHog Telemetry Export Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Telemetry Error: {e}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
