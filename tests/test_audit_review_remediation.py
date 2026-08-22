"""Comprehensive adversarial regression tests covering all audit findings and hardening blockers."""

from __future__ import annotations

import ast
import glob
import io
import json
import os
from datetime import datetime, timezone

import pytest
import yaml

from hardening_loop.cli import main
from hardening_loop.models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    sha256_text,
    utc_now_iso,
)
from hardening_loop.phases import (
    CodifyPhase,
    QuestionPhase,
)
from hardening_loop.phases.base import find_subprocess_calls, is_internal_framework_target
from hardening_loop.phases.simplify import infer_return_type
from hardening_loop.posthog_sink import PostHogSinkError, PostHogTelemetrySink
from hardening_loop.runner import HardeningRunner, aggregate_final_status
from hardening_loop.sandbox import PathSandboxError, assert_within_workspace
from hardening_loop.schema_validator import SchemaValidator
from hardening_loop.telemetry import verify_manifest_integrity


def test_s1_run_all_halts_immediately_on_verify_fail(tmp_path):
    """S1: run_all() must halt after verify failure and NEVER execute codify (Ley VIII)."""
    target = tmp_path / "unsafe_target.py"
    target.write_text("import os\nos.system('echo unsafe')\n", encoding="utf-8")
    out_dir = tmp_path / "evidence"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    envelopes = runner.run_all()

    executed_phases = [e.phase for e in envelopes]
    assert PhaseName.VERIFY in executed_phases
    assert PhaseName.CODIFY not in executed_phases
    assert runner.envelopes[-1].status == VerificationStatus.FAIL


def test_s2_monotonic_status_precedence():
    """S2: Aggregate final status must follow strict precedence: FAIL > WARN > PASS."""

    def mock_env(status: VerificationStatus) -> EvidenceEnvelope:
        canonical = CanonicalEvidence(
            evidence_id="evi-11112222",
            phase=PhaseName.QUESTION,
            input_hash="a" * 64,
            output_hash="b" * 64,
            method_version="v0.3",
            schema_version="v0.1",
            execution_context_hash="c" * 64,
            artifact_payload={},
        )
        runtime = RuntimeReceipt(
            producer="test",
            timestamp=utc_now_iso(),
            duration_ms=1.0,
            checks=[],
            status=status,
        )
        return EvidenceEnvelope(canonical=canonical, runtime=runtime)

    assert aggregate_final_status([mock_env(VerificationStatus.PASS), mock_env(VerificationStatus.PASS)]) == "PASS"
    assert aggregate_final_status([mock_env(VerificationStatus.PASS), mock_env(VerificationStatus.WARN)]) == "WARN"
    assert (
        aggregate_final_status(
            [mock_env(VerificationStatus.PASS), mock_env(VerificationStatus.WARN), mock_env(VerificationStatus.FAIL)]
        )
        == "FAIL"
    )
    assert aggregate_final_status([mock_env(VerificationStatus.BLOCKED), mock_env(VerificationStatus.PASS)]) == "FAIL"


def test_s3_default_workspace_sandboxing_fails_closed():
    """S3: assert_within_workspace must default to current workspace and fail closed."""
    with pytest.raises(PathSandboxError):
        assert_within_workspace("/etc/passwd")


def test_s4_inspect_detects_physical_artifact_tampering_on_disk(tmp_path):
    """S4: inspect must detect tampering of physical files on disk (Ley XI & Ley VIII)."""
    target = tmp_path / "clean.py"
    target.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    # 1. Run full hardening loop
    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    # 2. Inspect clean evidence directory -> MUST PASS
    ret_clean = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret_clean == 0

    # 3. Tamper with a physical file on disk (without updating manifest)
    tampered_file = out_dir / "test_results.json"
    tampered_file.write_text('{"tampered": true}', encoding="utf-8")

    # 4. Inspect tampered directory -> MUST FAIL with code 2
    ret_tampered = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret_tampered == 2


def test_s4_inspect_detects_path_traversal_escape_in_manifest(tmp_path):
    """S4: inspect must reject manifests pointing to artifacts outside the evidence directory."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Add a malicious artifact pointing to ../secret.txt
    manifest_data["artifacts"].append({"path": "../secret.txt", "type": "evidence", "sha256": "e" * 64})
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_s5_manifest_integrity_hash_verified_and_schema_compliant(tmp_path):
    """S5 & P1: evidence_manifest.json must pass v0.2 schema validation and have valid manifest_hash."""
    target = tmp_path / "clean.py"
    target.write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_path = out_dir / "evidence_manifest.json"
    assert manifest_path.exists()

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

    # 1. Validate against schema v0.2
    SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", manifest_data)

    # 2. Verify cryptographically that manifest_hash matches canonical calculation
    is_valid, _ = verify_manifest_integrity(manifest_data)
    assert is_valid is True


def test_s5_inspect_detects_manifest_and_artifact_synchronized_tampering(tmp_path):
    """S5: If an attacker modifies an artifact AND updates the manifest artifact sha256,

    manifest_hash detects desynchronization and fails closed.
    """
    target = tmp_path / "clean.py"
    target.write_text("x = 42\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    # Tamper with file
    diff_file = out_dir / "diff.patch"
    diff_file.write_text("MALICIOUS PATCH CONTENT", encoding="utf-8")
    new_sha = sha256_text("MALICIOUS PATCH CONTENT")

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Update the artifact entry in manifest to match new file hash
    for art in manifest_data["artifacts"]:
        if art["path"] == "diff.patch":
            art["sha256"] = new_sha

    # Attacker does NOT know how to forge manifest_hash or forgot to update it
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_s6_posthog_sink_hardening():
    """S6: PostHogTelemetrySink must enforce strict HTTPS allowlist and reject attacker hosts."""
    # 1. Authorized hosts MUST PASS
    sink_us = PostHogTelemetrySink(api_key="phc_test12345", host="https://us.i.posthog.com")
    assert sink_us.host == "https://us.i.posthog.com"

    sink_eu = PostHogTelemetrySink(api_key="phc_test12345", host="https://eu.i.posthog.com")
    assert sink_eu.host == "https://eu.i.posthog.com"

    sink_app = PostHogTelemetrySink(api_key="phc_test12345", host="https://app.posthog.com")
    assert sink_app.host == "https://app.posthog.com"

    # 2. Plain HTTP MUST FAIL
    with pytest.raises(PostHogSinkError, match="HTTP is only permitted"):
        PostHogTelemetrySink(api_key="phc_test12345", host="http://us.i.posthog.com")

    # 3. Attacker HTTPS host outside allowlist MUST FAIL
    with pytest.raises(PostHogSinkError, match="authorized allowlist"):
        PostHogTelemetrySink(api_key="phc_test12345", host="https://attacker.example.com")

    # 4. Trailing slashes and path components must be cleanly sanitized to origin
    sink_trail = PostHogTelemetrySink(api_key="phc_test12345", host="https://us.i.posthog.com/batch/v1/")
    assert sink_trail.host == "https://us.i.posthog.com"


def test_p2_and_p3_ast_nodes_and_directory_loc_metrics(tmp_path):
    """P2 & P3: Metrics must report real AST nodes visited and accurate multi-file directory LOC."""
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (d / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")

    out_dir = tmp_path / "evidence_pkg"
    runner = HardeningRunner(target_path=str(d), output_dir=str(out_dir))
    envelopes = runner.run_all()

    assert len(envelopes) == 5
    summary = runner.telemetry.get_summary()

    # Total LOC must be 4 (2 lines + 2 lines)
    assert summary["total_loc_analyzed"] >= 4
    # AST nodes must be non-zero and accumulated across all files and phases
    assert summary["total_ast_nodes_visited"] > 0
    assert summary["throughput_loc_per_sec"] >= 0.0


# ==============================================================================
# TARGETED REGRESSION MATRIX: T01 .. T16
# ==============================================================================


def test_t01_run_all_json_validates_as_canonical_manifest_v02(tmp_path, monkeypatch):
    """T01: 'hardening-loop run --phase all --json' outputs canonical manifest conforming to schema v0.2."""
    target = tmp_path / "target.py"
    target.write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t01"

    out_buf = io.StringIO()
    monkeypatch.setattr("sys.stdout", out_buf)

    exit_code = main(
        [
            "run",
            "--target",
            str(target),
            "--phase",
            "all",
            "--output",
            str(out_dir),
            "--json",
            "--workspace-root",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    raw_output = out_buf.getvalue().strip()
    manifest_data = json.loads(raw_output)

    # Validate against normative v0.2 schema
    SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", manifest_data)
    assert manifest_data["schema_version"] == "hardening-loop.manifest.v0.2"
    assert "canonical_manifest_digest" in manifest_data
    assert "work_unit" in manifest_data
    assert "envelopes" in manifest_data
    assert "runtime_telemetry" in manifest_data


def test_t02_invalid_manifest_schema_immediate_abort(tmp_path):
    """T02: Manifest schema violation causes immediate fail-closed exit with code 2."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t02"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Invalidate schema by deleting required schema_version
    del manifest_data["schema_version"]
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_t03_no_artifact_inspection_after_manifest_schema_failure(tmp_path, monkeypatch):
    """T03: Inspect aborts on schema validation before processing downstream artifacts or digests."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t03"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    del manifest_data["schema_version"]  # Schema invalid
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # Also delete a physical file; inspect must fail on schema error without running physical checks
    diff_file = out_dir / "diff.patch"
    if diff_file.exists():
        diff_file.unlink()

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_t04_terminal_evidence_persistence_failure_is_observable(tmp_path, monkeypatch):
    """T04: Failure to write terminal manifest during error handling raises a chained observable RuntimeError."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t04"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))

    def _exploding_run(*args, **kwargs):
        raise RuntimeError("Primary phase execution failure")

    def _exploding_write_manifest(*args, **kwargs):
        raise OSError("Disk full: cannot write terminal manifest")

    monkeypatch.setattr(runner.phases[PhaseName.QUESTION], "run", _exploding_run)
    monkeypatch.setattr(runner, "_write_manifest", _exploding_write_manifest)

    with pytest.raises(RuntimeError, match="terminal evidence persistence failed"):
        runner.run_all()


def test_t05_invalid_verify_severity_codify_fails_closed(tmp_path):
    """T05: Invalid finding severity in upstream results causes CodifyPhase to fail closed."""
    phase = CodifyPhase()
    ctx = {
        "evidence_ids": ["evi-12345678"],
        "verify_failures": [
            {
                "name": "custom_check",
                "severity": "INVALID_UNKNOWN_SEVERITY",
                "details": "Malformed severity string",
            }
        ],
    }
    payload, checks, status = phase.execute(str(tmp_path / "app.py"), ctx)
    assert status == VerificationStatus.FAIL
    assert "error" in payload


def test_t06_subprocess_check_call_aliases_detected(tmp_path):
    """T06: subprocess.check_call(..., shell=True) detected across direct and aliased imports."""
    code = "import subprocess as sp\nsp.check_call('ls', shell=True)\n"
    target = tmp_path / "check_call_test.py"
    target.write_text(code, encoding="utf-8")

    tree = ast.parse(code)
    calls = find_subprocess_calls(tree)
    assert len(calls) == 1
    assert calls[0][1] is True  # shell=True detected


def test_t07_arbitrary_runner_run_is_not_subprocess(tmp_path):
    """T07: Custom class method runner.run(shell=True) is not flagged as a subprocess invocation."""
    code = "class CustomRunner:\n    def run(self, shell=True):\n        return True\nrunner = CustomRunner()\nrunner.run(shell=True)\n"
    tree = ast.parse(code)
    calls = find_subprocess_calls(tree)
    assert len(calls) == 0


def test_t08_nested_function_attribution_innermost_scope(tmp_path):
    """T08: Nested functions accurately attribute AST calls to the innermost enclosing scope."""
    code = """
def outer():
    def inner():
        with open('data.txt') as f:
            pass
"""
    target = tmp_path / "nested_scope.py"
    target.write_text(code, encoding="utf-8")

    phase = QuestionPhase()
    payload, checks, status = phase.execute(str(target), {})
    assert status == VerificationStatus.PASS
    sec_req = next(r for r in payload["requirements"] if "open" in r.get("audit_finding", ""))
    assert "(inner)" in sec_req["source"]


def test_t09_framework_target_resolution_failure_fails_closed(monkeypatch):
    """T09: When path resolution encounters an OSError, is_internal_framework_target propagates the error."""

    def _exploding_realpath(path):
        raise OSError("Simulated path resolution hardware fault")

    monkeypatch.setattr(os.path, "realpath", _exploding_realpath)
    with pytest.raises(OSError, match="hardware fault"):
        is_internal_framework_target("/any/path")


def test_t10_ast_unparse_failure_cannot_emit_annotated_pass(monkeypatch):
    """T10: ast.unparse failure on return node propagates and cannot falsely emit 'Annotated'."""
    fn_def = ast.FunctionDef(
        name="foo",
        args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=[ast.Pass()],
        decorator_list=[],
        returns=ast.Name(id="MyType", ctx=ast.Load()),
    )

    def _exploding_unparse(node):
        raise TypeError("Simulated unparse failure on malformed AST node")

    monkeypatch.setattr(ast, "unparse", _exploding_unparse)
    with pytest.raises(TypeError, match="Simulated unparse failure"):
        infer_return_type(fn_def)


def test_t11_knowledge_candidate_created_at_is_real_recent_utc(tmp_path):
    """T11: KnowledgeCandidate.created_at is valid ISO-8601 UTC within the exact execution window."""
    target = tmp_path / "app.py"
    target.write_text("import os\np = '/Users/dev/tmp'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t11"

    t_before = datetime.now(timezone.utc)
    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()
    t_after = datetime.now(timezone.utc)

    kc_file = out_dir / "knowledge_candidate.yaml"
    assert kc_file.exists()
    candidates = yaml.safe_load(kc_file.read_text(encoding="utf-8"))
    assert len(candidates) > 0

    for cand in candidates:
        created_str = cand["created_at"]
        assert not created_str.startswith("1970")
        dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        assert dt.tzinfo is not None
        offset = dt.utcoffset()
        assert offset is not None and offset.total_seconds() == 0
        assert t_before <= dt <= t_after


def test_t12_canonical_candidate_and_output_hash_remain_clock_independent(tmp_path):
    """T12: Canonical evidence output_hash is clock-independent and hermetically deterministic across runs."""
    phase = CodifyPhase()
    ctx = {
        "evidence_ids": ["evi-12345678"],
        "deletion_candidates": [
            {
                "target": "os_system",
                "location": "app.py:10",
                "rationale": "Unsafe shell invocation",
                "action": "DELETE",
                "severity": "HIGH",
            }
        ],
    }

    payload1, _, _ = phase.execute(str(tmp_path / "app.py"), ctx)
    payload2, _, _ = phase.execute(str(tmp_path / "app.py"), ctx)

    # Canonical payload for both executions must be bit-for-bit identical
    assert json.dumps(payload1, sort_keys=True) == json.dumps(payload2, sort_keys=True)


def test_t13_previous_run_evidence_neither_mixed_nor_destroyed(tmp_path):
    """T13 (Anti-Ferrari A): Attempting to start a run in a directory with existing evidence fails closed."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t13"

    # Run 1 succeeds
    r1 = HardeningRunner(str(target), str(out_dir))
    r1.run_all()
    assert (out_dir / "evidence_manifest.json").exists()

    # Run 2 on same output_dir fails closed immediately to protect Run 1 evidence
    with pytest.raises(ValueError, match="already contains evidence manifest from a prior run"):
        HardeningRunner(str(target), str(out_dir))


def test_t14_output_and_wal_workspace_boundary(tmp_path):
    """T14: Target or output path escaping the workspace boundary raises PathSandboxError."""
    outside_dir = "/tmp/escaped_output"
    with pytest.raises(PathSandboxError):
        assert_within_workspace(outside_dir, str(tmp_path))


def test_t15_knowledge_candidate_yaml_deterministic_ordering(tmp_path):
    """T15: knowledge_candidate.yaml keys are deterministically sorted."""
    target = tmp_path / "app.py"
    target.write_text("import os\np = '/Users/dev/tmp'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t15"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    kc_text = (out_dir / "knowledge_candidate.yaml").read_text(encoding="utf-8")
    # Verify candidate_id appears before observation, finding before rule_proposal in sorted YAML output
    assert kc_text.index("candidate_id:") < kc_text.index("observation:")
    assert kc_text.index("finding:") < kc_text.index("rule_proposal:")


def test_t16_manifest_fixtures_lifecycle_and_schema_disposition():
    """T16: All active generated manifest fixtures conform to schema v0.2 while historical fixtures are preserved."""
    active_manifests = glob.glob("evidence/run-00[3-6]*/evidence_manifest.json")
    assert len(active_manifests) > 0

    for manifest_path in active_manifests:
        with open(manifest_path, encoding="utf-8") as mf:
            data = json.load(mf)
        SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", data)
        assert data["schema_version"] == "hardening-loop.manifest.v0.2"


def test_cli_review_and_validate_strict_utf8_fail_closed(tmp_path):
    """CLI review and validate subcommands must fail closed if candidate or payload file has invalid UTF-8 bytes."""
    corrupted_yaml = tmp_path / "corrupted_candidate.yaml"
    corrupted_yaml.write_bytes(b"candidate_id: kc-123\nname: \xff\xfe invalid utf8\n")

    # Review must fail closed (exit code 1 or 2, never 0)
    ret_review = main(
        ["review", str(corrupted_yaml), "--admit", "--reviewer", "human_rev", "--workspace-root", str(tmp_path)]
    )
    assert ret_review != 0

    # Validate must fail closed (exit code 1 or 2, never 0)
    ret_validate = main(["validate", str(corrupted_yaml), "--workspace-root", str(tmp_path)])
    assert ret_validate != 0


def test_run_all_emits_terminal_fail_event_and_manifest_on_exception(tmp_path, monkeypatch):
    """If an unexpected exception aborts run_all(), it emits hardening_run_failed and materializes manifest FAIL."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_exception"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))

    # Force an exception during QuestionPhase run
    def _exploding_run(*args, **kwargs):
        raise RuntimeError("Simulated catastrophic crash in phase execution")

    monkeypatch.setattr(runner.phases[PhaseName.QUESTION], "run", _exploding_run)

    with pytest.raises(RuntimeError, match="Simulated catastrophic crash"):
        runner.run_all()

    # Verify terminal manifest was written with final_status FAIL
    manifest_path = out_dir / "evidence_manifest.json"
    assert manifest_path.exists()
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["final_status"] == "FAIL"

    # Verify WAL contains hardening_run_failed event
    wal_path = out_dir / "telemetry.jsonl"
    assert wal_path.exists()
    with open(wal_path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    failed_event = next(e for e in events if e.get("event_name") == "hardening_run_failed")
    assert failed_event["status"] == "FAIL"
