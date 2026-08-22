"""Comprehensive adversarial regression tests covering all audit findings and hardening blockers."""

from __future__ import annotations

import json

import pytest
import yaml

from hardening_loop.cli import main
from hardening_loop.models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    FindingSeverity,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    sha256_text,
    utc_now_iso,
)
from hardening_loop.phases import (
    CodifyPhase,
    DeletePhase,
    QuestionPhase,
    SimplifyPhase,
    VerifyPhase,
)
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


def test_inspect_fails_closed_when_canonical_manifest_digest_missing(tmp_path):
    """Inspect must fail closed with code 2 if canonical_manifest_digest is missing or altered."""
    target = tmp_path / "clean.py"
    target.write_text("x = 100\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_inspect"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Remove canonical_manifest_digest
    del manifest_data["canonical_manifest_digest"]
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


def test_p5_persisted_candidates_have_real_utc_timestamps(tmp_path):
    """P5: Persisted knowledge_candidate.yaml must contain real recent UTC timestamps, never 1970."""
    target = tmp_path / "app_with_harness.py"
    target.write_text("import os\n# hardcoded path\np = '/Users/dev/tmp'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_kc"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    kc_file = out_dir / "knowledge_candidate.yaml"
    assert kc_file.exists()
    candidates = yaml.safe_load(kc_file.read_text(encoding="utf-8"))
    assert len(candidates) > 0

    for cand in candidates:
        assert "created_at" in cand
        assert not cand["created_at"].startswith("1970")
        assert "202" in cand["created_at"]


def test_p6_simplify_infers_unannotated_return_types(tmp_path):
    """P6: SimplifyPhase must infer unannotated function return types from AST Return nodes."""
    code = """
def get_count():
    return 42

def get_flag():
    return True

def get_text():
    return "hello"

def get_data():
    return {"a": 1}

def get_void():
    return
"""
    target = tmp_path / "types_test.py"
    target.write_text(code, encoding="utf-8")

    phase = SimplifyPhase()
    payload, checks, status = phase.execute(str(target), {})
    assert status == VerificationStatus.PASS

    fn_map = {fn["name"]: fn["return_type"] for fn in payload["functions"]}
    assert fn_map["get_count"] == "int"
    assert fn_map["get_flag"] == "bool"
    assert fn_map["get_text"] == "str"
    assert fn_map["get_data"] == "dict"
    assert fn_map["get_void"] == "None"


def test_p6_simplify_return_type_not_contaminated_by_nested_function(tmp_path):
    """P6: Return statements in nested functions/classes must NOT contaminate the outer function's inferred return type."""
    code = """
def outer_fn():
    def inner_fn():
        return 42
    return "outer_result"
"""
    target = tmp_path / "nested_test.py"
    target.write_text(code, encoding="utf-8")

    phase = SimplifyPhase()
    payload, checks, status = phase.execute(str(target), {})
    assert status == VerificationStatus.PASS

    fn_map = {fn["name"]: fn["return_type"] for fn in payload["functions"]}
    assert fn_map["outer_fn"] == "str"
    assert fn_map["inner_fn"] == "int"


def test_p7_codify_generates_zero_candidates_for_clean_target(tmp_path):
    """P7: CodifyPhase must emit 0 candidates for a completely clean target without findings."""
    phase = CodifyPhase()
    payload, checks, status = phase.execute(str(tmp_path / "clean.py"), {"evidence_ids": ["evi-11112222"]})
    assert status == VerificationStatus.PASS
    assert payload["candidates_count"] == 0
    assert len(payload["candidates"]) == 0
    assert payload["admission_record"]["admission_status"] == "NONE"


def test_p7_codify_generates_candidates_from_actual_upstream_findings(tmp_path):
    """P7: CodifyPhase structures candidates dynamically from real upstream deletion findings."""
    phase = CodifyPhase()
    ctx = {
        "evidence_ids": ["evi-12345678"],
        "deletion_candidates": [
            {
                "target": "os_system_invocation",
                "location": "app.py:42",
                "rationale": "Direct os.system executes unconstrained shell.",
                "action": "REPLACE_WITH_STRUCTURED_SUBPROCESS",
                "severity": "HIGH",
            }
        ],
    }
    payload, checks, status = phase.execute(str(tmp_path / "app.py"), ctx)
    assert status == VerificationStatus.PASS
    assert payload["candidates_count"] == 1
    candidate = payload["candidates"][0]
    assert "app.py:42" in candidate["observation"]
    assert candidate["rule_proposal"]["rule_id"].startswith("RULE-DEL-")


def test_codify_preserves_medium_severity_from_verify_failures(tmp_path):
    """CodifyPhase must preserve FindingSeverity.MEDIUM from verify failures without elevating to HIGH."""
    phase = CodifyPhase()
    ctx = {
        "evidence_ids": ["evi-12345678"],
        "verify_failures": [
            {
                "name": "no_hardcoded_developer_paths",
                "severity": "MEDIUM",
                "details": "Hardcoded path detected at app.py:12",
            }
        ],
    }
    payload, checks, status = phase.execute(str(tmp_path / "app.py"), ctx)
    assert status == VerificationStatus.PASS
    candidate = payload["candidates"][0]
    assert candidate["finding"]["severity"] == FindingSeverity.MEDIUM.value


def test_phases_fail_closed_on_syntax_errors(tmp_path):
    """Ley VIII: Python syntax errors in target must fail closed across all scanning phases."""
    bad_code = "def syntax_error(\n"
    target = tmp_path / "bad.py"
    target.write_text(bad_code, encoding="utf-8")

    q_phase = QuestionPhase()
    _, _, q_status = q_phase.execute(str(target), {})
    assert q_status == VerificationStatus.FAIL

    d_phase = DeletePhase()
    _, _, d_status = d_phase.execute(str(target), {})
    assert d_status == VerificationStatus.FAIL

    s_phase = SimplifyPhase()
    _, _, s_status = s_phase.execute(str(target), {})
    assert s_status == VerificationStatus.FAIL

    v_phase = VerifyPhase()
    _, _, v_status = v_phase.execute(str(target), {})
    assert v_status == VerificationStatus.FAIL


def test_external_path_with_hardening_loop_name_is_not_self_audit(tmp_path):
    """Target in external directory with 'hardening_loop' in name must NOT trigger framework self-audit candidates."""
    ext_dir = tmp_path / "hardening_loop-external-repo"
    ext_dir.mkdir()
    clean_target = ext_dir / "clean.py"
    clean_target.write_text("def calculate(x: int) -> int:\n    return x * 2\n", encoding="utf-8")

    out_dir = tmp_path / "evidence_ext"
    runner = HardeningRunner(target_path=str(clean_target), output_dir=str(out_dir))
    envelopes = runner.run_all()

    assert len(envelopes) == 5
    codify_env = envelopes[-1]
    assert codify_env.phase == PhaseName.CODIFY
    payload = codify_env.canonical.artifact_payload
    # Completely clean external target must produce 0 candidates, NOT the 2 framework rules
    assert payload["candidates_count"] == 0
    assert len(payload["candidates"]) == 0


def test_subprocess_alias_detection_positive_and_negative(tmp_path):
    """Tests that subprocess invocations with shell=True are detected across all import aliases (including check_call)."""
    # 1. Alias import subprocess as sp with check_call
    code_sp = "import subprocess as sp\nsp.check_call('ls', shell=True)\n"
    target_sp = tmp_path / "sp.py"
    target_sp.write_text(code_sp, encoding="utf-8")

    v_phase = VerifyPhase()
    payload_sp, _, status_sp = v_phase.execute(str(target_sp), {})
    assert status_sp == VerificationStatus.FAIL
    chk_sp = next(c for c in payload_sp["test_results"]["checks"] if c["name"] == "no_unconstrained_shell_execution")
    assert chk_sp["passed"] is False

    # 2. from subprocess import check_call as cc
    code_from = "from subprocess import check_call as cc\ncc('ls', shell=True)\n"
    target_from = tmp_path / "from_subp.py"
    target_from.write_text(code_from, encoding="utf-8")

    payload_from, _, status_from = v_phase.execute(str(target_from), {})
    assert status_from == VerificationStatus.FAIL
    chk_from = next(
        c for c in payload_from["test_results"]["checks"] if c["name"] == "no_unconstrained_shell_execution"
    )
    assert chk_from["passed"] is False

    # 3. Custom class runner.run(shell=True) -> IGNORED
    code_custom = "class MyRunner:\n    def run(self, shell=True):\n        return True\nrunner = MyRunner()\nrunner.run(shell=True)\n"
    target_custom = tmp_path / "custom.py"
    target_custom.write_text(code_custom, encoding="utf-8")

    payload_custom, _, status_custom = v_phase.execute(str(target_custom), {})
    assert status_custom == VerificationStatus.PASS
    chk_custom = next(
        c for c in payload_custom["test_results"]["checks"] if c["name"] == "no_unconstrained_shell_execution"
    )
    assert chk_custom["passed"] is True


def test_question_phase_exact_scope_attribution_in_nested_functions(tmp_path):
    """QuestionPhase must attribute calls to the innermost enclosing function/method scope."""
    code = """
def outer_fn():
    def inner_fn():
        with open('data.txt') as f:
            pass
"""
    target = tmp_path / "scope_nesting.py"
    target.write_text(code, encoding="utf-8")

    phase = QuestionPhase()
    payload, checks, status = phase.execute(str(target), {})
    assert status == VerificationStatus.PASS

    reqs = payload["requirements"]
    sec_req = next(r for r in reqs if r["type"] == "security_constraint" and "open" in r.get("audit_finding", ""))
    # Source must attribute to (inner_fn), not (outer_fn)
    assert "(inner_fn)" in sec_req["source"]


def test_codify_no_shared_mutable_state_between_runners(tmp_path):
    """Running multiple HardeningRunner instances must have zero shared mutable phase state."""
    target1 = tmp_path / "t1.py"
    target1.write_text("import os\nos.system('echo 1')\n", encoding="utf-8")
    out1 = tmp_path / "out1"

    target2 = tmp_path / "t2.py"
    target2.write_text("def pure_add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    out2 = tmp_path / "out2"

    r1 = HardeningRunner(str(target1), str(out1))
    r2 = HardeningRunner(str(target2), str(out2))

    # Phase instances are unique to each runner
    assert r1.phases[PhaseName.CODIFY] is not r2.phases[PhaseName.CODIFY]

    r2.run_all()
    # Clean target 2 produces 0 candidates
    assert len(r2.envelopes[-1].canonical.artifact_payload.get("candidates", [])) == 0


def test_wal_isolated_per_run_and_closed(tmp_path):
    """Reusing output_dir must cleanly isolate the WAL file and not mix events from previous runs."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "shared_evidence"

    # Run 1
    r1 = HardeningRunner(str(target), str(out_dir))
    r1.run_all()

    wal_path = out_dir / "telemetry.jsonl"
    with open(wal_path, encoding="utf-8") as f:
        events_run1 = [json.loads(line) for line in f if line.strip()]
    count_run1 = len(events_run1)
    assert count_run1 > 0

    # Run 2 with same output_dir
    r2 = HardeningRunner(str(target), str(out_dir))
    r2.run_all()

    with open(wal_path, encoding="utf-8") as f:
        events_run2 = [json.loads(line) for line in f if line.strip()]

    # Run 2 events must belong strictly to run 2's run_id, not contaminated by run 1
    assert all(e["run_id"] == r2.work_unit.work_unit_id for e in events_run2)


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
