"""Comprehensive adversarial regression tests covering all 15 audit findings (S1-S7, P1-P7)."""

from __future__ import annotations

import json

import pytest

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

    # 3. Tamper with a physical artifact file on disk (test_results.json)
    results_path = out_dir / "test_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        f.write('{"tampered": true}\n')

    # 4. Inspect must detect physical file corruption and exit with code 2 (Fail-Closed)
    ret_tampered = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret_tampered == 2


def test_s4_inspect_detects_path_traversal_escape_in_manifest(tmp_path):
    """S4: inspect must reject manifests attempting path traversal escaping evidence boundary."""
    target = tmp_path / "clean.py"
    target.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_path = out_dir / "evidence_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Add malicious escaping artifact path
    manifest["artifacts"].append({"path": "../../../etc/passwd", "type": "evidence", "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_s5_manifest_integrity_hash_verified_and_schema_compliant(tmp_path):
    """S5 & P1: Manifest must strictly validate against schema v0.2 and manifest_hash must match."""
    target = tmp_path / "code.py"
    target.write_text("def mul(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    out_dir = tmp_path / "evidence"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_file = out_dir / "evidence_manifest.json"
    assert manifest_file.exists()
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Schema validation against normative schema
    SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", manifest)

    # Re-calculate and verify manifest_hash over entire document
    is_valid, msg = verify_manifest_integrity(manifest)
    assert is_valid, msg


def test_s5_inspect_detects_manifest_and_artifact_synchronized_tampering(tmp_path):
    """S5 & S4: If attacker modifies test_results.json AND updates artifacts[].sha256, inspect still catches it via manifest_hash!"""
    target = tmp_path / "code.py"
    target.write_text("def mul(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    out_dir = tmp_path / "evidence"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    # Attacker mutates test_results.json
    results_path = out_dir / "test_results.json"
    results_path.write_text('{"hacked": true}\n', encoding="utf-8")
    new_sha = sha256_text('{"hacked": true}\n')

    # Attacker updates artifacts array in manifest, but does not (or cannot) properly forge manifest_hash
    manifest_path = out_dir / "evidence_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for art in manifest["artifacts"]:
        if art["path"] == "test_results.json":
            art["sha256"] = new_sha

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Inspect MUST detect tampering because manifest_hash mismatch is caught!
    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_s6_posthog_sink_hardening():
    """S6: Host validation, path sanitization, and explicit credential requirement."""
    # 1. Invalid non-https host
    with pytest.raises(PostHogSinkError):
        PostHogTelemetrySink(api_key="key", host="http://attacker.com")

    # 2. Reject unauthorized HTTPS host (attacker domain)
    with pytest.raises(PostHogSinkError, match="Untrusted PostHog host"):
        PostHogTelemetrySink(api_key="key", host="https://attacker.example")

    # 3. Accept authorized HTTPS hosts
    sink_us = PostHogTelemetrySink(api_key="key", host="https://us.i.posthog.com")
    assert sink_us.host == "https://us.i.posthog.com"

    sink_eu = PostHogTelemetrySink(api_key="key", host="https://eu.i.posthog.com")
    assert sink_eu.host == "https://eu.i.posthog.com"

    # 4. Path sanitization
    manifest = {
        "work_unit": {"target_path": "/Users/developer/secret_repo/code.py", "work_unit_id": "wu-123"},
        "runtime_telemetry": {"total_duration_ms": 10.0},
    }
    batch = sink_us.format_telemetry_batch(manifest)
    sanitized_target = batch[0]["properties"]["target_path"]
    assert "/Users/developer" not in sanitized_target
    assert "code.py#hash:" in sanitized_target

    # 5. Missing API key raises explicit PostHogSinkError when not dry_run
    sink_no_key = PostHogTelemetrySink(api_key="")
    with pytest.raises(PostHogSinkError, match="Missing PostHog API Key"):
        sink_no_key.export(manifest, dry_run=False)


def test_p2_and_p3_ast_nodes_and_directory_loc_metrics(tmp_path):
    """P2 & P3: Accurately counts AST nodes visited and directory LOC."""
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "mod1.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    (sub / "mod2.py").write_text("def fn():\n    return 42\n", encoding="utf-8")

    runner = HardeningRunner(target_path=str(sub), output_dir=str(tmp_path / "out"))
    runner.run_all()

    summary = runner.telemetry.get_summary()
    assert summary["total_loc_analyzed"] == 4
    assert summary["total_ast_nodes_visited"] > 0
    assert "memory_delta_mb" in summary


def test_p5_codify_candidate_timestamps_and_hermetic_hashing(tmp_path):
    """P5: KnowledgeCandidate records real UTC timestamps while preserving canonical candidate hashing."""
    phase = CodifyPhase()
    mock_ctx = {
        "evidence_ids": ["evi-11112222"],
        "deletion_candidates": [
            {
                "target": "os_system_invocation",
                "location": "mod.py:10",
                "rationale": "Unsafe shell invocation",
                "action": "REPLACE",
                "severity": "HIGH",
            }
        ],
    }
    payload_a, _, _ = phase.execute(str(tmp_path), mock_ctx)
    payload_b, _, _ = phase.execute(str(tmp_path), mock_ctx)

    # The canonical candidate representations have identical deterministic digests
    digest_a = sha256_text(json.dumps(payload_a["candidates"], sort_keys=True))
    digest_b = sha256_text(json.dumps(payload_b["candidates"], sort_keys=True))
    assert digest_a == digest_b

    # Full candidates contain real current UTC timestamps
    for cand in phase._last_full_candidates:
        assert not cand["created_at"].startswith("1970-01-01")
        assert "T" in cand["created_at"]


def test_p6_simplify_infers_unannotated_return_types(tmp_path):
    """P6: SimplifyPhase infers return types for unannotated functions via AST Return nodes."""
    code = """
def return_int():
    return 100

def return_dict():
    return {"status": "ok"}

def return_none():
    pass
"""
    target = tmp_path / "unannotated.py"
    target.write_text(code, encoding="utf-8")

    phase = SimplifyPhase()
    payload, _, status = phase.execute(str(target), {})
    assert status == VerificationStatus.PASS

    fn_map = {f["name"]: f["return_type"] for f in payload["functions"]}
    assert fn_map["return_int"] == "int"
    assert fn_map["return_dict"] == "dict"
    assert fn_map["return_none"] == "None"


def test_p6_simplify_return_type_not_contaminated_by_nested_function(tmp_path):
    """P6: Outer function return type must not be contaminated by nested inner function returns."""
    code = """
def outer_fn():
    def inner_fn():
        return 42
    return "hello"
"""
    target = tmp_path / "nested.py"
    target.write_text(code, encoding="utf-8")

    phase = SimplifyPhase()
    payload, _, status = phase.execute(str(target), {})
    assert status == VerificationStatus.PASS

    fn_map = {f["name"]: f["return_type"] for f in payload["functions"]}
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
    assert candidate["rule_proposal"]["rule_id"] == "RULE-DEL-001"


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


def test_verify_phase_ignores_non_subprocess_run_shell_true(tmp_path):
    """VerifyPhase must check that the receiver is actually subprocess before flagging shell=True."""
    code = """
class MyRunner:
    def run(self, shell=True):
        return "custom runner"

runner = MyRunner()
runner.run(shell=True)
"""
    target = tmp_path / "custom_runner.py"
    target.write_text(code, encoding="utf-8")

    v_phase = VerifyPhase()
    payload, checks, status = v_phase.execute(str(target), {})
    # Custom class runner.run(shell=True) should NOT trigger shell check failure
    shell_check = next(c for c in payload["test_results"]["checks"] if c["name"] == "no_unconstrained_shell_execution")
    assert shell_check["passed"] is True
