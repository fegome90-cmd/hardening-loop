"""Tests for audit precision, fail-closed enforcement, exact AST attribution, and timestamps."""

import os
import tempfile

from hardening_loop.admission import KnowledgeAdmissionGate
from hardening_loop.models import FindingCategory, FindingSeverity, VerificationStatus
from hardening_loop.phases import DeletePhase, SimplifyPhase, VerifyPhase


def test_verify_phase_fails_closed_on_critical_security_violation():
    """`VerifyPhase` must report `FAIL` if a CRITICAL check fails (Ley VIII)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_file = os.path.join(tmp_dir, "unsafe.py")
        with open(bad_file, "w") as f:
            f.write("import os\nos.system('rm -rf ' + user_input)\n")

        phase = VerifyPhase()
        payload, checks, status = phase.execute(bad_file, {})
        assert status == VerificationStatus.FAIL
        assert payload["test_results"]["failed_checks"] > 0


def test_verify_phase_passes_on_clean_external_target():
    """`VerifyPhase` must not fail clean external targets due to missing framework strings."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        clean_file = os.path.join(tmp_dir, "clean_math.py")
        with open(clean_file, "w") as f:
            f.write("def add(a: int, b: int) -> int:\n    return a + b\n")

        phase = VerifyPhase()
        payload, checks, status = phase.execute(clean_file, {})
        assert status == VerificationStatus.PASS
        assert payload["test_results"]["failed_checks"] == 0


def test_deletion_candidates_have_exact_file_and_line_attribution():
    """`DeletePhase` must attribute deletion candidates to exact `file:line` locations."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_file = os.path.join(tmp_dir, "harness.py")
        with open(target_file, "w") as f:
            f.write("import subprocess\n\ndef run_cmd(cmd):\n    subprocess.run(cmd, shell=True)\n")

        phase = DeletePhase()
        payload, checks, status = phase.execute(target_file, {})
        candidates = payload.get("deletion_candidates", [])
        assert len(candidates) > 0
        for cand in candidates:
            assert "location" in cand
            assert ":" in cand["location"]
            assert os.path.basename(target_file) in cand["location"]


def test_simplify_phase_infers_actual_function_contracts():
    """`SimplifyPhase` must not claim external functions return `EvidenceEnvelope`."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_file = os.path.join(tmp_dir, "external_service.py")
        with open(target_file, "w") as f:
            f.write("def run(cmd: str) -> int:\n    return 42\n")

        phase = SimplifyPhase()
        payload, checks, status = phase.execute(target_file, {})
        contracts = payload.get("contract_analysis", [])
        for c in contracts:
            assert "EvidenceEnvelope" not in c.get("observation", "")


def test_knowledge_candidate_timestamp_is_recent_utc():
    """`KnowledgeCandidate` must have real UTC timestamp, never epoch 1970."""
    candidate = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-1234567890ab",
        observation="Deterministic hashing observation",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        finding_description="Missing deterministic sort_keys",
        target_lines=[1, 2],
        rule_id="RULE-SEC-001",
        rule_title="Deterministic Hashing Rule",
        enforcement_mechanism="SCHEMA_GUARD",
        rationale="Guarantees SHA-256 stability",
        evidence_references=["evi-1234567890ab"],
    )
    assert not candidate.created_at.startswith("1970-01-01")
    assert "T" in candidate.created_at
