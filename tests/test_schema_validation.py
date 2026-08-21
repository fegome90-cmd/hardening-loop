"""Tests for Tier 2: Deterministic Fail-Closed JSON Schema Enforcement (Leyes VI y VIII)."""

import os
import tempfile

import pytest

from hardening_loop.admission import KnowledgeAdmissionGate
from hardening_loop.models import (
    EvidenceArtifact,
    EvidenceEnvelope,
    EvidenceVerification,
    FindingCategory,
    FindingSeverity,
    HardeningState,
    PhaseName,
    SchemaValidationError,
    VerificationStatus,
    WorkUnit,
    sha256_text,
    utc_now_iso,
)
from hardening_loop.runner import HardeningRunner
from hardening_loop.schema_validator import validate_payload


def test_valid_evidence_envelope_schema_passes():
    """Valid EvidenceEnvelope satisfies the normative schema."""
    envelope = EvidenceEnvelope(
        evidence_id="evi-1234567890ab",
        producer="hardening-loop:test:0.1.0",
        timestamp=utc_now_iso(),
        phase=PhaseName.QUESTION,
        input_hash=sha256_text("input"),
        output_hash=sha256_text("output"),
        artifact=EvidenceArtifact(
            path="/tmp/test_artifact.json",
            artifact_type="question_payload",
            payload={"key": "value"},
        ),
        verification=EvidenceVerification(
            passed=True,
            checks=["check 1", "check 2"],
            duration_ms=12.5,
        ),
        status=VerificationStatus.PASS,
    )
    # Should not raise
    envelope.validate_schema()


def test_invalid_evidence_envelope_hash_fails_closed():
    """EvidenceEnvelope with non-SHA256 hash pattern must fail closed."""
    envelope_data = {
        "evidence_id": "evi-1234567890ab",
        "producer": "hardening-loop:test:0.1.0",
        "timestamp": utc_now_iso(),
        "phase": "question",
        "input_hash": "invalid-short-hash",  # Not 64 hex chars
        "output_hash": sha256_text("output"),
        "artifact": {
            "path": "/tmp/test.json",
            "artifact_type": "test",
            "payload": {},
        },
        "verification": {
            "passed": True,
            "checks": [],
            "duration_ms": 5.0,
            "error": None,
        },
        "status": "PASS",
        "method_version": "v0.3",
        "environment_hash": sha256_text("env"),
    }

    with pytest.raises(SchemaValidationError) as excinfo:
        validate_payload(envelope_data, "evidence_envelope")

    assert "input_hash" in str(excinfo.value)
    assert "[FAIL-CLOSED]" in str(excinfo.value)


def test_invalid_evidence_envelope_id_pattern_fails_closed():
    """EvidenceEnvelope with invalid evidence_id prefix fails closed."""
    envelope_data = {
        "evidence_id": "wrong_prefix_123",  # Missing 'evi-' prefix or invalid pattern
        "producer": "hardening-loop:test:0.1.0",
        "timestamp": utc_now_iso(),
        "phase": "question",
        "input_hash": sha256_text("input"),
        "output_hash": sha256_text("output"),
        "artifact": {
            "path": "/tmp/test.json",
            "artifact_type": "test",
            "payload": {},
        },
        "verification": {
            "passed": True,
            "checks": [],
            "duration_ms": 5.0,
            "error": None,
        },
        "status": "PASS",
        "method_version": "v0.3",
        "environment_hash": sha256_text("env"),
    }

    with pytest.raises(SchemaValidationError) as excinfo:
        validate_payload(envelope_data, "evidence_envelope")

    assert "evidence_id" in str(excinfo.value)


def test_evidence_envelope_extra_properties_fails_closed():
    """EvidenceEnvelope with unauthorized properties fails closed (additionalProperties: false)."""
    envelope_data = {
        "evidence_id": "evi-1234567890ab",
        "producer": "hardening-loop:test:0.1.0",
        "timestamp": utc_now_iso(),
        "phase": "question",
        "input_hash": sha256_text("input"),
        "output_hash": sha256_text("output"),
        "artifact": {
            "path": "/tmp/test.json",
            "artifact_type": "test",
            "payload": {},
        },
        "verification": {
            "passed": True,
            "checks": [],
            "duration_ms": 5.0,
            "error": None,
        },
        "status": "PASS",
        "method_version": "v0.3",
        "environment_hash": sha256_text("env"),
        "unauthorized_extra_field": "slop",  # Extra property
    }

    with pytest.raises(SchemaValidationError) as excinfo:
        validate_payload(envelope_data, "evidence_envelope")

    assert "unauthorized_extra_field" in str(excinfo.value) or "Additional properties are not allowed" in str(
        excinfo.value
    )


def test_valid_knowledge_candidate_schema_passes():
    """KnowledgeCandidate created via AdmissionGate satisfies schema."""
    candidate = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-abcdef123456",
        observation="Found unconstrained command execution",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.CRITICAL,
        finding_description="Subprocess called with unquoted user input",
        target_lines=[42, 43],
        rule_id="RULE-SEC-001",
        rule_title="Strict Command Whitelist",
        enforcement_mechanism="LINTER",
        rationale="Prevents arbitrary remote command injection",
        evidence_references=["evi-1234567890ab"],
    )
    # Should not raise
    candidate.validate_schema()


def test_invalid_knowledge_candidate_severity_fails_closed():
    """KnowledgeCandidate with invalid severity enum fails closed."""
    candidate_data = {
        "candidate_id": "kc-abcdef123456",
        "observation": "Observation",
        "finding": {
            "category": "SECURITY",
            "severity": "NON_EXISTENT_SEVERITY",  # Invalid enum
            "description": "Desc",
            "target_lines": [1],
        },
        "rule_proposal": {
            "rule_id": "RULE-001",
            "title": "Title",
            "enforcement_mechanism": "LINTER",
            "rationale": "Rationale",
        },
        "evidence_references": ["evi-1234567890ab"],
        "admission_status": "PENDING_REVIEW",
        "created_at": utc_now_iso(),
    }

    with pytest.raises(SchemaValidationError) as excinfo:
        validate_payload(candidate_data, "knowledge_candidate")

    assert "severity" in str(excinfo.value)


def test_valid_work_unit_schema_passes():
    """WorkUnit satisfies the normative schema."""
    work_unit = WorkUnit(
        work_unit_id="wu-1234567890ab",
        target_path="/Users/felipe/Developer/target.py",
        target_hash=sha256_text("code"),
        state=HardeningState.DRAFT,
        metadata={"author": "Felipe", "description": "Audit run"},
    )
    # Should not raise
    work_unit.validate_schema()


def test_invalid_work_unit_state_fails_closed():
    """WorkUnit with illegal state string fails closed."""
    wu_data = {
        "work_unit_id": "wu-1234567890ab",
        "target_path": "/path/to/target.py",
        "target_hash": sha256_text("target"),
        "state": "ILLEGAL_STATE",  # Not in enum
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "phases_executed": [],
        "metadata": {},
    }

    with pytest.raises(SchemaValidationError) as excinfo:
        validate_payload(wu_data, "work_unit")

    assert "state" in str(excinfo.value)


def test_hardening_runner_end_to_end_schema_validity():
    """End-to-end runner execution verifies all produced envelopes and work unit against schemas."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as temp_out:
        runner = HardeningRunner(target_path=target, output_dir=temp_out)
        envelopes = runner.run_all()
        assert len(envelopes) == 5
        for env in envelopes:
            env.validate_schema()
        runner.work_unit.validate_schema()
