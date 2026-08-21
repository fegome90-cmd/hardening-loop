"""Tests for Tier 2 Fail-Closed JSON Schema Validation."""

import pytest
from hardening_loop.models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    HardeningState,
    KnowledgeCandidate,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    WorkUnit,
    compute_execution_context_hash,
    utc_now_iso,
)
from hardening_loop.schema_validator import SchemaValidationError, SchemaValidator


def test_valid_evidence_envelope_schema_passes():
    payload = {"test_metric": 42}
    canonical = CanonicalEvidence(
        evidence_id="evi-112233445566",
        phase=PhaseName.VERIFY,
        input_hash="a" * 64,
        output_hash="b" * 64,
        method_version="v0.3",
        schema_version="v0.1-beta",
        execution_context_hash="c" * 64,
        artifact_payload=payload,
    )
    runtime = RuntimeReceipt(
        producer="hardening-loop:verify:0.1.0-beta",
        timestamp=utc_now_iso(),
        duration_ms=1.23,
        checks=["check 1"],
        status=VerificationStatus.PASS,
    )
    env = EvidenceEnvelope(canonical=canonical, runtime=runtime)
    SchemaValidator.validate_or_raise("evidence_envelope", env.to_dict())


def test_invalid_evidence_envelope_hash_fails_closed():
    payload = {"test_metric": 42}
    invalid_env = {
        "canonical_evidence": {
            "evidence_id": "evi-112233445566",
            "phase": "verify",
            "input_hash": "invalid-hash-too-short",
            "output_hash": "b" * 64,
            "method_version": "v0.3",
            "schema_version": "v0.1-beta",
            "execution_context_hash": "c" * 64,
            "artifact_payload": payload,
        },
        "runtime_receipt": {
            "producer": "hardening-loop:verify:0.1.0-beta",
            "timestamp": utc_now_iso(),
            "duration_ms": 1.23,
            "checks": ["check 1"],
            "status": "PASS",
        }
    }
    with pytest.raises(SchemaValidationError) as excinfo:
        SchemaValidator.validate_or_raise("evidence_envelope", invalid_env)
    assert "input_hash" in str(excinfo.value)


def test_valid_work_unit_schema_passes():
    wu = WorkUnit(
        work_unit_id="wu-112233445566",
        target_path="src/hardening_loop",
        target_hash="f" * 64,
        state=HardeningState.DRAFT,
        phases_executed=["question", "delete"],
        metadata={"author": "Felipe"},
    )
    SchemaValidator.validate_or_raise("work_unit", wu.to_dict())


def test_invalid_work_unit_state_fails_closed():
    raw_wu = {
        "work_unit_id": "wu-112233445566",
        "target_path": "src/",
        "target_hash": "f" * 64,
        "state": "INVALID_STATE",
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "phases_executed": [],
        "metadata": {},
    }
    with pytest.raises(SchemaValidationError) as excinfo:
        SchemaValidator.validate_or_raise("work_unit", raw_wu)
    assert "state" in str(excinfo.value)
