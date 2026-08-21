"""Layer 2: Contract Invariants — State machine rules and fail-closed JSON schema enforcement."""

import pytest

from hardening_loop.models import HardeningState, WorkUnit
from hardening_loop.schema_validator import SchemaValidationError, SchemaValidator
from hardening_loop.states import InvalidStateTransitionError, StateMachine


def test_state_machine_valid_progression():
    wu = WorkUnit(work_unit_id="wu-01", target_path="src/", target_hash="0" * 64, state=HardeningState.DRAFT)
    assert wu.state == HardeningState.DRAFT

    StateMachine.transition(wu, HardeningState.AUDITING)
    assert wu.state == HardeningState.AUDITING

    StateMachine.transition(wu, HardeningState.PATCH_PROPOSED)
    assert wu.state == HardeningState.PATCH_PROPOSED

    StateMachine.transition(wu, HardeningState.VERIFIED)
    assert wu.state == HardeningState.VERIFIED

    StateMachine.transition(wu, HardeningState.KNOWLEDGE_CANDIDATE)
    assert wu.state == HardeningState.KNOWLEDGE_CANDIDATE

    StateMachine.transition(wu, HardeningState.ADMITTED)
    assert wu.state == HardeningState.ADMITTED

    StateMachine.transition(wu, HardeningState.READY_FOR_PR_REVIEW)
    assert wu.state == HardeningState.READY_FOR_PR_REVIEW

    StateMachine.transition(wu, HardeningState.CANONICAL)
    assert wu.state == HardeningState.CANONICAL

    StateMachine.transition(wu, HardeningState.DEPRECATED)
    assert wu.state == HardeningState.DEPRECATED


def test_state_machine_invalid_skips_fail_closed():
    wu = WorkUnit(work_unit_id="wu-02", target_path="src/", target_hash="0" * 64, state=HardeningState.DRAFT)

    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.CANONICAL)

    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.READY_FOR_PR_REVIEW)

    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.ADMITTED)


def test_envelope_schema_fail_closed():
    invalid_envelope = {
        "canonical_evidence": {
            "evidence_id": "invalid-pattern",
            "phase": "verify",
            "input_hash": "short",
            "output_hash": "a" * 64,
            "method_version": "v0.3",
            "schema_version": "v0.1-beta",
            "execution_context_hash": "a" * 64,
            "artifact_payload": {},
        },
        "runtime_receipt": {
            "producer": "test",
            "timestamp": "2026-08-21T00:00:00Z",
            "duration_ms": 1.0,
            "checks": [],
            "status": "PASS",
        },
    }
    with pytest.raises(SchemaValidationError):
        SchemaValidator.validate_or_raise("evidence_envelope", invalid_envelope)
