"""Tests for HardeningState lifecycle and StateMachine transition rules."""

import pytest

from hardening_loop.models import HardeningState, WorkUnit
from hardening_loop.states import InvalidStateTransitionError, StateMachine


def test_valid_state_transitions():
    wu = WorkUnit(
        work_unit_id="wu-test-01",
        target_path="/fake/path.py",
        target_hash="a" * 64,
        state=HardeningState.DRAFT,
    )
    assert wu.state == HardeningState.DRAFT

    # DRAFT -> AUDITING
    StateMachine.transition(wu, HardeningState.AUDITING, "Audit started")
    assert wu.state == HardeningState.AUDITING

    # AUDITING -> PATCH_PROPOSED
    StateMachine.transition(wu, HardeningState.PATCH_PROPOSED, "Patches ready")
    assert wu.state == HardeningState.PATCH_PROPOSED

    # PATCH_PROPOSED -> VERIFIED
    StateMachine.transition(wu, HardeningState.VERIFIED, "Tests passed")
    assert wu.state == HardeningState.VERIFIED

    # VERIFIED -> KNOWLEDGE_CANDIDATE
    StateMachine.transition(wu, HardeningState.KNOWLEDGE_CANDIDATE, "Rule formulated")
    assert wu.state == HardeningState.KNOWLEDGE_CANDIDATE

    # KNOWLEDGE_CANDIDATE -> ADMITTED
    StateMachine.transition(wu, HardeningState.ADMITTED, "Approved by human reviewer")
    assert wu.state == HardeningState.ADMITTED

    # ADMITTED -> READY_FOR_PR_REVIEW
    StateMachine.transition(wu, HardeningState.READY_FOR_PR_REVIEW, "CI tests pass")
    assert wu.state == HardeningState.READY_FOR_PR_REVIEW

    # READY_FOR_PR_REVIEW -> CANONICAL
    StateMachine.transition(wu, HardeningState.CANONICAL, "Linter rule active")
    assert wu.state == HardeningState.CANONICAL

    # CANONICAL -> DEPRECATED
    StateMachine.transition(wu, HardeningState.DEPRECATED, "Superseded by new spec")
    assert wu.state == HardeningState.DEPRECATED


def test_invalid_state_transitions():
    wu = WorkUnit(
        work_unit_id="wu-test-02",
        target_path="/fake/path.py",
        target_hash="a" * 64,
        state=HardeningState.DRAFT,
    )

    # Cannot jump DRAFT -> VERIFIED
    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.VERIFIED)

    # Cannot jump DRAFT -> CANONICAL
    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.CANONICAL)

    # Move to AUDITING
    StateMachine.transition(wu, HardeningState.AUDITING)

    # Cannot jump AUDITING -> CANONICAL
    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.CANONICAL)
