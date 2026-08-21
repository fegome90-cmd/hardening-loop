"""Ontological invariant and hermetic reproducibility tests for the Hardening Loop."""

import os
import tempfile

import pytest

from hardening_loop.models import (
    HardeningState,
    compute_target_hash,
)
from hardening_loop.runner import HardeningRunner
from hardening_loop.states import InvalidStateTransitionError, StateMachine


def test_directory_target_merkle_hashing():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        # Create identical files in d1 and d2
        f1_path = os.path.join(d1, "mod.py")
        f2_path = os.path.join(d2, "mod.py")
        with open(f1_path, "w") as f:
            f.write("def foo(): return 42\n")
        with open(f2_path, "w") as f:
            f.write("def foo(): return 42\n")

        hash1 = compute_target_hash(d1)
        hash2 = compute_target_hash(d2)
        assert hash1 == hash2
        assert len(hash1) == 64

        # Mutate d2
        with open(f2_path, "a") as f:
            f.write("# mutation\n")
        hash2_mutated = compute_target_hash(d2)
        assert hash1 != hash2_mutated


def test_hermetic_reproducibility_run_a_vs_run_b():
    """Invariant: Two independent runs over the same codebase produce identical payload hashes."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "hardening_loop"))

    with tempfile.TemporaryDirectory() as out_a, tempfile.TemporaryDirectory() as out_b:
        runner_a = HardeningRunner(target_path=target, output_dir=out_a)
        envelopes_a = runner_a.run_all()

        runner_b = HardeningRunner(target_path=target, output_dir=out_b)
        envelopes_b = runner_b.run_all()

        assert len(envelopes_a) == len(envelopes_b) == 5

        # Output payload hashes must match bit-for-bit across all 5 phases
        for env_a, env_b in zip(envelopes_a, envelopes_b, strict=True):
            assert env_a.phase == env_b.phase
            assert env_a.output_hash == env_b.output_hash, f"Hash mismatch in phase {env_a.phase}"
            assert env_a.input_hash == env_b.input_hash
            assert env_a.method_version == env_b.method_version
            assert env_a.environment_hash == env_b.environment_hash


def test_admission_gate_bypass_prevention():
    """Invariant: A WorkUnit can never transition to ADMITTED or CANONICAL skipping review."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "hardening_loop"))
    runner = HardeningRunner(target_path=target, output_dir="/tmp/dummy")

    assert runner.work_unit.state == HardeningState.DRAFT

    # Attempt direct skip to ADMITTED
    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(runner.work_unit, HardeningState.ADMITTED)

    # Attempt direct skip to CANONICAL
    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(runner.work_unit, HardeningState.CANONICAL)


def test_envelope_provenance_schema_fields():
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "hardening_loop"))
    with tempfile.TemporaryDirectory() as out_dir:
        runner = HardeningRunner(target_path=target, output_dir=out_dir)
        envelopes = runner.run_all()
        for env in envelopes:
            d = env.to_dict()
            assert "method_version" in d
            assert "environment_hash" in d
            assert len(d["environment_hash"]) == 64
            assert d["method_version"] == "v0.3"
