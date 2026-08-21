"""Layer 3: Epistemic Invariants — Determinism, provenance governance, and admission laws."""

import json
import os
import tempfile

import pytest

from hardening_loop.admission import KnowledgeAdmissionError, KnowledgeAdmissionGate
from hardening_loop.models import (
    AdmissionStatus,
    FindingCategory,
    FindingSeverity,
    HardeningState,
    WorkUnit,
)
from hardening_loop.runner import HardeningRunner
from hardening_loop.states import InvalidStateTransitionError, StateMachine


def test_canonical_manifest_reproducibility():
    """Epistemic Invariant: sha256(canonical_manifest) run-A == run-B across independent executions."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "hardening_loop"))

    with tempfile.TemporaryDirectory() as out_a, tempfile.TemporaryDirectory() as out_b:
        runner_a = HardeningRunner(target_path=target, output_dir=out_a)
        runner_a.run_all()

        runner_b = HardeningRunner(target_path=target, output_dir=out_b)
        runner_b.run_all()

        with open(os.path.join(out_a, "evidence_manifest.json")) as f:
            manifest_a = json.load(f)
        with open(os.path.join(out_b, "evidence_manifest.json")) as f:
            manifest_b = json.load(f)

        # The canonical manifest digest MUST be bit-identical across runs
        assert manifest_a["canonical_manifest_digest"] == manifest_b["canonical_manifest_digest"]
        assert len(manifest_a["canonical_manifest_digest"]) == 64

        # Verify all individual canonical output hashes match
        envs_a = manifest_a["envelopes"]
        envs_b = manifest_b["envelopes"]
        assert len(envs_a) == len(envs_b) == 5

        for ea, eb in zip(envs_a, envs_b, strict=True):
            ca = ea["canonical_evidence"]
            cb = eb["canonical_evidence"]
            assert ca["evidence_id"] == cb["evidence_id"]
            assert ca["input_hash"] == cb["input_hash"]
            assert ca["output_hash"] == cb["output_hash"]
            assert ca["execution_context_hash"] == cb["execution_context_hash"]


def test_no_evidence_without_execution_context():
    """Epistemic Invariant: Evidence envelopes must declare execution context and method version."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "hardening_loop"))
    with tempfile.TemporaryDirectory() as out_dir:
        runner = HardeningRunner(target_path=target, output_dir=out_dir)
        envelopes = runner.run_all()
        for env in envelopes:
            assert len(env.canonical.execution_context_hash) == 64
            assert env.canonical.method_version == "v0.3"
            assert env.canonical.schema_version == "v0.1-beta"


def test_admission_requires_human_reviewer_assertion():
    """Epistemic Invariant: Knowledge Admission Gate rejects empty or unauthenticated reviewer assertions."""
    c = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-abcdef123456",
        observation="Test observation",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        finding_description="Test description",
        target_lines=[1],
        rule_id="RULE-EPI-001",
        rule_title="Epistemic Review",
        enforcement_mechanism="CONTRACT_VALIDATOR",
        rationale="Testing reviewer enforcement",
        evidence_references=["evi-abcdef123456"],
    )

    # Empty reviewer assertion must fail closed
    with pytest.raises(KnowledgeAdmissionError):
        KnowledgeAdmissionGate.review_candidate(c, AdmissionStatus.ACCEPTED, reviewer="")

    with pytest.raises(KnowledgeAdmissionError):
        KnowledgeAdmissionGate.review_candidate(c, AdmissionStatus.ACCEPTED, reviewer="   ")


def test_no_canonical_state_without_admission_phase():
    """Epistemic Invariant: WorkUnit cannot reach CANONICAL without transitioning through ADMITTED."""
    wu = WorkUnit(work_unit_id="wu-epistemic-01", target_path="src/", target_hash="a" * 64, state=HardeningState.DRAFT)

    with pytest.raises(InvalidStateTransitionError):
        StateMachine.transition(wu, HardeningState.CANONICAL)
