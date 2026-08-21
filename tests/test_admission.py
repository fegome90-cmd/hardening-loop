"""Tests for Knowledge Admission Gate (Aduana de Conocimiento)."""

import pytest
from hardening_loop.admission import KnowledgeAdmissionError, KnowledgeAdmissionGate
from hardening_loop.models import (
    AdmissionStatus,
    FindingCategory,
    FindingSeverity,
)


def test_candidate_creation_defaults_to_pending_review():
    c = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-test-01",
        observation="Found unvalidated tool call parameter in handler.",
        category=FindingCategory.CONTRACT_BREACH,
        severity=FindingSeverity.HIGH,
        finding_description="Missing schema validation for params dict.",
        target_lines=[10, 11],
        rule_id="RULE-VAL-001",
        rule_title="Validate Tool Call Parameters",
        enforcement_mechanism="SCHEMA_GUARD",
        rationale="Prevents unhandled runtime KeyError exceptions.",
        evidence_references=["evi-12345678"],
    )
    assert c.admission_status == AdmissionStatus.PENDING_REVIEW
    assert c.reviewer is None
    assert c.reviewed_at is None


def test_admission_review_acceptance():
    c = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-test-02",
        observation="Command injection vulnerability detected.",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.CRITICAL,
        finding_description="Direct execution of shell string.",
        target_lines=[50],
        rule_id="RULE-SEC-002",
        rule_title="Use Parameterized Subprocess",
        enforcement_mechanism="CONTRACT_VALIDATOR",
        rationale="Prevents command injection.",
        evidence_references=["evi-87654321"],
    )

    reviewed = KnowledgeAdmissionGate.review_candidate(
        c,
        decision=AdmissionStatus.ACCEPTED,
        reviewer="lead-architect",
        notes="Validated against security policy.",
    )
    assert reviewed.admission_status == AdmissionStatus.ACCEPTED
    assert reviewed.reviewer == "lead-architect"
    assert reviewed.reviewed_at is not None


def test_admission_requires_reviewer():
    c = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-test-03",
        observation="Missing docstring.",
        category=FindingCategory.UNCLEAR_INTERFACE,
        severity=FindingSeverity.LOW,
        finding_description="No docstrings on internal helper.",
        target_lines=[5],
        rule_id="RULE-DOC-001",
        rule_title="Enforce Docstrings",
        enforcement_mechanism="LINTER",
        rationale="Code clarity.",
        evidence_references=[],
    )

    with pytest.raises(KnowledgeAdmissionError):
        KnowledgeAdmissionGate.review_candidate(
            c,
            decision=AdmissionStatus.ACCEPTED,
            reviewer="",  # Missing reviewer must fail
        )


def test_yaml_export_and_load_roundtrip():
    c = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-test-04",
        observation="Observation text",
        category=FindingCategory.DEAD_HARNESS,
        severity=FindingSeverity.MEDIUM,
        finding_description="Finding description",
        target_lines=[1, 2, 3],
        rule_id="RULE-CLN-001",
        rule_title="Clean Harness",
        enforcement_mechanism="LINTER",
        rationale="Rationale text",
        evidence_references=["evi-00001111"],
    )
    yaml_str = KnowledgeAdmissionGate.export_candidate_yaml(c)
    loaded = KnowledgeAdmissionGate.load_candidate_yaml(yaml_str)
    assert loaded.candidate_id == c.candidate_id
    assert loaded.finding.category == c.finding.category
    assert loaded.rule_proposal.rule_id == c.rule_proposal.rule_id
