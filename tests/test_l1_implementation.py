"""Layer 1: Implementation Tests — Unit functionality, parsers, and serializers."""

import tempfile

from hardening_loop.admission import KnowledgeAdmissionGate
from hardening_loop.cli import create_parser
from hardening_loop.models import (
    FindingCategory,
    FindingSeverity,
    compute_canonical_directory_digest,
    compute_execution_context_hash,
    sha256_text,
)


def test_cli_parser_subcommands():
    parser = create_parser()
    args_run = parser.parse_args(["run", "--target", "src/", "--phase", "all", "--output", "evidence/test"])
    assert args_run.command == "run"
    assert args_run.target == "src/"
    assert args_run.phase == "all"

    args_rev = parser.parse_args(
        ["review", "evidence/test/candidate.yaml", "--admit", "--reviewer", "arch-01", "--notes", "LGTM"]
    )
    assert args_rev.command == "review"
    assert args_rev.admit is True
    assert args_rev.reviewer == "arch-01"


def test_canonical_directory_digest():
    with tempfile.NamedTemporaryFile("w") as f:
        f.write("print('hello')\n")
        f.flush()
        d = compute_canonical_directory_digest(f.name)
        assert len(d) == 64
        assert d == sha256_text("print('hello')\n")


def test_execution_context_hash_generation():
    ctx_hash = compute_execution_context_hash()
    assert len(ctx_hash) == 64


def test_yaml_load_and_dump_integrity():
    c = KnowledgeAdmissionGate.create_candidate(
        candidate_id="kc-112233445566",
        observation="Test observation",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        finding_description="Test description",
        target_lines=[10, 20],
        rule_id="RULE-TEST-001",
        rule_title="Test Rule Title",
        enforcement_mechanism="LINTER",
        rationale="Test Rationale",
        evidence_references=["evi-112233445566"],
    )
    yaml_str = KnowledgeAdmissionGate.export_candidate_yaml(c)
    loaded = KnowledgeAdmissionGate.load_candidate_yaml(yaml_str)
    assert loaded.candidate_id == c.candidate_id
    assert loaded.rule_proposal.rule_id == "RULE-TEST-001"
