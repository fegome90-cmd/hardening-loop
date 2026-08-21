"""Unit tests for individual hardening loop phases."""

import os
import tempfile

import pytest

from hardening_loop.models import PhaseName, VerificationStatus
from hardening_loop.phases import (
    CodifyPhase,
    DeletePhase,
    QuestionPhase,
    SimplifyPhase,
    VerifyPhase,
)

SAMPLE_CODE = """
#!/usr/bin/env python3
import subprocess

def execute(fn, params):
    \"\"\"Execute tool call.\"\"\"
    if fn == "bash":
        cmd = params.get("command", "")
        subprocess.run(["/bin/zsh", "-c", cmd], cwd="/Users/felipe_gonzalez/Developer/examen_grado")
    elif fn == "read":
        with open(params.get("file_path")) as f:
            return f.read()

def main():
    pass
"""


@pytest.fixture
def temp_target():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(SAMPLE_CODE)
        path = f.name
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_question_phase(temp_target):
    phase = QuestionPhase()
    with tempfile.TemporaryDirectory() as out_dir:
        envelope = phase.run(temp_target, {}, out_dir)
        assert envelope.phase == PhaseName.QUESTION
        assert envelope.status == VerificationStatus.PASS
        payload = envelope.artifact.payload
        assert payload["total_requirements_audited"] > 0


def test_delete_phase(temp_target):
    phase = DeletePhase()
    with tempfile.TemporaryDirectory() as out_dir:
        envelope = phase.run(temp_target, {}, out_dir)
        assert envelope.phase == PhaseName.DELETE
        assert envelope.status == VerificationStatus.PASS
        payload = envelope.artifact.payload
        assert payload["deletion_candidates_count"] >= 2
        assert "diff_patch" in payload
        assert "rollback_reference" in payload


def test_simplify_phase(temp_target):
    phase = SimplifyPhase()
    with tempfile.TemporaryDirectory() as out_dir:
        envelope = phase.run(temp_target, {}, out_dir)
        assert envelope.phase == PhaseName.SIMPLIFY
        assert envelope.status == VerificationStatus.PASS
        payload = envelope.artifact.payload
        assert payload["interfaces_audited"] >= 2


def test_verify_phase(temp_target):
    phase = VerifyPhase()
    with tempfile.TemporaryDirectory() as out_dir:
        envelope = phase.run(temp_target, {}, out_dir)
        assert envelope.phase == PhaseName.VERIFY
        assert envelope.status in (VerificationStatus.PASS, VerificationStatus.WARN)
        payload = envelope.artifact.payload
        assert "benchmark" in payload
        assert payload["benchmark"]["meets_fast_feedback_sla"] is True


def test_codify_phase(temp_target):
    phase = CodifyPhase()
    with tempfile.TemporaryDirectory() as out_dir:
        envelope = phase.run(temp_target, {"evidence_ids": ["evi-11112222"]}, out_dir)
        assert envelope.phase == PhaseName.CODIFY
        assert envelope.status == VerificationStatus.PASS
        payload = envelope.artifact.payload
        assert payload["candidates_count"] >= 2
        assert payload["admission_record"]["admission_status"] == "PENDING_REVIEW"
