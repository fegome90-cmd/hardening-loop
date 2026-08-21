"""Tests for CLI UX enhancements: JSON output, quiet mode, and POSIX exit codes."""

import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from unittest.mock import patch

import yaml

from hardening_loop.cli import main
from hardening_loop.schema_validator import SchemaValidationError


def test_cli_run_json_output():
    """`hardening-loop run --json` emits machine-readable JSON to stdout and returns 0."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["run", "--target", target, "--phase", "question", "--output", out_dir, "--json"])
        assert exit_code == 0
        output = f.getvalue().strip()
        data = json.loads(output)
        assert "canonical_evidence" in data
        assert data["canonical_evidence"]["phase"] == "question"
        assert data["runtime_receipt"]["status"] == "PASS"


def test_cli_run_all_json_output():
    """`hardening-loop run --phase all --json` emits manifest JSON with canonical digest to stdout."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["run", "--target", target, "--phase", "all", "--output", out_dir, "--json"])
        assert exit_code == 0
        output = f.getvalue().strip()
        data = json.loads(output)
        assert "canonical_manifest_digest" in data
        assert "work_unit" in data
        assert "envelopes" in data
        assert len(data["envelopes"]) == 5


def test_cli_run_verbose_mode_and_directory_target():
    """`hardening-loop run` prints banners and phase status on directory target."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "hardening_loop"))
    with tempfile.TemporaryDirectory() as out_dir:
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["run", "--target", target, "--phase", "all", "--output", out_dir])
        assert exit_code == 0
        output = f.getvalue()
        assert "=== Algorithmic Code Hardening Loop" in output
        assert "[QUESTION]" in output
        assert "[DELETE]" in output
        assert "[SIMPLIFY]" in output
        assert "[VERIFY]" in output
        assert "[CODIFY]" in output


def test_cli_run_individual_phase_non_json():
    """`hardening-loop run --phase simplify` without json."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["run", "--target", target, "--phase", "simplify", "--output", out_dir])
        assert exit_code == 0
        output = f.getvalue()
        assert "[SIMPLIFY]" in output


def test_cli_run_quiet_mode():
    """`hardening-loop run -q` suppresses verbose banners and only emits summary."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["run", "--target", target, "--phase", "question", "--output", out_dir, "-q"])
        assert exit_code == 0
        output = f.getvalue().strip()
        assert "=== Algorithmic Code Hardening Loop" not in output
        assert "PASS" in output


def test_cli_nonexistent_target_returns_code_1():
    """Target path that does not exist returns exit code 1."""
    with tempfile.TemporaryDirectory() as out_dir:
        exit_code = main(["run", "--target", "/non/existent/path.py", "--output", out_dir])
        assert exit_code == 1


def test_cli_review_admit_and_reject():
    """`hardening-loop review` supports both admit and reject decisions."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        candidate_file = os.path.join(out_dir, "knowledge_candidate.yaml")

        # Admit
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["review", candidate_file, "--admit", "--reviewer", "arch-lead", "--json"])
        assert exit_code == 0
        data = json.loads(f.getvalue().strip())
        assert data["decision"] == "ACCEPTED"

        # Reject
        f2 = io.StringIO()
        with redirect_stdout(f2):
            exit_code = main(
                ["review", candidate_file, "--reject", "--reviewer", "security-lead", "--notes", "Too broad", "-q"]
            )
        assert exit_code == 0


def test_cli_review_single_dict_yaml():
    """`hardening-loop review` handles single candidate YAML object."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        candidate_file = os.path.join(out_dir, "knowledge_candidate.yaml")

        with open(candidate_file) as f:
            items = yaml.safe_load(f)
        single_candidate = items[0]
        with open(candidate_file, "w") as f:
            yaml.dump(single_candidate, f)

        exit_code = main(["review", candidate_file, "--admit", "--reviewer", "lead"])
        assert exit_code == 0


def test_cli_review_nonexistent_file_returns_code_1():
    """Reviewing missing candidate file returns code 1."""
    exit_code = main(["review", "/non/existent/candidate.yaml", "--admit", "--reviewer", "lead"])
    assert exit_code == 1


def test_cli_schema_validation_error_returns_code_2():
    """Schema validation errors trigger exit code 2 (Fail-Closed)."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        with patch(
            "hardening_loop.cli.HardeningRunner.run_all",
            side_effect=SchemaValidationError("evidence_envelope", ["Corrupted field hash"]),
        ):
            exit_code = main(["run", "--target", target, "--phase", "all", "--output", out_dir])
            assert exit_code == 2


def test_cli_review_schema_validation_error_returns_code_2():
    """Schema validation errors in review trigger code 2."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        candidate_file = os.path.join(out_dir, "knowledge_candidate.yaml")
        with patch(
            "hardening_loop.admission.KnowledgeAdmissionGate.review_candidate",
            side_effect=SchemaValidationError("knowledge_candidate", ["Missing field"]),
        ):
            exit_code = main(["review", candidate_file, "--admit", "--reviewer", "lead"])
            assert exit_code == 2


def test_cli_generic_exception_returns_code_1():
    """Generic exceptions in run trigger code 1."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        with patch(
            "hardening_loop.cli.HardeningRunner.run_all",
            side_effect=RuntimeError("Unexpected OS error"),
        ):
            exit_code = main(["run", "--target", target, "--phase", "all", "--output", out_dir])
            assert exit_code == 1
