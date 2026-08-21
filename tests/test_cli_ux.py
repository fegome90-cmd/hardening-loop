"""Tests for CLI UX enhancements: JSON output, quiet mode, and POSIX exit codes."""

import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from unittest.mock import patch

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
    """`hardening-loop run --phase all --json` emits manifest JSON to stdout."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["run", "--target", target, "--phase", "all", "--output", out_dir, "--json"])
        assert exit_code == 0
        output = f.getvalue().strip()
        data = json.loads(output)
        assert "work_unit" in data
        assert "envelopes" in data
        assert len(data["envelopes"]) == 5


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


def test_cli_review_json_output():
    """`hardening-loop review --json` emits structured confirmation."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    with tempfile.TemporaryDirectory() as out_dir:
        # Generate candidates first
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        candidate_file = os.path.join(out_dir, "knowledge_candidate.yaml")
        assert os.path.exists(candidate_file)

        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["review", candidate_file, "--admit", "--reviewer", "arch-lead", "--json"])
        assert exit_code == 0
        data = json.loads(f.getvalue().strip())
        assert data["status"] == "SUCCESS"
        assert data["decision"] == "ACCEPTED"
        assert data["reviewer"] == "arch-lead"


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
