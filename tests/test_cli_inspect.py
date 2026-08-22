"""Tests for CLI subcommands: `inspect`, `validate`, and workspace sandboxing."""

import io
import json
import os
import shutil
import tempfile
from contextlib import redirect_stdout

from hardening_loop.cli import main


def test_cli_inspect_valid_evidence_passes():
    """`hardening-loop inspect` over an untampered evidence dir returns exit code 0."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "tmp_inspect_valid"))
    os.makedirs(out_dir, exist_ok=True)
    try:
        # 1. Run pipeline
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])

        # 2. Inspect evidence directory
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["inspect", out_dir, "--json"])
        assert exit_code == 0
        data = json.loads(f.getvalue().strip())
        assert data["integrity_status"] == "INTEGRITY_PASS"
        assert data["tamper_detected"] is False
        assert data["total_envelopes_verified"] == 5
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def test_cli_inspect_tampered_manifest_fails_closed_code_2():
    """`hardening-loop inspect` detects tampered manifest digest and returns exit code 2."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "tmp_inspect_tamper"))
    os.makedirs(out_dir, exist_ok=True)
    try:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        manifest_path = os.path.join(out_dir, "evidence_manifest.json")

        # Tamper with the manifest payload
        with open(manifest_path) as f:
            data = json.loads(f.read())
        data["envelopes"][0]["canonical_evidence"]["artifact_payload"]["hacked"] = True
        with open(manifest_path, "w") as f:
            json.dump(data, f)

        # Inspect must fail closed
        exit_code = main(["inspect", out_dir])
        assert exit_code == 2
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def test_cli_validate_valid_candidate_passes():
    """`hardening-loop validate` on valid knowledge candidate returns 0."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "tmp_validate_cand"))
    os.makedirs(out_dir, exist_ok=True)
    try:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        candidate_file = os.path.join(out_dir, "knowledge_candidate.yaml")

        exit_code = main(["validate", candidate_file, "--json"])
        assert exit_code == 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def test_cli_validate_corrupted_payload_fails_closed_code_2():
    """`hardening-loop validate` on invalid JSON schema payload returns code 2."""
    corrupted_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "corrupted_env.json"))
    os.makedirs(os.path.dirname(corrupted_file), exist_ok=True)
    try:
        with open(corrupted_file, "w") as f:
            json.dump({"invalid_envelope": True}, f)

        exit_code = main(["validate", corrupted_file, "--schema", "evidence_envelope"])
        assert exit_code == 2
    finally:
        if os.path.exists(corrupted_file):
            os.remove(corrupted_file)


def test_cli_workspace_sandbox_traversal_fails_closed_code_2():
    """CLI commands with path traversal outside workspace_root fail closed with code 2."""
    with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as outside:
        target_outside = os.path.join(outside, "target.py")
        with open(target_outside, "w") as f:
            f.write("# code")

        out_dir = os.path.join(ws, "evidence")
        exit_code = main(["run", "--target", target_outside, "--output", out_dir, "--workspace-root", ws])
        assert exit_code == 2
