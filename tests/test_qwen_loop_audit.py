"""Integration test: End-to-end Hardening Loop execution on baseline qwen-tool-loop target."""

import json
import os
import tempfile
import pytest
from hardening_loop.models import HardeningState, PhaseName, VerificationStatus
from hardening_loop.runner import HardeningRunner

FIXTURE_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py")
REAL_SCRIPT = "/Users/felipe_gonzalez/Developer/examen_grado/scripts/qwen-tool-loop.py"


@pytest.mark.parametrize("target_path", [
    FIXTURE_SCRIPT,
    pytest.param(REAL_SCRIPT, marks=pytest.mark.skipif(not os.path.exists(REAL_SCRIPT), reason="Real script not present")),
])
def test_qwen_tool_loop_full_hardening_cycle(target_path):
    target = os.path.abspath(target_path)
    with tempfile.TemporaryDirectory() as out_dir:
        runner = HardeningRunner(target_path=target, output_dir=out_dir)
        envelopes = runner.run_all()

        assert len(envelopes) == 5
        assert runner.work_unit.state == HardeningState.KNOWLEDGE_CANDIDATE
        assert runner.work_unit.phases_executed == ["question", "delete", "simplify", "verify", "codify"]

        # 1. Verify QUESTION phase findings
        req_file = os.path.join(out_dir, "requirements_audit.json")
        assert os.path.exists(req_file)
        with open(req_file) as f:
            req_data = json.load(f)
        assert req_data["total_requirements_audited"] >= 1

        # 2. Verify DELETE phase findings
        del_file = os.path.join(out_dir, "deletion_candidates.json")
        patch_file = os.path.join(out_dir, "diff.patch")
        assert os.path.exists(del_file)
        assert os.path.exists(patch_file)
        with open(del_file) as f:
            del_candidates = json.load(f)
        assert len(del_candidates) >= 2
        candidate_targets = [c["target"] for c in del_candidates]
        assert "unconstrained_shell_harness" in candidate_targets

        # 3. Verify SIMPLIFY phase
        contract_file = os.path.join(out_dir, "contract_diff.json")
        assert os.path.exists(contract_file)
        with open(contract_file) as f:
            contract_data = json.load(f)
        assert contract_data["interface_breaking_changes_detected"] == 0

        # 4. Verify VERIFY phase
        test_res_file = os.path.join(out_dir, "test_results.json")
        benchmark_file = os.path.join(out_dir, "benchmark.json")
        assert os.path.exists(test_res_file)
        assert os.path.exists(benchmark_file)
        with open(benchmark_file) as f:
            bench_data = json.load(f)
        assert bench_data["meets_fast_feedback_sla"] is True

        # 5. Verify CODIFY phase & Admission Gate
        kc_file = os.path.join(out_dir, "knowledge_candidate.yaml")
        admission_file = os.path.join(out_dir, "admission_record.json")
        assert os.path.exists(kc_file)
        assert os.path.exists(admission_file)
        with open(admission_file) as f:
            adm_data = json.load(f)
        assert adm_data["admission_status"] == "PENDING_REVIEW"
        assert adm_data["gate_policy"] == "NO_AUTO_CANONICAL"

        # 6. Verify Manifest and WorkUnit records
        manifest_file = os.path.join(out_dir, "evidence_manifest.json")
        wu_file = os.path.join(out_dir, "work_unit.json")
        assert os.path.exists(manifest_file)
        assert os.path.exists(wu_file)
