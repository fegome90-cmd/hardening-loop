"""Comprehensive adversarial regression tests covering all audit findings, T01..T26 matrix, and hardening blockers."""

from __future__ import annotations

import ast
import io
import json
import os
from datetime import datetime, timezone

import pytest
import yaml

from hardening_loop.cli import main
from hardening_loop.models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    HardeningState,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    WorkUnit,
    sha256_text,
    utc_now_iso,
)
from hardening_loop.phases import (
    CodifyPhase,
    QuestionPhase,
    VerifyPhase,
)
from hardening_loop.phases.base import find_subprocess_calls
from hardening_loop.posthog_sink import PostHogSinkError, PostHogTelemetrySink
from hardening_loop.runner import HardeningRunner, aggregate_final_status, count_target_loc
from hardening_loop.sandbox import PathSandboxError, assert_within_workspace
from hardening_loop.schema_validator import SchemaValidator
from hardening_loop.states import StateMachine
from hardening_loop.telemetry import (
    TelemetryEmitter,
    WalWriter,
    verify_manifest_integrity,
)

# ==============================================================================
# S1 .. S6 CORE ARCHITECTURAL INVARIANTS
# ==============================================================================


def test_s1_run_all_halts_immediately_on_verify_fail(tmp_path):
    """S1: run_all() must halt after verify failure and NEVER execute codify (Ley VIII)."""
    target = tmp_path / "unsafe_target.py"
    target.write_text("import os\nos.system('echo unsafe')\n", encoding="utf-8")
    out_dir = tmp_path / "evidence"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    envelopes = runner.run_all()

    executed_phases = [e.phase for e in envelopes]
    assert PhaseName.VERIFY in executed_phases
    assert PhaseName.CODIFY not in executed_phases
    assert runner.envelopes[-1].status == VerificationStatus.FAIL


def test_s2_monotonic_status_precedence():
    """S2: Aggregate final status must follow strict precedence: FAIL > WARN > PASS."""

    def mock_env(status: VerificationStatus) -> EvidenceEnvelope:
        canonical = CanonicalEvidence(
            evidence_id="evi-11112222",
            phase=PhaseName.QUESTION,
            input_hash="a" * 64,
            output_hash="b" * 64,
            method_version="v0.3",
            schema_version="v0.1",
            execution_context_hash="c" * 64,
            artifact_payload={},
        )
        runtime = RuntimeReceipt(
            producer="test",
            timestamp=utc_now_iso(),
            duration_ms=1.0,
            checks=[],
            status=status,
        )
        return EvidenceEnvelope(canonical=canonical, runtime=runtime)

    assert aggregate_final_status([mock_env(VerificationStatus.PASS), mock_env(VerificationStatus.PASS)]) == "PASS"
    assert aggregate_final_status([mock_env(VerificationStatus.PASS), mock_env(VerificationStatus.WARN)]) == "WARN"
    assert (
        aggregate_final_status(
            [mock_env(VerificationStatus.PASS), mock_env(VerificationStatus.WARN), mock_env(VerificationStatus.FAIL)]
        )
        == "FAIL"
    )
    assert aggregate_final_status([mock_env(VerificationStatus.BLOCKED), mock_env(VerificationStatus.PASS)]) == "FAIL"


def test_s3_default_workspace_sandboxing_fails_closed():
    """S3: assert_within_workspace must default to current workspace and fail closed."""
    with pytest.raises(PathSandboxError):
        assert_within_workspace("/etc/passwd")


def test_s4_inspect_detects_physical_artifact_tampering_on_disk(tmp_path):
    """S4: inspect must detect tampering of physical files on disk (Ley XI & Ley VIII)."""
    target = tmp_path / "clean.py"
    target.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    # 1. Run full hardening loop
    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    # 2. Inspect clean evidence directory -> MUST PASS
    ret_clean = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret_clean == 0

    # 3. Tamper with a physical file on disk (without updating manifest)
    tampered_file = out_dir / "test_results.json"
    tampered_file.write_text('{"tampered": true}', encoding="utf-8")

    # 4. Inspect tampered directory -> MUST FAIL with code 2
    ret_tampered = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret_tampered == 2


def test_s4_inspect_detects_path_traversal_escape_in_manifest(tmp_path):
    """S4: inspect must reject manifests pointing to artifacts outside the evidence directory."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Add a malicious artifact pointing to ../secret.txt
    manifest_data["artifacts"].append({"path": "../secret.txt", "type": "evidence", "sha256": "e" * 64})
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_s5_manifest_integrity_hash_verified_and_schema_compliant(tmp_path):
    """S5 & P1: evidence_manifest.json must pass v0.2 schema validation and have valid manifest_hash."""
    target = tmp_path / "clean.py"
    target.write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_path = out_dir / "evidence_manifest.json"
    assert manifest_path.exists()

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

    # 1. Validate against schema v0.2
    SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", manifest_data)

    # 2. Verify cryptographically that manifest_hash matches canonical calculation
    is_valid, _ = verify_manifest_integrity(manifest_data)
    assert is_valid is True


def test_s5_inspect_detects_manifest_and_artifact_synchronized_tampering(tmp_path):
    """S5: If an attacker modifies an artifact AND updates the manifest artifact sha256, manifest_hash detects desynchronization."""
    target = tmp_path / "clean.py"
    target.write_text("x = 42\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_run"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    # Tamper with file
    diff_file = out_dir / "diff.patch"
    diff_file.write_text("MALICIOUS PATCH CONTENT", encoding="utf-8")
    new_sha = sha256_text("MALICIOUS PATCH CONTENT")

    manifest_file = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Update the artifact entry in manifest to match new file hash
    for art in manifest_data["artifacts"]:
        if art["path"] == "diff.patch":
            art["sha256"] = new_sha

    # Attacker does NOT know how to forge manifest_hash or forgot to update it
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    ret = main(["inspect", str(out_dir), "--workspace-root", str(tmp_path)])
    assert ret == 2


def test_s6_posthog_sink_hardening():
    """S6: PostHogTelemetrySink must enforce strict HTTPS allowlist and reject attacker hosts."""
    sink_us = PostHogTelemetrySink(api_key="phc_test12345", host="https://us.i.posthog.com")
    assert sink_us.host == "https://us.i.posthog.com"

    sink_eu = PostHogTelemetrySink(api_key="phc_test12345", host="https://eu.i.posthog.com")
    assert sink_eu.host == "https://eu.i.posthog.com"

    sink_app = PostHogTelemetrySink(api_key="phc_test12345", host="https://app.posthog.com")
    assert sink_app.host == "https://app.posthog.com"

    with pytest.raises(PostHogSinkError, match="HTTP is only permitted"):
        PostHogTelemetrySink(api_key="phc_test12345", host="http://us.i.posthog.com")

    with pytest.raises(PostHogSinkError, match="authorized allowlist"):
        PostHogTelemetrySink(api_key="phc_test12345", host="https://attacker.example.com")


# ==============================================================================
# FULL TARGETED REGRESSION MATRIX: T01 .. T26
# ==============================================================================


def test_t01_transition_history_records_true_previous_state():
    """T01: StateMachine.transition records accurate 'from' previous state before mutation."""
    wu = WorkUnit(
        work_unit_id="wu-t01",
        target_path="app.py",
        target_hash="a" * 64,
        state=HardeningState.DRAFT,
    )
    StateMachine.transition(wu, HardeningState.AUDITING, "Beginning phase audits")
    assert wu.state == HardeningState.AUDITING
    history = wu.metadata.get("transition_history", [])
    assert len(history) == 1
    assert history[0]["from"] == "DRAFT"
    assert history[0]["to"] == "AUDITING"
    assert history[0]["from"] != history[0]["to"]


def test_t02_chained_transitions_preserve_provenance():
    """T02: Chained state transitions preserve true historical sequence and distinct from/to."""
    wu = WorkUnit(
        work_unit_id="wu-t02",
        target_path="app.py",
        target_hash="b" * 64,
        state=HardeningState.DRAFT,
    )
    StateMachine.transition(wu, HardeningState.AUDITING, "Start audit")
    StateMachine.transition(wu, HardeningState.PATCH_PROPOSED, "Patches ready")
    StateMachine.transition(wu, HardeningState.VERIFIED, "Verification tests pass")

    history = wu.metadata.get("transition_history", [])
    assert len(history) == 3
    assert history[0]["from"] == "DRAFT" and history[0]["to"] == "AUDITING"
    assert history[1]["from"] == "AUDITING" and history[1]["to"] == "PATCH_PROPOSED"
    assert history[2]["from"] == "PATCH_PROPOSED" and history[2]["to"] == "VERIFIED"


def test_t03_run_json_validates_against_manifest_v02(tmp_path, monkeypatch):
    """T03: 'hardening-loop run --phase all --json' stdout parses and validates against manifest v0.2."""
    target = tmp_path / "target.py"
    target.write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t03"

    out_buf = io.StringIO()
    monkeypatch.setattr("sys.stdout", out_buf)

    exit_code = main(
        [
            "run",
            "--target",
            str(target),
            "--output",
            str(out_dir),
            "--phase",
            "all",
            "--json",
            "--workspace-root",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    raw_output = out_buf.getvalue().strip()
    data = json.loads(raw_output)

    SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", data)
    assert data["schema_version"] == "hardening-loop.manifest.v0.2"
    assert "canonical_manifest_digest" in data
    assert "runtime_telemetry" in data


def test_t04_run_json_equals_persisted_manifest_semantics(tmp_path, monkeypatch):
    """T04: stdout of run --json is semantically equal to canonical persisted evidence_manifest.json."""
    target = tmp_path / "app.py"
    target.write_text("def ok(): return True\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t04"

    out_buf = io.StringIO()
    monkeypatch.setattr("sys.stdout", out_buf)

    exit_code = main(
        [
            "run",
            "--target",
            str(target),
            "--output",
            str(out_dir),
            "--phase",
            "all",
            "--json",
            "--workspace-root",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    stdout_manifest = json.loads(out_buf.getvalue().strip())
    disk_manifest = json.loads((out_dir / "evidence_manifest.json").read_text(encoding="utf-8"))

    assert stdout_manifest == disk_manifest


def test_t05_missing_manifest_fails_closed_no_fallback(tmp_path, monkeypatch):
    """T05: If canonical manifest is unexpectedly missing after run, CLI fails closed without synthesizing fallback."""
    target = tmp_path / "app.py"
    target.write_text("x = 10\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t05"

    original_run_all = HardeningRunner.run_all

    def _run_all_and_delete_manifest(self):
        envs = original_run_all(self)
        manifest_file = os.path.join(self.output_dir, "evidence_manifest.json")
        if os.path.exists(manifest_file):
            os.remove(manifest_file)
        return envs

    monkeypatch.setattr(HardeningRunner, "run_all", _run_all_and_delete_manifest)

    err_buf = io.StringIO()
    monkeypatch.setattr("sys.stderr", err_buf)

    exit_code = main(
        [
            "run",
            "--target",
            str(target),
            "--output",
            str(out_dir),
            "--phase",
            "all",
            "--json",
            "--workspace-root",
            str(tmp_path),
        ]
    )
    assert exit_code != 0
    assert "was not generated (fail-closed)" in err_buf.getvalue()


def test_t06_telemetry_inside_workspace_passes(tmp_path):
    """T06: TelemetryEmitter within workspace boundary creates WAL and records events."""
    out_dir = tmp_path / "telemetry_t06"
    emitter = TelemetryEmitter(output_dir=str(out_dir), workspace_root=str(tmp_path))
    emitter.start_run(
        git_sha="0" * 40,
        branch="main",
        dirty_worktree=False,
        runner_version="0.3.0",
        config_hash="a" * 64,
        input_hash="b" * 64,
    )
    emitter.wal.close()
    assert (out_dir / "telemetry.jsonl").exists()


def test_t07_telemetry_outside_workspace_fails_before_write(tmp_path):
    """T07: TelemetryEmitter outside workspace boundary fails closed before creating directory or file."""
    outside_dir = "/tmp/outside_telemetry_t07"
    with pytest.raises(PathSandboxError):
        TelemetryEmitter(output_dir=outside_dir, workspace_root=str(tmp_path))


def test_t08_wal_path_escape_fails(tmp_path):
    """T08: WalWriter escaping workspace boundary raises PathSandboxError before opening file."""
    outside_file = "/tmp/escaped_wal.jsonl"
    with pytest.raises(PathSandboxError):
        WalWriter(outside_file, mode="a", workspace_root=str(tmp_path))


def test_t09_second_run_cannot_alter_first_run_evidence(tmp_path):
    """T09: A second run on an output directory containing evidence fails closed, leaving Run 1 bytes unchanged."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t09"

    # Run 1 succeeds
    r1 = HardeningRunner(str(target), str(out_dir))
    r1.run_all()
    manifest_bytes_run1 = (out_dir / "evidence_manifest.json").read_bytes()
    wal_bytes_run1 = (out_dir / "telemetry.jsonl").read_bytes()

    # Run 2 on same output_dir fails closed immediately
    with pytest.raises(ValueError, match="already contains evidence"):
        HardeningRunner(str(target), str(out_dir))

    # Assert Run 1 bytes were not modified or truncated
    assert (out_dir / "evidence_manifest.json").read_bytes() == manifest_bytes_run1
    assert (out_dir / "telemetry.jsonl").read_bytes() == wal_bytes_run1


def test_t10_orphan_wal_cannot_be_truncated(tmp_path):
    """T10: An orphan non-empty telemetry.jsonl in output directory prevents new runs and cannot be truncated."""
    out_dir = tmp_path / "orphan_dir"
    out_dir.mkdir()
    wal_file = out_dir / "telemetry.jsonl"
    wal_file.write_text('{"orphan_event": true}\n', encoding="utf-8")
    wal_hash_before = sha256_text(wal_file.read_text(encoding="utf-8"))

    # HardeningRunner rejects directory with orphan WAL
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="already contains evidence"):
        HardeningRunner(str(target), str(out_dir))

    # WalWriter with mode='w' refuses to truncate existing non-empty WAL
    with pytest.raises(ValueError, match="Refusing to truncate prior evidence"):
        WalWriter(str(wal_file), mode="w")

    assert sha256_text(wal_file.read_text(encoding="utf-8")) == wal_hash_before


def test_t11_partial_evidence_dir_cannot_be_overwritten(tmp_path):
    """T11: If a partial owned run artifact exists in output directory, HardeningRunner fails closed."""
    out_dir = tmp_path / "partial_dir"
    out_dir.mkdir()
    (out_dir / "work_unit.json").write_text('{"work_unit_id": "wu-partial"}', encoding="utf-8")

    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="already contains evidence"):
        HardeningRunner(str(target), str(out_dir))


def test_t12_loc_invalid_utf8_fails_closed(tmp_path):
    """T12: count_target_loc on invalid UTF-8 target raises decode error rather than fabricating LOC=0."""
    bad_file = tmp_path / "bad.py"
    bad_file.write_bytes(b"x = \xff\xfe\xfa\n")
    with pytest.raises(UnicodeDecodeError):
        count_target_loc(str(bad_file))


def test_t13_loc_unreadable_source_fails_closed():
    """T13: count_target_loc on non-existent path raises ValueError fail-closed."""
    with pytest.raises(ValueError, match="Target path does not exist"):
        count_target_loc("/nonexistent/file/path.py")


def test_t14_no_partial_loc_represented_as_complete(tmp_path):
    """T14: count_target_loc on a directory containing an invalid file fails closed without emitting partial count."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "good.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    (pkg / "bad.py").write_bytes(b"\x80\x81\x82 invalid utf8\n")

    with pytest.raises(UnicodeDecodeError):
        count_target_loc(str(pkg))


def test_t15_current_manifest_fixtures_validate(tmp_path):
    """T15: Freshly generated manifest fixtures validate against normative schema v0.2."""
    target = tmp_path / "app.py"
    target.write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t15"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    manifest_path = out_dir / "evidence_manifest.json"
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

    SchemaValidator.validate_or_raise("hardening_loop_manifest.v0.2", manifest_data)
    assert manifest_data["schema_version"] == "hardening-loop.manifest.v0.2"


def test_t16_historical_evidence_remains_historically_honest():
    """T16: Historical evidence under evidence/run-001/ is preserved without synthetic rewrite."""
    assert os.path.exists("evidence/run-001/evidence_manifest.json")
    historical_manifest = json.loads(open("evidence/run-001/evidence_manifest.json", encoding="utf-8").read())
    # Historical manifest preserves historical format
    assert "canonical_manifest_digest" in historical_manifest or "work_unit" in historical_manifest


def test_t17_transition_fixture_provenance_is_valid(tmp_path):
    """T17: HardeningRunner state transitions record genuine distinct from -> to steps."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t17"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    history = runner.work_unit.metadata.get("transition_history", [])
    assert len(history) >= 2
    for item in history:
        assert item["from"] != item["to"], f"Impossible self-transition recorded: {item}"


def test_t18_subprocess_direct_alias_check_call_detected():
    """T18: find_subprocess_calls detects check_call, direct calls, and import aliases."""
    src = """
import subprocess as sp
from subprocess import check_call as cc, run as r

def f1():
    sp.check_call(["ls", "-la"], shell=True)

def f2():
    cc(["pwd"], shell=True)

def f3():
    r("echo hi", shell=True)
"""
    tree = ast.parse(src)
    calls = find_subprocess_calls(tree)
    assert len(calls) == 3
    for _node, has_shell in calls:
        assert has_shell is True


def test_t19_unrelated_runner_run_not_classified_as_subprocess():
    """T19: Class method runner.run(shell=True) is not flagged as a subprocess call."""
    src = """
class MyRunner:
    def run(self, cmd, shell=False):
        return cmd

runner = MyRunner()
runner.run("do_something", shell=True)
"""
    tree = ast.parse(src)
    calls = find_subprocess_calls(tree)
    assert len(calls) == 0


def test_t20_nested_ast_scope_remains_innermost(tmp_path):
    """T20: QuestionPhase attributes security constraints to innermost nested function scope."""
    code = """
def outer_fn():
    def inner_fn():
        f = open("file.txt", "r")
        return f.read()
    return inner_fn()
"""
    target = tmp_path / "nested.py"
    target.write_text(code, encoding="utf-8")

    phase = QuestionPhase()
    payload, checks, status = phase.execute(str(target), {})

    reqs = payload.get("requirements", [])
    open_reqs = [r for r in reqs if "open()" in r.get("audit_finding", "")]
    assert len(open_reqs) == 1
    assert "inner_fn" in open_reqs[0]["source"]


def test_t21_strict_phase_utf8_syntax_fail_closed(tmp_path):
    """T21: Target with invalid syntax causes phases to fail closed with FAIL status."""
    bad_target = tmp_path / "syntax_error.py"
    bad_target.write_text("def broken(\n", encoding="utf-8")

    phase = VerifyPhase()
    payload, checks, status = phase.execute(str(bad_target), {})
    assert status == VerificationStatus.FAIL


def test_t22_manifest_self_hash_and_artifact_verification(tmp_path):
    """T22: verify_manifest_integrity checks self-hash and physical artifact digests."""
    target = tmp_path / "app.py"
    target.write_text("x = 100\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t22"

    runner = HardeningRunner(str(target), str(out_dir))
    runner.run_all()

    manifest_data = json.loads((out_dir / "evidence_manifest.json").read_text(encoding="utf-8"))
    valid, computed_hash = verify_manifest_integrity(manifest_data)
    assert valid is True
    assert len(computed_hash) == 64


def test_t23_posthog_arbitrary_https_rejection():
    """T23: PostHog sink rejects arbitrary HTTPS host not in allowlist."""
    with pytest.raises(PostHogSinkError, match="authorized allowlist"):
        PostHogTelemetrySink(api_key="phc_key", host="https://malicious-telemetry.io")


def test_t24_candidate_created_at_is_real_recent_utc(tmp_path):
    """T24: Materialized KnowledgeCandidate created_at is a real recent UTC timestamp."""
    t_before = datetime.now(timezone.utc)

    target = tmp_path / "app.py"
    target.write_text("p = '/Users/dev/tmp_secret'\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t24"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))
    runner.run_all()

    kc_file = out_dir / "knowledge_candidate.yaml"
    assert kc_file.exists()
    kc_data = yaml.safe_load(kc_file.read_text(encoding="utf-8"))
    candidate = kc_data[0] if isinstance(kc_data, list) else kc_data

    created_at_str = candidate["created_at"]
    assert not created_at_str.startswith("1970-01-01")

    dt = datetime.fromisoformat(created_at_str)
    t_after = datetime.now(timezone.utc)
    assert t_before.timestamp() - 5 <= dt.timestamp() <= t_after.timestamp() + 5
    assert dt.utcoffset() == timezone.utc.utcoffset(dt)


def test_t25_canonical_candidate_identity_clock_independent(tmp_path):
    """T25: Canonical evidence output_hash is clock-independent and hermetically deterministic."""
    phase = CodifyPhase()
    ctx = {
        "evidence_ids": ["evi-99998888"],
        "deletion_candidates": [
            {
                "target": "os_system",
                "location": "app.py:10",
                "rationale": "Unsafe shell invocation",
                "action": "DELETE",
                "severity": "HIGH",
            }
        ],
    }

    payload1, _, _ = phase.execute(str(tmp_path / "app.py"), ctx)
    payload2, _, _ = phase.execute(str(tmp_path / "app.py"), ctx)

    assert json.dumps(payload1, sort_keys=True) == json.dumps(payload2, sort_keys=True)


def test_t26_terminal_persistence_failure_remains_observable(tmp_path, monkeypatch):
    """T26: Terminal evidence persistence failure is chained via RuntimeError and observable."""
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")
    out_dir = tmp_path / "evidence_t26"

    runner = HardeningRunner(target_path=str(target), output_dir=str(out_dir))

    # Force failure during terminal write_manifest
    def _failing_write_manifest(*args, **kwargs):
        raise OSError("Simulated disk full during terminal manifest write")

    monkeypatch.setattr(runner.emitter, "write_manifest", _failing_write_manifest)

    # Force phase failure to trigger terminal write
    def _failing_question(*args, **kwargs):
        raise RuntimeError("Phase crashed")

    monkeypatch.setattr(runner.phases[PhaseName.QUESTION], "run", _failing_question)

    with pytest.raises(RuntimeError) as exc_info:
        runner.run_all()

    # Assert chained persistence error is observable
    assert "terminal evidence persistence failed" in str(exc_info.value)
