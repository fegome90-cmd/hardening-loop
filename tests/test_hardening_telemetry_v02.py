from __future__ import annotations

import hashlib
import importlib
import json
import re
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest

from hardening_loop.telemetry import EventValidationError

RUN_ID = "hl_test_telemetry_v02"
TRACE_ID = "tr_test_telemetry_v02"
SHA256 = "a" * 64


def make_event(event_name: str = "hardening_run_started", **overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": "hardening-loop.telemetry.v0.2",
        "event_name": event_name,
        "timestamp": "2026-08-21T20:00:00Z",
        "run_id": RUN_ID,
        "trace_id": TRACE_ID,
        "span_id": None,
        "parent_span_id": None,
        "status": "STARTED",
        "git_sha": "b" * 40,
        "branch": "task/test",
        "dirty_worktree": False,
        "runner_version": "test",
        "config_hash": SHA256,
        "input_hash": SHA256,
    }
    event.update(overrides)
    return event


def telemetry_module():
    return importlib.import_module("hardening_loop.telemetry")


def legacy_manifest() -> dict[str, object]:
    return {
        "canonical_manifest_digest": SHA256,
        "work_unit": {
            "work_unit_id": "wu-test",
            "target_path": "src/example.py",
            "phases_executed": ["question"],
        },
        "runtime_telemetry": {
            "timestamp": "2026-08-21T20:00:00Z",
            "total_duration_ms": 1.0,
            "total_loc_analyzed": 1,
            "throughput_loc_per_sec": 1.0,
            "peak_memory_mb": 1.0,
            "final_status": "PASS",
        },
        "envelopes": [
            {
                "canonical_evidence": {
                    "evidence_id": "evi-test",
                    "phase": "question",
                    "input_hash": SHA256,
                    "output_hash": SHA256,
                    "execution_context_hash": SHA256,
                },
                "runtime_receipt": {
                    "timestamp": "2026-08-21T20:00:00Z",
                    "duration_ms": 1.0,
                    "status": "PASS",
                },
            }
        ],
    }


def test_valid_v02_event_passes_schema_validation() -> None:
    telemetry = telemetry_module()
    telemetry.validate_event(make_event())


def test_event_without_run_id_fails_validation() -> None:
    telemetry = telemetry_module()
    event = make_event()
    del event["run_id"]
    with pytest.raises((EventValidationError, ValueError, KeyError, jsonschema.ValidationError, TypeError)):
        telemetry.validate_event(event)


def test_event_with_noncanonical_status_fails_validation() -> None:
    telemetry = telemetry_module()
    with pytest.raises((EventValidationError, ValueError, KeyError, jsonschema.ValidationError, TypeError)):
        telemetry.validate_event(make_event(status="SUCCESS"))


def test_event_with_noncanonical_phase_fails_validation() -> None:
    telemetry = telemetry_module()
    event = make_event(
        "hardening_phase_started",
        status="STARTED",
        span_id="sp_test",
        phase="not-a-phase",
        phase_index=0,
    )
    with pytest.raises((EventValidationError, ValueError, KeyError, jsonschema.ValidationError, TypeError)):
        telemetry.validate_event(event)


def test_wal_writes_readable_jsonl(tmp_path: Path) -> None:
    telemetry = telemetry_module()
    wal = telemetry.WalWriter(tmp_path / "telemetry.jsonl", workspace_root=str(tmp_path))
    wal.append(make_event())
    wal.append(make_event("hardening_run_completed", status="PASS"))
    wal.close()

    rows = (tmp_path / "telemetry.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == 2
    assert all(isinstance(json.loads(row), dict) for row in rows)


def test_manifest_generates_sha256_hashes(tmp_path: Path) -> None:
    telemetry = telemetry_module()
    artifact = tmp_path / "patch.diff"
    artifact.write_text("diff --git a/x b/x\n", encoding="utf-8")
    emitter = telemetry.TelemetryEmitter(
        output_dir=tmp_path,
        run_id=RUN_ID,
        trace_id=TRACE_ID,
        workspace_root=str(tmp_path),
    )
    emitter.write_artifact(artifact, artifact_type="patch")
    emitter.write_manifest(final_status="PASS")

    manifest = json.loads((tmp_path / "evidence_manifest.json").read_text(encoding="utf-8"))
    assert manifest["integrity"]["hash_algorithm"] == "sha256"
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["integrity"]["manifest_hash"])
    artifact_record = next(item for item in manifest["artifacts"] if item["path"] == "patch.diff")
    assert artifact_record["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()


def test_manifest_fails_when_obligatory_artifact_is_missing(tmp_path: Path) -> None:
    telemetry = telemetry_module()
    emitter = telemetry.TelemetryEmitter(
        output_dir=tmp_path,
        run_id=RUN_ID,
        trace_id=TRACE_ID,
        workspace_root=str(tmp_path),
    )
    with pytest.raises((EventValidationError, ValueError, FileNotFoundError, jsonschema.ValidationError)):
        emitter.write_manifest(
            final_status="PASS",
            artifacts=[tmp_path / "missing.patch.diff"],
        )


def test_posthog_dry_run_makes_no_network_call() -> None:
    from hardening_loop.posthog_sink import PostHogTelemetrySink

    sink = PostHogTelemetrySink(api_key="test-key")
    with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
        result = sink.export(legacy_manifest(), dry_run=True)
    assert result["status"] == "DRY_RUN"


def test_prohibited_properties_are_removed_or_rejected() -> None:
    telemetry = telemetry_module()
    event = make_event(
        prompt="full prompt",
        system_prompt="full system prompt",
        output="full output",
        tool_output="full tool output",
        secret="secret",
    )
    with pytest.raises((EventValidationError, ValueError, KeyError, jsonschema.ValidationError, TypeError)):
        sanitized = telemetry.sanitize_event(event)
    if "sanitized" in locals():
        for key in ("prompt", "system_prompt", "output", "tool_output", "secret"):
            assert key not in sanitized


def test_synthetic_complete_run_writes_wal_and_manifest(tmp_path: Path) -> None:
    telemetry = telemetry_module()
    patch_file = tmp_path / "patch.diff"
    patch_file.write_text("", encoding="utf-8")
    emitter = telemetry.TelemetryEmitter(
        output_dir=tmp_path,
        run_id=RUN_ID,
        trace_id=TRACE_ID,
        workspace_root=str(tmp_path),
    )
    emitter.start_run(
        git_sha="b" * 40,
        branch="task/test",
        dirty_worktree=False,
        runner_version="test",
        config_hash=SHA256,
        input_hash=SHA256,
    )
    emitter.write_artifact(patch_file, artifact_type="patch")
    emitter.complete_run(status="PASS")
    emitter.write_manifest(final_status="PASS")

    assert (tmp_path / "telemetry.jsonl").is_file()
    assert (tmp_path / "evidence_manifest.json").is_file()


def test_legacy_events_remain_compatible() -> None:
    from hardening_loop.posthog_sink import PostHogTelemetrySink

    events = PostHogTelemetrySink(api_key="test-key").format_telemetry_batch(legacy_manifest())
    names = {event["event"] for event in events}
    assert "hardening_run_completed" in names
    assert "hardening_phase_executed" in names
