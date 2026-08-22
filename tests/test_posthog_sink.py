"""Tests for PostHog telemetry sink integration (Ley XI)."""

import io
import json
import os
import shutil
from contextlib import redirect_stdout

from hardening_loop.cli import main
from hardening_loop.posthog_sink import PostHogTelemetrySink


def test_format_telemetry_batch_structure():
    """`PostHogTelemetrySink.format_telemetry_batch` produces typed events with `$insert_id`."""
    sink = PostHogTelemetrySink(api_key="test_key")
    manifest = {
        "canonical_manifest_digest": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "work_unit": {
            "work_unit_id": "wu-abcdef123456",
            "target_path": "/path/to/target.py",
            "phases_executed": ["question", "delete", "simplify", "verify", "codify"],
        },
        "envelopes": [
            {
                "canonical_evidence": {
                    "evidence_id": "evi-111122223333",
                    "phase": "question",
                    "input_hash": "a" * 64,
                    "output_hash": "b" * 64,
                    "execution_context_hash": "c" * 64,
                },
                "runtime_receipt": {
                    "duration_ms": 12.34,
                    "status": "PASS",
                    "timestamp": "2026-08-21T12:00:00Z",
                },
            }
        ],
        "runtime_telemetry": {
            "total_duration_ms": 45.67,
            "total_loc_analyzed": 150,
            "throughput_loc_per_sec": 3280.0,
            "peak_memory_mb": 28.5,
            "final_status": "PASS",
            "timestamp": "2026-08-21T12:00:00Z",
        },
    }

    events = sink.format_telemetry_batch(manifest)
    assert len(events) == 2

    # Check Run Event
    run_event = events[0]
    assert run_event["event"] == "hardening_run_completed"
    assert run_event["properties"]["$insert_id"] == "run-abcdef1234567890"
    assert run_event["properties"]["throughput_loc_per_sec"] == 3280.0
    assert run_event["properties"]["$property_type"]["throughput_loc_per_sec"] == "Numeric"

    # Check Phase Event
    phase_event = events[1]
    assert phase_event["event"] == "hardening_phase_executed"
    assert phase_event["properties"]["$insert_id"] == "evi-111122223333"
    assert phase_event["properties"]["phase"] == "question"
    assert phase_event["properties"]["duration_ms"] == 12.34
    assert phase_event["properties"]["$property_type"]["duration_ms"] == "Numeric"


def test_export_dry_run_mode():
    """`PostHogTelemetrySink.export` returns DRY_RUN payload when no key or dry_run=True."""
    sink = PostHogTelemetrySink(api_key=None)
    manifest = {
        "canonical_manifest_digest": "1234" * 16,
        "work_unit": {"work_unit_id": "wu-1234", "target_path": "foo.py"},
        "envelopes": [],
        "runtime_telemetry": {"total_duration_ms": 10.0},
    }
    result = sink.export(manifest, dry_run=True)
    assert result["status"] == "DRY_RUN"
    assert result["events_count"] == 1


def test_cli_telemetry_posthog_dry_run():
    """`hardening-loop telemetry <dir> --posthog --dry-run --json` outputs PostHog batch."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "tmp_ph_dry_run"))
    os.makedirs(out_dir, exist_ok=True)
    try:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])

        f_json = io.StringIO()
        with redirect_stdout(f_json):
            exit_code = main(["telemetry", out_dir, "--posthog", "--dry-run", "--json"])
        assert exit_code == 0
        data = json.loads(f_json.getvalue().strip())
        assert data["status"] == "DRY_RUN"
        assert data["events_count"] == 6  # 1 run + 5 phases
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
