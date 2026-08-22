"""Tests for high-precision telemetry, benchmarking, and observability (Ley XI)."""

import io
import json
import os
import shutil
from contextlib import redirect_stdout

from hardening_loop.cli import main
from hardening_loop.telemetry import TelemetryCollector


def test_telemetry_collector_records_phases():
    """`TelemetryCollector` tracks start, stop, LOC, and throughput."""
    collector = TelemetryCollector()
    collector.start_phase("question")
    # Simulate work
    collector.record_phase_metrics("question", loc=100, ast_nodes=25)
    collector.end_phase("question")

    summary = collector.get_summary()
    assert "question" in summary["phase_durations_ms"]
    assert summary["total_loc_analyzed"] == 100
    assert summary["total_ast_nodes_visited"] == 25
    assert summary["total_duration_ms"] >= 0.0
    assert summary["throughput_loc_per_sec"] >= 0.0


def test_runner_emits_complete_telemetry_manifest():
    """`HardeningRunner.run_all` populates comprehensive `runtime_telemetry`."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "tmp_telem_man"))
    os.makedirs(out_dir, exist_ok=True)
    try:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])
        manifest_file = os.path.join(out_dir, "evidence_manifest.json")
        assert os.path.exists(manifest_file)

        with open(manifest_file) as f:
            manifest = json.load(f)

        telemetry = manifest.get("runtime_telemetry", {})
        assert "phase_durations_ms" in telemetry
        assert "question" in telemetry["phase_durations_ms"]
        assert "delete" in telemetry["phase_durations_ms"]
        assert "simplify" in telemetry["phase_durations_ms"]
        assert "verify" in telemetry["phase_durations_ms"]
        assert "codify" in telemetry["phase_durations_ms"]
        assert "total_duration_ms" in telemetry
        assert "total_loc_analyzed" in telemetry
        assert "throughput_loc_per_sec" in telemetry
        assert "peak_memory_mb" in telemetry
        assert telemetry["total_loc_analyzed"] > 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def test_cli_telemetry_subcommand_json_and_table():
    """`hardening-loop telemetry <dir>` outputs structured metrics."""
    target = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "qwen-tool-loop.py"))
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "tmp_telem_sub"))
    os.makedirs(out_dir, exist_ok=True)
    try:
        main(["run", "--target", target, "--phase", "all", "--output", out_dir, "-q"])

        # JSON output test
        f_json = io.StringIO()
        with redirect_stdout(f_json):
            exit_code = main(["telemetry", out_dir, "--json"])
        assert exit_code == 0
        data = json.loads(f_json.getvalue().strip())
        assert "phase_durations_ms" in data
        assert "total_duration_ms" in data
        assert "throughput_loc_per_sec" in data

        # Tabular output test
        f_text = io.StringIO()
        with redirect_stdout(f_text):
            exit_code = main(["telemetry", out_dir])
        assert exit_code == 0
        output = f_text.getvalue()
        assert "=== Hardening Loop Telemetry & Observability Report ===" in output
        assert "Throughput" in output
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
