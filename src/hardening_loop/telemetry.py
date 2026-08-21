"""High-precision telemetry, benchmarking, and observability (Ley XI)."""

from __future__ import annotations

import resource
import sys
import time
from typing import Any

from .models import utc_now_iso


def get_process_memory_mb() -> float:
    """Returns the peak resident set size (RSS) memory in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # On macOS ru_maxrss is in bytes; on Linux it is in kilobytes
    if sys.platform == "darwin":
        return round(usage / (1024 * 1024), 2)
    return round(usage / 1024, 2)


class TelemetryCollector:
    """Collects and aggregates runtime telemetry, latencies, throughput, and memory."""

    def __init__(self) -> None:
        self.phase_starts: dict[str, float] = {}
        self.phase_durations: dict[str, float] = {}
        self.phase_loc: dict[str, int] = {}
        self.phase_ast_nodes: dict[str, int] = {}
        self.initial_memory_mb = get_process_memory_mb()

    def start_phase(self, phase_name: str) -> None:
        """Marks the start timestamp of a hardening phase."""
        self.phase_starts[phase_name] = time.perf_counter()

    def record_phase_metrics(self, phase_name: str, loc: int = 0, ast_nodes: int = 0) -> None:
        """Records processed lines of code and AST nodes visited in a phase."""
        self.phase_loc[phase_name] = self.phase_loc.get(phase_name, 0) + loc
        self.phase_ast_nodes[phase_name] = self.phase_ast_nodes.get(phase_name, 0) + ast_nodes

    def end_phase(self, phase_name: str) -> float:
        """Marks the end of a hardening phase and computes duration in ms."""
        start_time = self.phase_starts.get(phase_name, time.perf_counter())
        duration_sec = time.perf_counter() - start_time
        duration_ms = round(duration_sec * 1000, 3)
        self.phase_durations[phase_name] = duration_ms
        return duration_ms

    def get_summary(self) -> dict[str, Any]:
        """Computes aggregated telemetry metrics across all executed phases."""
        total_duration_ms = round(sum(self.phase_durations.values()), 3)
        total_duration_sec = total_duration_ms / 1000.0

        # Lines of code analyzed across phases
        total_loc = max(self.phase_loc.values()) if self.phase_loc else 0
        total_ast_nodes = max(self.phase_ast_nodes.values()) if self.phase_ast_nodes else 0

        throughput_loc_sec = round(total_loc / total_duration_sec, 1) if total_duration_sec > 0 else 0.0

        return {
            "timestamp": utc_now_iso(),
            "total_duration_ms": total_duration_ms,
            "phase_durations_ms": self.phase_durations,
            "total_loc_analyzed": total_loc,
            "total_ast_nodes_visited": total_ast_nodes,
            "throughput_loc_per_sec": throughput_loc_sec,
            "peak_memory_mb": get_process_memory_mb(),
        }
