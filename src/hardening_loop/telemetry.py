"""High-precision telemetry, benchmarking, and observability (Ley XI)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import resource
import sys
import time
from typing import Any

from .models import utc_now_iso

# ---------------------------------------------------------------------------
# v0.2 event validation and WAL core (fail-closed)
# ---------------------------------------------------------------------------

EVENT_SCHEMA_PATH = "schemas/hardening_loop_event.v0.2.json"
MANIFEST_SCHEMA_PATH = "schemas/hardening_loop_manifest.v0.2.json"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_API_KEY_RES = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),  # OpenAI-style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key ids
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),  # GitHub PATs
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack tokens
)

# Fields whose mere presence is a privacy/integrity violation (fail-closed).
PROHIBITED_KEYS = frozenset(
    {
        "prompt",
        "system_prompt",
        "output",
        "tool_output",
        "response",
        "completion",
        "messages",
        "transcript",
        "conversation",
        "clinical_data",
        "patient_data",
        "phi",
        "pii",
        "secret",
        "secrets",
        "api_key",
        "apikey",
        "api_key_value",
        "token",
        "access_token",
        "password",
        "credentials",
        "authorization",
        "private_key",
    }
)

_PROHIBITED_KEY_RE = re.compile(
    r"(prompt|system_prompt|output|secret|api[_-]?key|token|password|credential"
    r"|private[_-]?key|clinical|patient|person[_-]?name|full[_-]?name)",
    re.IGNORECASE,
)


class EventValidationError(Exception):
    """Raised when a v0.2 telemetry event is invalid or unsafe (fail-closed)."""


def _find_schema_file() -> str:
    """Resolves the exact canonical schema path, repo-relative or CWD-relative."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    candidates = [
        os.path.join(repo_root, EVENT_SCHEMA_PATH),
        os.path.abspath(EVENT_SCHEMA_PATH),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise EventValidationError(f"Canonical event schema not found at: {EVENT_SCHEMA_PATH}")


_EVENT_SCHEMA_CACHE: dict[str, Any] | None = None
_MANIFEST_SCHEMA_CACHE: dict[str, Any] | None = None


def _load_event_schema() -> dict[str, Any]:
    global _EVENT_SCHEMA_CACHE
    if _EVENT_SCHEMA_CACHE is None:
        with open(_find_schema_file(), encoding="utf-8") as f:
            _EVENT_SCHEMA_CACHE = json.load(f)
    return _EVENT_SCHEMA_CACHE


def _load_manifest_schema() -> dict[str, Any]:
    global _MANIFEST_SCHEMA_CACHE
    if _MANIFEST_SCHEMA_CACHE is None:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
        schema_path = os.path.join(repo_root, MANIFEST_SCHEMA_PATH)
        if not os.path.isfile(schema_path):
            raise EventValidationError(f"Canonical manifest schema not found at: {MANIFEST_SCHEMA_PATH}")
        with open(schema_path, encoding="utf-8") as schema_file:
            _MANIFEST_SCHEMA_CACHE = json.load(schema_file)
    return _MANIFEST_SCHEMA_CACHE


def _validate_manifest(manifest: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - fail closed without jsonschema
        raise EventValidationError(f"jsonschema unavailable for manifest validation: {exc}") from exc
    validator = Draft202012Validator(_load_manifest_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda error: list(error.absolute_path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}" for error in errors
        )
        raise EventValidationError("Invalid v0.2 telemetry manifest: " + details)


def compute_manifest_hash(manifest: dict[str, Any]) -> str:
    """Computes deterministic SHA-256 integrity digest over a manifest with manifest_hash=''."""
    canonical_copy = copy.deepcopy(manifest)
    if "integrity" in canonical_copy:
        canonical_copy["integrity"]["manifest_hash"] = ""
    canonical = json.dumps(canonical_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_manifest_integrity(manifest: dict[str, Any]) -> tuple[bool, str]:
    """Verifies that manifest['integrity']['manifest_hash'] matches the recalculated digest.

    Returns:
        Tuple of (is_valid, detail_message)
    """
    integrity = manifest.get("integrity", {})
    expected = integrity.get("manifest_hash", "")
    if not expected:
        return False, "Missing integrity.manifest_hash in manifest"
    actual = compute_manifest_hash(manifest)
    if actual != expected:
        return False, f"Manifest integrity hash mismatch: expected {expected}, calculated {actual}"
    return True, actual


def _check_sha256_fields(event: dict[str, Any]) -> None:
    for key, value in event.items():
        if not isinstance(value, str):
            continue
        lowered = key.lower()
        if lowered.endswith("_sha256") or lowered in ("config_hash", "input_hash", "prompt_hash", "system_hash"):
            if not _SHA256_RE.match(value):
                raise EventValidationError(
                    f"Field '{key}' must be exactly 64 lowercase hex chars (sha256), got: {value!r}"
                )


def _check_prohibited_content(event: dict[str, Any]) -> None:
    for key in event:
        lowered = key.lower()
        if lowered in PROHIBITED_KEYS:
            raise EventValidationError(f"Prohibited field present in event: '{key}'")
        # Hash digests and token *counts* are safe derived fields, not content.
        if lowered.endswith(("_hash", "_sha256", "_tokens")):
            continue
        if _PROHIBITED_KEY_RE.search(lowered):
            raise EventValidationError(f"Prohibited field present in event: '{key}'")
    for key, value in event.items():
        if not isinstance(value, str):
            continue
        if _EMAIL_RE.search(value):
            raise EventValidationError(f"Prohibited content (email address) detected in field '{key}'")
        for pattern in _API_KEY_RES:
            if pattern.search(value):
                raise EventValidationError(f"Prohibited content (secret/API key) detected in field '{key}'")


def validate_event(event: Any) -> None:
    """Validates a v0.2 telemetry event fail-closed against the canonical schema.

    Raises EventValidationError on any violation: schema errors, non-canonical
    status/phase/event values, phase_index outside 0..4, missing span_id for
    phase/gate/llm/tool events, missing tool_name/tool_status for tool events,
    malformed sha256 hashes, or any prohibited field/content.
    """
    if not isinstance(event, dict):
        raise EventValidationError("Event must be a JSON object")

    _check_prohibited_content(event)
    _check_sha256_fields(event)

    schema = _load_event_schema()
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - fail closed without jsonschema
        raise EventValidationError(f"jsonschema unavailable for fail-closed validation: {exc}") from exc

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.absolute_path))
    if errors:
        messages = []
        for err in errors:
            location = "/".join(str(p) for p in err.absolute_path) or "<root>"
            messages.append(f"{location}: {err.message}")
        raise EventValidationError("Invalid v0.2 telemetry event: " + "; ".join(messages))


def sanitize_event(event: Any) -> dict[str, Any]:
    """Returns a safe deep copy of the event, raising if prohibited data is present.

    Fail-closed: this never silently strips and returns an unsafe payload; any
    prohibited field or content raises EventValidationError.
    """
    validate_event(event)
    return copy.deepcopy(event)


class WalWriter:
    """Write-ahead log: one deterministic JSON object per line, validated fail-closed."""

    def __init__(self, path: Any) -> None:
        self.path = os.fspath(path)
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")
        self._closed = False

    def append(self, event: Any) -> None:
        """Validates and sanitizes the event, then appends it as one JSON line."""
        if self._closed:
            raise EventValidationError("WalWriter is closed")
        safe_event = sanitize_event(event)
        line = json.dumps(safe_event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self._fh.write(line + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def flush(self) -> None:
        if not self._closed:
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        if not self._closed:
            self._fh.flush()
            self._fh.close()
            self._closed = True

    def __enter__(self) -> WalWriter:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


class TelemetryEmitter:
    """Emit validated v0.2 events and a tamper-evident evidence manifest."""

    def __init__(self, output_dir: Any, run_id: str, trace_id: str) -> None:
        self.output_dir = os.path.realpath(os.fspath(output_dir))
        os.makedirs(self.output_dir, exist_ok=True)
        self.run_id = run_id
        self.trace_id = trace_id
        self.wal = WalWriter(os.path.join(self.output_dir, "telemetry.jsonl"))
        self._artifacts: list[dict[str, str]] = []
        self._git_sha = "0" * 40
        self._dirty_worktree = False
        self._span_counter = 0
        self._run_span_id: str | None = None
        self._phase_spans: dict[str, str] = {}
        self._phase_state: dict[str, tuple[int | None, float]] = {}
        self._run_context: dict[str, Any] = {}

    def _next_span_id(self) -> str:
        self._span_counter += 1
        return f"sp_{self._span_counter}"

    def _emit(self, event_name: str, status: str, parent_span_id: str | None = None, **fields: Any) -> str:
        span_id = self._next_span_id()
        event: dict[str, Any] = {
            "schema_version": "hardening-loop.telemetry.v0.2",
            "event_name": event_name,
            "timestamp": utc_now_iso(),
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "status": status,
        }
        event.update(fields)
        self.wal.append(event)
        return span_id

    def start_run(self, **fields: Any) -> None:
        self._git_sha = fields.get("git_sha", self._git_sha)
        self._dirty_worktree = fields.get("dirty_worktree", self._dirty_worktree)
        self._run_context = dict(fields)
        self._run_span_id = self._emit("hardening_run_started", "STARTED", **fields)

    def complete_run(self, status: str = "PASS", **fields: Any) -> None:
        self._emit("hardening_run_completed", status, **{**self._run_context, **fields})

    def fail_run(self, status: str = "FAIL", **fields: Any) -> None:
        self._emit("hardening_run_failed", status, **{**self._run_context, **fields})

    def start_phase(self, phase: str, phase_index: int | None = None, **fields: Any) -> None:
        if phase_index is None:
            phase_index = {"question": 0, "delete": 1, "simplify": 2, "verify": 3, "codify": 4}.get(phase)
        if phase_index is not None:
            fields["phase_index"] = phase_index
        self._phase_state[phase] = (phase_index, time.monotonic())
        self._phase_spans[phase] = self._emit(
            "hardening_phase_started", "STARTED", parent_span_id=self._run_span_id, phase=phase, **fields
        )

    def complete_phase(
        self,
        phase: str,
        status: str = "PASS",
        phase_index: int | None = None,
        duration_ms: float | None = None,
        **fields: Any,
    ) -> None:
        self._finish_phase(phase, "hardening_phase_completed", status, phase_index, duration_ms, fields)

    def fail_phase(
        self,
        phase: str,
        status: str = "FAIL",
        phase_index: int | None = None,
        duration_ms: float | None = None,
        **fields: Any,
    ) -> None:
        self._finish_phase(phase, "hardening_phase_failed", status, phase_index, duration_ms, fields)

    def _finish_phase(
        self,
        phase: str,
        event_name: str,
        status: str,
        phase_index: int | None,
        duration_ms: float | None,
        fields: dict[str, Any],
    ) -> None:
        state = self._phase_state.get(phase)
        if phase_index is None and state is not None:
            phase_index = state[0]
        if phase_index is None:
            phase_index = {"question": 0, "delete": 1, "simplify": 2, "verify": 3, "codify": 4}.get(phase)
        if duration_ms is None:
            duration_ms = round((time.monotonic() - state[1]) * 1000, 3) if state is not None else 0.0
        fields.update(phase_index=phase_index, duration_ms=duration_ms)
        self._emit(
            event_name,
            status,
            parent_span_id=self._phase_spans.get(phase, self._run_span_id),
            phase=phase,
            **fields,
        )

    def record_gate(self, gate_id: str, gate_status: str, status: str = "PASS", **fields: Any) -> None:
        self._emit(
            "hardening_gate_evaluated",
            status,
            parent_span_id=self._phase_spans.get(fields.get("phase", ""), self._run_span_id),
            gate_id=gate_id,
            gate_status=gate_status,
            **fields,
        )

    def record_decision(
        self,
        decision_id: str,
        decision_type: str,
        decision_reason: str,
        status: str = "PASS",
        **fields: Any,
    ) -> None:
        self._emit(
            "hardening_decision_recorded",
            status,
            parent_span_id=self._phase_spans.get(fields.get("phase", ""), self._run_span_id),
            decision_id=decision_id,
            decision_type=decision_type,
            decision_reason=decision_reason,
            **fields,
        )

    def write_artifact(self, path: Any, artifact_type: str = "artifact") -> dict[str, str]:
        artifact_path = os.path.realpath(os.fspath(path))
        try:
            inside_output_dir = os.path.commonpath((artifact_path, self.output_dir)) == self.output_dir
        except ValueError:
            inside_output_dir = False
        if not inside_output_dir:
            raise ValueError(f"Artifact path is outside output_dir: {path!r}")
        if not os.path.isfile(artifact_path):
            raise FileNotFoundError(artifact_path)
        relative_path = os.path.relpath(artifact_path, self.output_dir).replace(os.sep, "/")
        with open(artifact_path, "rb") as artifact_file:
            artifact_sha256 = hashlib.sha256(artifact_file.read()).hexdigest()
        record = {
            "path": relative_path,
            "type": artifact_type,
            "sha256": artifact_sha256,
        }
        self._artifacts = [item for item in self._artifacts if item["path"] != relative_path]
        self._artifacts.append(record)
        self._emit(
            "hardening_artifact_written",
            "PASS",
            artifact_path=relative_path,
            artifact_type=artifact_type,
            artifact_sha256=record["sha256"],
        )
        return record

    def write_manifest(
        self,
        final_status: str,
        artifacts: list[Any] | None = None,
        git_sha: str | None = None,
        dirty_worktree: bool | None = None,
        branch: str | None = None,
        canonical_manifest_digest: str | None = None,
        work_unit: dict[str, Any] | None = None,
        envelopes: list[dict[str, Any]] | None = None,
        runtime_telemetry: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if artifacts is not None:
            for artifact in artifacts:
                if isinstance(artifact, dict):
                    self.write_artifact(artifact["path"], artifact.get("type", "artifact"))
                else:
                    self.write_artifact(artifact)
        if not any(item["type"] == "patch" for item in self._artifacts):
            patch_path = os.path.join(self.output_dir, "patch.diff")
            with open(patch_path, "wb") as patch_file:
                patch_file.write(b"")
            self.write_artifact(patch_path, artifact_type="patch")

        self._write_local_evidence()
        # The manifest event must be part of telemetry.jsonl before its final hash
        # is registered, but cannot carry the manifest hash without a circular dependency.
        self._emit(
            "hardening_manifest_written",
            "PASS",
            artifact_path="evidence_manifest.json",
            artifact_type="manifest",
        )
        self.wal.flush()
        self._register_artifact_hash(os.path.join(self.output_dir, "telemetry.jsonl"), "telemetry")

        manifest: dict[str, Any] = {
            "schema_version": "hardening-loop.manifest.v0.2",
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "created_at": utc_now_iso(),
            "git_sha": git_sha if git_sha is not None else self._git_sha,
            "dirty_worktree": dirty_worktree if dirty_worktree is not None else self._dirty_worktree,
            "final_status": final_status,
            "artifacts": list(self._artifacts),
            "integrity": {
                "hash_algorithm": "sha256",
                "manifest_hash": "",
                "artifact_count": len(self._artifacts),
                "integrity_status": "PASS",
            },
        }
        if branch is not None:
            manifest["branch"] = branch
        if canonical_manifest_digest is not None:
            manifest["canonical_manifest_digest"] = canonical_manifest_digest
        if work_unit is not None:
            manifest["work_unit"] = work_unit
        if envelopes is not None:
            manifest["envelopes"] = envelopes
        if runtime_telemetry is not None:
            manifest["runtime_telemetry"] = runtime_telemetry

        manifest["integrity"]["manifest_hash"] = compute_manifest_hash(manifest)
        _validate_manifest(manifest)
        manifest_path = os.path.join(self.output_dir, "evidence_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, indent=2, sort_keys=True)
            manifest_file.write("\n")
        return manifest

    def _register_artifact_hash(self, path: Any, artifact_type: str) -> dict[str, str]:
        artifact_path = os.path.realpath(os.fspath(path))
        try:
            inside_output_dir = os.path.commonpath((artifact_path, self.output_dir)) == self.output_dir
        except ValueError:
            inside_output_dir = False
        if not inside_output_dir:
            raise ValueError(f"Artifact path is outside output_dir: {path!r}")
        if not os.path.isfile(artifact_path):
            raise FileNotFoundError(artifact_path)
        relative_path = os.path.relpath(artifact_path, self.output_dir).replace(os.sep, "/")
        if not relative_path or "\\" in relative_path or ".." in relative_path.split("/"):
            raise ValueError(f"Unsafe artifact path: {relative_path!r}")
        with open(artifact_path, "rb") as artifact_file:
            digest = hashlib.sha256(artifact_file.read()).hexdigest()
        record = {"path": relative_path, "type": artifact_type, "sha256": digest}
        self._artifacts = [item for item in self._artifacts if item["path"] != relative_path]
        self._artifacts.append(record)
        return record

    def _write_local_evidence(self) -> None:
        self.wal.flush()
        events: list[dict[str, Any]] = []
        wal_path = os.path.join(self.output_dir, "telemetry.jsonl")
        with open(wal_path, encoding="utf-8") as wal_file:
            for line in wal_file:
                if line.strip():
                    events.append(json.loads(line))

        gate_events = [
            event
            for event in events
            if event.get("event_name") in {"hardening_gate_evaluated", "hardening_gate_blocked"}
        ]
        decision_events = [event for event in events if event.get("event_name") == "hardening_decision_recorded"]
        gate_path = os.path.join(self.output_dir, "gate_results.json")
        decision_path = os.path.join(self.output_dir, "decision_records.jsonl")
        hashes_path = os.path.join(self.output_dir, "artifact_hashes.json")
        structured_path = os.path.join(self.output_dir, "structured.log.jsonl")
        with open(gate_path, "w", encoding="utf-8") as gate_file:
            json.dump(gate_events, gate_file, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            gate_file.write("\n")
        with open(decision_path, "w", encoding="utf-8") as decision_file:
            for event in decision_events:
                decision_file.write(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        with open(hashes_path, "w", encoding="utf-8") as hashes_file:
            json.dump(
                sorted(self._artifacts, key=lambda item: item["path"]),
                hashes_file,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            hashes_file.write("\n")
        with open(structured_path, "w", encoding="utf-8") as structured_file:
            structured_file.write(
                "\n".join(
                    json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True) for event in events
                )
            )
            if events:
                structured_file.write("\n")
        self._register_artifact_hash(gate_path, "evidence")
        self._register_artifact_hash(decision_path, "evidence")
        self._register_artifact_hash(hashes_path, "evidence")
        self._register_artifact_hash(structured_path, "evidence")


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
        peak_memory_mb = get_process_memory_mb()
        memory_delta_mb = max(0.0, round(peak_memory_mb - self.initial_memory_mb, 2))

        return {
            "timestamp": utc_now_iso(),
            "total_duration_ms": total_duration_ms,
            "phase_durations_ms": self.phase_durations,
            "total_loc_analyzed": total_loc,
            "total_ast_nodes_visited": total_ast_nodes,
            "throughput_loc_per_sec": throughput_loc_sec,
            "initial_memory_mb": self.initial_memory_mb,
            "peak_memory_mb": peak_memory_mb,
            "memory_delta_mb": memory_delta_mb,
        }
