"""PostHog Telemetry Sink — Idempotent telemetry export to PostHog Cloud (Ley XI)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .models import sha256_text, utc_now_iso


class PostHogSinkError(Exception):
    """Raised when telemetry export to PostHog fails."""


class PostHogTelemetrySink:
    """Exports structured telemetry events to PostHog Cloud with strict idempotency and path sanitization."""

    DEFAULT_HOST = "https://us.i.posthog.com"
    ALLOWED_HOSTS = frozenset(
        {
            "https://us.i.posthog.com",
            "https://eu.i.posthog.com",
            "https://app.posthog.com",
            "https://us.posthog.com",
            "https://eu.posthog.com",
        }
    )

    def __init__(self, api_key: str | None = None, host: str | None = None):
        self.api_key = api_key or os.getenv("POSTHOG_API_KEY") or os.getenv("POSTHOG_PROJECT_TOKEN")
        raw_host = (host or os.getenv("POSTHOG_HOST") or self.DEFAULT_HOST).rstrip("/")
        self.host = self._validate_host(raw_host)

    @classmethod
    def _validate_host(cls, host: str) -> str:
        parsed = urllib.parse.urlparse(host)
        if parsed.scheme not in ("http", "https"):
            raise PostHogSinkError(f"Invalid PostHog host scheme '{parsed.scheme}': must be https://")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            raise PostHogSinkError("HTTP is only permitted for localhost/127.0.0.1 in PostHog host configuration.")
        return host

    @staticmethod
    def _sanitize_target_path(path: str) -> str:
        """Sanitizes local absolute paths to avoid leaking filesystem and username details."""
        if not path:
            return ""
        # If it contains absolute developer paths, emit sanitized digest or basename
        if path.startswith(("/", "C:\\", "\\\\")):
            fname = os.path.basename(path)
            path_digest = sha256_text(path)[:12]
            return f"{fname}#hash:{path_digest}"
        return path

    def format_telemetry_batch(
        self, manifest: dict[str, Any], distinct_id: str = "antigravity-hardening-loop"
    ) -> list[dict[str, Any]]:
        """Transforms a Hardening Loop manifest into typed PostHog events with $insert_id."""
        events: list[dict[str, Any]] = []
        telemetry = manifest.get("runtime_telemetry", {})
        work_unit = manifest.get("work_unit", {})
        canonical_digest = manifest.get("canonical_manifest_digest", "")

        raw_target = work_unit.get("target_path", "")
        sanitized_target = self._sanitize_target_path(raw_target)

        # 1. Run Summary Event
        run_event = {
            "event": "hardening_run_completed",
            "distinct_id": distinct_id,
            "timestamp": telemetry.get("timestamp", utc_now_iso()),
            "properties": {
                "$insert_id": f"run-{canonical_digest[:16]}",
                "canonical_manifest_digest": canonical_digest,
                "work_unit_id": work_unit.get("work_unit_id", ""),
                "target_path": sanitized_target,
                "total_duration_ms": telemetry.get("total_duration_ms", 0.0),
                "total_loc_analyzed": telemetry.get("total_loc_analyzed", 0),
                "total_ast_nodes_visited": telemetry.get("total_ast_nodes_visited", 0),
                "throughput_loc_per_sec": telemetry.get("throughput_loc_per_sec", 0.0),
                "initial_memory_mb": telemetry.get("initial_memory_mb", 0.0),
                "peak_memory_mb": telemetry.get("peak_memory_mb", 0.0),
                "memory_delta_mb": telemetry.get("memory_delta_mb", 0.0),
                "final_status": telemetry.get("final_status", "UNKNOWN"),
                "phases_executed_count": len(work_unit.get("phases_executed", [])),
                "$property_type": {
                    "total_duration_ms": "Numeric",
                    "total_loc_analyzed": "Numeric",
                    "total_ast_nodes_visited": "Numeric",
                    "throughput_loc_per_sec": "Numeric",
                    "peak_memory_mb": "Numeric",
                    "memory_delta_mb": "Numeric",
                },
            },
        }
        events.append(run_event)

        # 2. Phase-Level Execution Events
        for envelope in manifest.get("envelopes", []):
            canonical = envelope.get("canonical_evidence", {})
            receipt = envelope.get("runtime_receipt", {})
            evidence_id = canonical.get("evidence_id", "")
            phase = canonical.get("phase", "")

            phase_event = {
                "event": "hardening_phase_executed",
                "distinct_id": distinct_id,
                "timestamp": receipt.get("timestamp", utc_now_iso()),
                "properties": {
                    "$insert_id": evidence_id,
                    "evidence_id": evidence_id,
                    "phase": phase,
                    "duration_ms": receipt.get("duration_ms", 0.0),
                    "status": receipt.get("status", "UNKNOWN"),
                    "input_hash": canonical.get("input_hash", ""),
                    "output_hash": canonical.get("output_hash", ""),
                    "execution_context_hash": canonical.get("execution_context_hash", ""),
                    "$property_type": {
                        "duration_ms": "Numeric",
                    },
                },
            }
            events.append(phase_event)

        return events

    def export(
        self,
        manifest: dict[str, Any],
        distinct_id: str = "antigravity-hardening-loop",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Sends the formatted telemetry batch to PostHog Cloud or returns dry-run payload."""
        batch = self.format_telemetry_batch(manifest, distinct_id=distinct_id)

        if dry_run:
            return {
                "status": "DRY_RUN",
                "events_count": len(batch),
                "events": batch,
                "api_key_configured": bool(self.api_key),
            }

        if not self.api_key:
            raise PostHogSinkError(
                "Missing PostHog API Key. Provide --api-key or configure POSTHOG_API_KEY environment variable. "
                "Use --dry-run to simulate telemetry export without credentials."
            )

        endpoint = f"{self.host}/batch/"
        payload = {
            "api_key": self.api_key,
            "batch": batch,
        }
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "HardeningLoop-Telemetry/0.1"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                res_body = response.read().decode("utf-8")
                return {
                    "status": "SENT",
                    "http_status": response.status,
                    "events_count": len(batch),
                    "response": json.loads(res_body) if res_body else {},
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            raise PostHogSinkError(f"PostHog HTTP Error {e.code}: {err_body}") from e
        except Exception as e:
            raise PostHogSinkError(f"Failed to connect to PostHog: {e}") from e
