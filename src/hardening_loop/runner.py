"""Hardening Loop Orchestrator — Executes phases and emits deterministic evidence packages."""

import json
import os
import subprocess
from typing import Any

import yaml

from .models import (
    EvidenceEnvelope,
    HardeningState,
    PhaseName,
    VerificationStatus,
    WorkUnit,
    compute_canonical_directory_digest,
    compute_execution_context_hash,
    sha256_dict,
    sha256_text,
)
from .phases import (
    BasePhase,
    CodifyPhase,
    DeletePhase,
    QuestionPhase,
    SimplifyPhase,
    VerifyPhase,
)
from .states import StateMachine
from .telemetry import TelemetryCollector, TelemetryEmitter


def aggregate_final_status(envelopes: list[EvidenceEnvelope]) -> str:
    """Computes monotonic final status with strict precedence: FAIL/BLOCKED > WARN > PASS."""
    if not envelopes:
        return "UNKNOWN"
    statuses = {e.status for e in envelopes}
    if any(s in (VerificationStatus.FAIL, VerificationStatus.BLOCKED) for s in statuses):
        return "FAIL"
    if VerificationStatus.WARN in statuses:
        return "WARN"
    if all(s == VerificationStatus.PASS for s in statuses):
        return "PASS"
    return "WARN"


def count_target_loc(target_path: str) -> int:
    """Counts total lines of code in target file or recursive python files in directory."""
    if not os.path.exists(target_path):
        return 0
    if os.path.isfile(target_path):
        try:
            with open(target_path, encoding="utf-8", errors="replace") as f:
                return len(f.readlines())
        except Exception:
            return 0
    total = 0
    for root, _, files in os.walk(target_path):
        for file in sorted(files):
            if file.endswith(".py"):
                try:
                    with open(os.path.join(root, file), encoding="utf-8", errors="replace") as f:
                        total += len(f.readlines())
                except Exception:
                    pass
    return total


class HardeningRunner:
    """Coordinates execution of the Algorithmic Code Hardening Loop."""

    PHASE_MAP: dict[PhaseName, BasePhase] = {
        PhaseName.QUESTION: QuestionPhase(),
        PhaseName.DELETE: DeletePhase(),
        PhaseName.SIMPLIFY: SimplifyPhase(),
        PhaseName.VERIFY: VerifyPhase(),
        PhaseName.CODIFY: CodifyPhase(),
    }

    def __init__(self, target_path: str, output_dir: str):
        self.target_path = os.path.abspath(target_path)
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        target_hash = compute_canonical_directory_digest(self.target_path)
        run_id = f"wu-{target_hash[:12] if target_hash else '000000000000'}"
        trace_id = f"tr_{run_id}"

        self.work_unit = WorkUnit(
            work_unit_id=run_id,
            target_path=self.target_path,
            target_hash=target_hash,
            state=HardeningState.DRAFT,
            metadata={
                "runner_version": "0.3.0",
                "method_version": "v0.3",
                "execution_context_hash": compute_execution_context_hash(),
            },
        )
        self.envelopes: list[EvidenceEnvelope] = []
        self.telemetry = TelemetryCollector()
        self.emitter = TelemetryEmitter(output_dir=self.output_dir, run_id=run_id, trace_id=trace_id)
        self._emitter_run_started = False

    def _git_context(self) -> dict[str, Any]:
        repo_dir = os.path.dirname(self.target_path) or "."

        def _git(*args: str) -> str | None:
            try:
                result = subprocess.run(["git", *args], cwd=repo_dir, capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                return None
            if result.returncode != 0:
                return None
            return result.stdout.strip() or None

        sha = _git("rev-parse", "HEAD")
        branch = _git("rev-parse", "--abbrev-ref", "HEAD")
        porcelain = _git("status", "--porcelain")
        return {
            "git_sha": sha if sha and len(sha) == 40 else "0" * 40,
            "branch": branch or "main",
            "dirty_worktree": bool(porcelain),
        }

    def _ensure_run_started(self) -> None:
        if not self._emitter_run_started:
            git_ctx = self._git_context()
            input_h = self.work_unit.target_hash if self.work_unit.target_hash else sha256_text("")
            self.emitter.start_run(
                git_sha=git_ctx["git_sha"],
                branch=git_ctx["branch"],
                dirty_worktree=git_ctx["dirty_worktree"],
                runner_version=str(self.work_unit.metadata.get("runner_version", "0.3.0")),
                config_hash=str(self.work_unit.metadata.get("execution_context_hash", sha256_text("cfg"))),
                input_hash=input_h,
            )
            self._emitter_run_started = True

    def run_phase(self, phase_name: PhaseName, context: dict[str, Any] | None = None) -> EvidenceEnvelope:
        phase = self.PHASE_MAP.get(phase_name)
        if not phase:
            raise ValueError(f"Unknown phase '{phase_name}'")

        self._ensure_run_started()

        if self.work_unit.state == HardeningState.DRAFT:
            StateMachine.transition(self.work_unit, HardeningState.AUDITING, reason="Starting hardening run")

        self.telemetry.start_phase(phase_name.value)
        self.emitter.start_phase(phase_name.value)

        ctx = context or {}
        ctx["evidence_ids"] = [e.evidence_id for e in self.envelopes]
        envelope = phase.run(self.target_path, ctx, self.output_dir)
        self.envelopes.append(envelope)
        self.work_unit.phases_executed.append(phase_name.value)

        # Extract telemetry metrics from payload
        payload = envelope.canonical.artifact_payload
        loc_count = payload.get("total_lines_of_code", 0)
        if not loc_count:
            loc_count = count_target_loc(self.target_path)
        ast_nodes = payload.get("total_ast_nodes_visited", 0)

        self.telemetry.record_phase_metrics(phase_name.value, loc=loc_count, ast_nodes=ast_nodes)
        duration_ms = self.telemetry.end_phase(phase_name.value)

        # Complete phase in WAL emitter
        phase_status = envelope.status.value
        if envelope.status in (VerificationStatus.FAIL, VerificationStatus.BLOCKED):
            self.emitter.fail_phase(phase_name.value, status=phase_status, duration_ms=duration_ms)
        else:
            self.emitter.complete_phase(phase_name.value, status=phase_status, duration_ms=duration_ms)

        # Write phase-specific canonical artifacts to output directory and register in emitter
        self._write_phase_artifacts(phase_name, envelope)

        # Handle state progression
        if phase_name == PhaseName.SIMPLIFY:
            if self.work_unit.state == HardeningState.AUDITING:
                StateMachine.transition(
                    self.work_unit, HardeningState.PATCH_PROPOSED, reason="Audit and simplification complete"
                )
        elif phase_name == PhaseName.VERIFY:
            if (
                envelope.status in (VerificationStatus.PASS, VerificationStatus.WARN)
                and self.work_unit.state == HardeningState.PATCH_PROPOSED
            ):
                StateMachine.transition(
                    self.work_unit,
                    HardeningState.VERIFIED,
                    reason="Verification passed"
                    if envelope.status == VerificationStatus.PASS
                    else "Verification passed with warnings",
                )
        elif phase_name == PhaseName.CODIFY:
            if self.work_unit.state == HardeningState.VERIFIED:
                StateMachine.transition(
                    self.work_unit, HardeningState.KNOWLEDGE_CANDIDATE, reason="Knowledge candidates formulated"
                )

        return envelope

    def _write_phase_artifacts(self, phase_name: PhaseName, envelope: EvidenceEnvelope) -> None:
        payload = envelope.canonical.artifact_payload
        if phase_name == PhaseName.QUESTION:
            p = os.path.join(self.output_dir, "requirements_audit.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p, artifact_type="evidence")
        elif phase_name == PhaseName.DELETE:
            p1 = os.path.join(self.output_dir, "deletion_candidates.json")
            with open(p1, "w", encoding="utf-8") as f:
                json.dump(payload.get("deletion_candidates", []), f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p1, artifact_type="evidence")

            p2 = os.path.join(self.output_dir, "diff.patch")
            with open(p2, "w", encoding="utf-8") as f:
                f.write(payload.get("diff_patch", ""))
            self.emitter.write_artifact(p2, artifact_type="patch")

            p3 = os.path.join(self.output_dir, "rollback_reference.json")
            with open(p3, "w", encoding="utf-8") as f:
                json.dump(payload.get("rollback_reference", {}), f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p3, artifact_type="evidence")
        elif phase_name == PhaseName.SIMPLIFY:
            p = os.path.join(self.output_dir, "contract_diff.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p, artifact_type="evidence")
        elif phase_name == PhaseName.VERIFY:
            p1 = os.path.join(self.output_dir, "test_results.json")
            with open(p1, "w", encoding="utf-8") as f:
                json.dump(payload.get("test_results", {}), f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p1, artifact_type="evidence")

            p2 = os.path.join(self.output_dir, "benchmark.json")
            with open(p2, "w", encoding="utf-8") as f:
                json.dump(payload.get("benchmark", {}), f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p2, artifact_type="evidence")

            p3 = os.path.join(self.output_dir, "runtime_evidence.json")
            with open(p3, "w", encoding="utf-8") as f:
                json.dump(payload.get("runtime_evidence", {}), f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p3, artifact_type="evidence")
        elif phase_name == PhaseName.CODIFY:
            # Read full candidates with schema fields (including created_at)
            codify_phase = self.PHASE_MAP[PhaseName.CODIFY]
            candidates = getattr(codify_phase, "_last_full_candidates", payload.get("candidates", []))
            p1 = os.path.join(self.output_dir, "knowledge_candidate.yaml")
            with open(p1, "w", encoding="utf-8") as f:
                yaml.dump(candidates, f, sort_keys=False, allow_unicode=True)
            self.emitter.write_artifact(p1, artifact_type="evidence")

            p2 = os.path.join(self.output_dir, "admission_record.json")
            with open(p2, "w", encoding="utf-8") as f:
                json.dump(payload.get("admission_record", {}), f, indent=2, sort_keys=True)
            self.emitter.write_artifact(p2, artifact_type="evidence")

    def run_all(self) -> list[EvidenceEnvelope]:
        """Executes all 5 hardening phases in sequence with strict Fail-Closed abort on error."""
        self._ensure_run_started()
        git_ctx = self._git_context()

        order = [
            PhaseName.QUESTION,
            PhaseName.DELETE,
            PhaseName.SIMPLIFY,
            PhaseName.VERIFY,
            PhaseName.CODIFY,
        ]
        for phase in order:
            env = self.run_phase(phase)
            # Fail-closed (Ley VIII): abort immediately on critical/high verification failure
            if env.status in (VerificationStatus.FAIL, VerificationStatus.BLOCKED):
                break

        final_status = aggregate_final_status(self.envelopes)

        if final_status == "FAIL":
            self.emitter.fail_run(
                status="FAIL",
                git_sha=git_ctx["git_sha"],
                branch=git_ctx["branch"],
                dirty_worktree=git_ctx["dirty_worktree"],
                runner_version=str(self.work_unit.metadata.get("runner_version", "0.3.0")),
                config_hash=str(self.work_unit.metadata.get("execution_context_hash", sha256_text("cfg"))),
                input_hash=self.work_unit.target_hash if self.work_unit.target_hash else sha256_text(""),
            )
        else:
            self.emitter.complete_run(
                status=final_status,
                git_sha=git_ctx["git_sha"],
                branch=git_ctx["branch"],
                dirty_worktree=git_ctx["dirty_worktree"],
                runner_version=str(self.work_unit.metadata.get("runner_version", "0.3.0")),
                config_hash=str(self.work_unit.metadata.get("execution_context_hash", sha256_text("cfg"))),
                input_hash=self.work_unit.target_hash if self.work_unit.target_hash else sha256_text(""),
            )

        # Write unified evidence_manifest.json with integrity hashes and telemetry
        self._write_manifest(final_status)
        return self.envelopes

    def _write_manifest(self, final_status: str) -> dict[str, Any]:
        """Writes the canonical manifest with epistemic blocks, artifact hashes, and telemetry."""
        canonical_blocks = [e.canonical.to_dict() for e in self.envelopes]
        canonical_manifest_digest = sha256_dict({"phases": canonical_blocks})

        telemetry_summary = self.telemetry.get_summary()
        telemetry_summary["final_status"] = final_status

        # Write work unit state
        with open(os.path.join(self.output_dir, "work_unit.json"), "w", encoding="utf-8") as f:
            json.dump(self.work_unit.to_dict(), f, indent=2, sort_keys=True)
        self.emitter.write_artifact(os.path.join(self.output_dir, "work_unit.json"), artifact_type="work_unit")

        # Use emitter to flush WAL and compute physical artifact hashes
        manifest = self.emitter.write_manifest(final_status=final_status)

        # Add backward-compatible and epistemic metadata fields to manifest
        manifest["canonical_manifest_digest"] = canonical_manifest_digest
        manifest["work_unit"] = self.work_unit.to_dict()
        manifest["envelopes"] = [e.to_dict() for e in self.envelopes]
        manifest["runtime_telemetry"] = telemetry_summary

        manifest_path = os.path.join(self.output_dir, "evidence_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        return manifest
