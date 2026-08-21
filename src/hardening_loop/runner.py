"""Hardening Loop Orchestrator — Executes phases and emits deterministic evidence packages."""

import json
import os
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
    utc_now_iso,
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

        self.work_unit = WorkUnit(
            work_unit_id=f"wu-{target_hash[:12] if target_hash else '000000000000'}",
            target_path=self.target_path,
            target_hash=target_hash,
            state=HardeningState.DRAFT,
            metadata={
                "runner_version": "0.1.0-beta",
                "method_version": "v0.3",
                "execution_context_hash": compute_execution_context_hash(),
            },
        )
        self.envelopes: list[EvidenceEnvelope] = []

    def run_phase(self, phase_name: PhaseName, context: dict[str, Any] | None = None) -> EvidenceEnvelope:
        phase = self.PHASE_MAP.get(phase_name)
        if not phase:
            raise ValueError(f"Unknown phase '{phase_name}'")

        if self.work_unit.state == HardeningState.DRAFT:
            StateMachine.transition(self.work_unit, HardeningState.AUDITING, reason="Starting hardening run")

        ctx = context or {}
        ctx["evidence_ids"] = [e.evidence_id for e in self.envelopes]
        envelope = phase.run(self.target_path, ctx, self.output_dir)
        self.envelopes.append(envelope)
        self.work_unit.phases_executed.append(phase_name.value)

        # Write phase-specific canonical artifacts to output directory
        self._write_phase_artifacts(phase_name, envelope)

        # Handle state progression
        if phase_name == PhaseName.SIMPLIFY:
            if self.work_unit.state == HardeningState.AUDITING:
                StateMachine.transition(
                    self.work_unit, HardeningState.PATCH_PROPOSED, reason="Audit and simplification complete"
                )
        elif phase_name == PhaseName.VERIFY:
            if envelope.status == VerificationStatus.PASS and self.work_unit.state == HardeningState.PATCH_PROPOSED:
                StateMachine.transition(self.work_unit, HardeningState.VERIFIED, reason="Verification tests passed")
        elif phase_name == PhaseName.CODIFY:
            if self.work_unit.state == HardeningState.VERIFIED:
                StateMachine.transition(
                    self.work_unit, HardeningState.KNOWLEDGE_CANDIDATE, reason="Knowledge candidates formulated"
                )

        return envelope

    def _write_phase_artifacts(self, phase_name: PhaseName, envelope: EvidenceEnvelope) -> None:
        payload = envelope.canonical.artifact_payload
        if phase_name == PhaseName.QUESTION:
            with open(os.path.join(self.output_dir, "requirements_audit.json"), "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
        elif phase_name == PhaseName.DELETE:
            with open(os.path.join(self.output_dir, "deletion_candidates.json"), "w", encoding="utf-8") as f:
                json.dump(payload.get("deletion_candidates", []), f, indent=2, sort_keys=True)
            with open(os.path.join(self.output_dir, "diff.patch"), "w", encoding="utf-8") as f:
                f.write(payload.get("diff_patch", ""))
            with open(os.path.join(self.output_dir, "rollback_reference.json"), "w", encoding="utf-8") as f:
                json.dump(payload.get("rollback_reference", {}), f, indent=2, sort_keys=True)
        elif phase_name == PhaseName.SIMPLIFY:
            with open(os.path.join(self.output_dir, "contract_diff.json"), "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
        elif phase_name == PhaseName.VERIFY:
            with open(os.path.join(self.output_dir, "test_results.json"), "w", encoding="utf-8") as f:
                json.dump(payload.get("test_results", {}), f, indent=2, sort_keys=True)
            with open(os.path.join(self.output_dir, "benchmark.json"), "w", encoding="utf-8") as f:
                json.dump(payload.get("benchmark", {}), f, indent=2, sort_keys=True)
            with open(os.path.join(self.output_dir, "runtime_evidence.json"), "w", encoding="utf-8") as f:
                json.dump(payload.get("runtime_evidence", {}), f, indent=2, sort_keys=True)
        elif phase_name == PhaseName.CODIFY:
            candidates = payload.get("candidates", [])
            with open(os.path.join(self.output_dir, "knowledge_candidate.yaml"), "w", encoding="utf-8") as f:
                yaml.dump(candidates, f, sort_keys=False, allow_unicode=True)
            with open(os.path.join(self.output_dir, "admission_record.json"), "w", encoding="utf-8") as f:
                json.dump(payload.get("admission_record", {}), f, indent=2, sort_keys=True)

    def run_all(self) -> list[EvidenceEnvelope]:
        order = [
            PhaseName.QUESTION,
            PhaseName.DELETE,
            PhaseName.SIMPLIFY,
            PhaseName.VERIFY,
            PhaseName.CODIFY,
        ]
        for phase in order:
            self.run_phase(phase)

        # Compute deterministic canonical manifest digest over canonical evidence only
        canonical_blocks = [e.canonical.to_dict() for e in self.envelopes]
        canonical_manifest_digest = sha256_dict({"phases": canonical_blocks})

        manifest = {
            "canonical_manifest_digest": canonical_manifest_digest,
            "work_unit": self.work_unit.to_dict(),
            "envelopes": [e.to_dict() for e in self.envelopes],
            "runtime_telemetry": {
                "completed_at": utc_now_iso(),
                "final_status": "PASS" if all(e.status == VerificationStatus.PASS for e in self.envelopes) else "WARN",
            },
        }
        with open(os.path.join(self.output_dir, "evidence_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        with open(os.path.join(self.output_dir, "work_unit.json"), "w", encoding="utf-8") as f:
            json.dump(self.work_unit.to_dict(), f, indent=2, sort_keys=True)

        return self.envelopes
