"""Phase 5: CODIFY VALIDATED LEARNING — Structure candidate rules dynamically from upstream verified findings."""

import re
from typing import Any

from ..admission import KnowledgeAdmissionGate
from ..models import (
    FindingCategory,
    FindingSeverity,
    KnowledgeCandidate,
    PhaseName,
    VerificationStatus,
    sha256_text,
)
from .base import BasePhase, is_internal_framework_target


def _parse_lines(loc_str: str) -> list[int]:
    """Extracts line numbers from location strings like 'mod.py:42'."""
    match = re.search(r":(\d+)", str(loc_str))
    if match:
        return [int(match.group(1))]
    return [1]


class CodifyPhase(BasePhase):
    """Packages validated learnings into candidates for human/curator review without shared mutable state."""

    def __init__(self):
        super().__init__(name=PhaseName.CODIFY)

    def execute(
        self, target_path: str, context: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], VerificationStatus]:
        checks = []
        evidence_refs = context.get("evidence_ids", [])
        candidates: list[KnowledgeCandidate] = []

        is_self_audit = is_internal_framework_target(target_path)

        if is_self_audit:
            # Self-audit candidate 1: Mandatory Envelope Provenance
            cid_1 = f"kc-{sha256_text('RULE-EVIDENCE-001')[:12]}"
            candidates.append(
                KnowledgeAdmissionGate.create_candidate(
                    candidate_id=cid_1,
                    observation="Evidence envelopes must decouple canonical evidence from runtime receipts and track method_version, schema_version, and execution_context_hash for hermetic reproducibility.",
                    category=FindingCategory.PROVENANCE_GAP,
                    severity=FindingSeverity.HIGH,
                    finding_description="Without method_version, schema_version, and execution_context_hash, evidence artifacts cannot be cross-validated across different CI or host environments.",
                    target_lines=[1, 2, 3],
                    rule_id="RULE-EVIDENCE-001",
                    rule_title="Decoupled Canonical Evidence and Execution Context in Envelopes",
                    enforcement_mechanism="SCHEMA_GUARD",
                    rationale="Hermetic reproducibility requires capturing the exact runtime execution context digest, schema version, and framework version.",
                    evidence_references=evidence_refs,
                    suggested_fix="Include canonical_evidence sub-object with execution_context_hash as required schema properties in evidence_envelope.schema.json.",
                )
            )

            # Self-audit candidate 2: Strict Admission Gate Invariant
            cid_2 = f"kc-{sha256_text('RULE-GATE-001')[:12]}"
            candidates.append(
                KnowledgeAdmissionGate.create_candidate(
                    candidate_id=cid_2,
                    observation="Knowledge Admission Gate must strictly forbid transitions to ADMITTED without non-empty reviewer identity.",
                    category=FindingCategory.SECURITY,
                    severity=FindingSeverity.CRITICAL,
                    finding_description="An unauthenticated or automated reviewer could pollute canonical knowledge.",
                    target_lines=[40, 41, 42],
                    rule_id="RULE-GATE-001",
                    rule_title="Mandatory Human Reviewer Identity for Knowledge Promotion",
                    enforcement_mechanism="CONTRACT_VALIDATOR",
                    rationale="The knowledge base remains trustworthy only if all promoted rules have verifiable human/curator provenance.",
                    evidence_references=evidence_refs,
                    suggested_fix="Enforce reviewer.strip() check in KnowledgeAdmissionGate.review_candidate.",
                )
            )
        else:
            # Dynamically formulate candidates from ACTUAL upstream findings
            deletion_candidates = context.get("deletion_candidates", [])
            challenged_reqs = context.get("challenged_requirements", [])
            verify_failures = context.get("verify_failures", [])

            # 1. Formulate candidates from deletion findings with stable finding-derived IDs
            for dc in deletion_candidates:
                target_str = dc.get("target", "unnecessary_harness")
                loc = dc.get("location", "")
                rationale = dc.get("rationale", "Dead or overprivileged capability identified.")
                action = dc.get("action", "DELETE_OR_REFACTOR")
                sev_str = dc.get("severity", "MEDIUM")
                try:
                    severity = FindingSeverity(sev_str)
                except ValueError:
                    return (
                        {"error": f"Invalid severity '{sev_str}' in deletion candidate for '{target_str}'"},
                        [f"Invalid severity '{sev_str}' (fail-closed)"],
                        VerificationStatus.FAIL,
                    )
                category = (
                    FindingCategory.SECURITY
                    if "shell" in target_str or "eval" in target_str or "exec" in target_str
                    else FindingCategory.DEAD_HARNESS
                )

                rule_id = f"RULE-DEL-{sha256_text(loc + target_str)[:6].upper()}"
                cid = f"kc-{sha256_text(rule_id + target_str)[:12]}"
                candidates.append(
                    KnowledgeAdmissionGate.create_candidate(
                        candidate_id=cid,
                        observation=f"Audited target contains {target_str} at {loc}.",
                        category=category,
                        severity=severity,
                        finding_description=rationale,
                        target_lines=_parse_lines(loc),
                        rule_id=rule_id,
                        rule_title=f"Eliminate {target_str} in favor of safe structured alternatives",
                        enforcement_mechanism="CONTRACT_VALIDATOR",
                        rationale=rationale,
                        evidence_references=evidence_refs,
                        suggested_fix=f"Apply recommended action: {action}.",
                    )
                )

            # 2. Formulate candidates from challenged requirements with stable finding-derived IDs
            for cr in challenged_reqs:
                req_id = cr.get("id", "REQ-HIST")
                stmt = cr.get("statement", "")
                source = cr.get("source", "")
                challenge = cr.get("challenge", "Unjustified assumption identified.")
                rule_id = f"RULE-REQ-{sha256_text(source + req_id)[:6].upper()}"
                cid = f"kc-{sha256_text(rule_id + req_id)[:12]}"
                candidates.append(
                    KnowledgeAdmissionGate.create_candidate(
                        candidate_id=cid,
                        observation=f"Challenged requirement {req_id} at {source}: {stmt}",
                        category=FindingCategory.SECURITY
                        if "path" in stmt.lower()
                        else FindingCategory.UNCLEAR_INTERFACE,
                        severity=FindingSeverity.MEDIUM,
                        finding_description=challenge,
                        target_lines=_parse_lines(source),
                        rule_id=rule_id,
                        rule_title=f"Remediate challenged requirement {req_id}",
                        enforcement_mechanism="SCHEMA_GUARD",
                        rationale=challenge,
                        evidence_references=evidence_refs,
                        suggested_fix="Inject configuration or environment parameters dynamically.",
                    )
                )

            # 3. Formulate candidates from verify safety check failures with exact severity mapping
            for vf in verify_failures:
                chk_name = vf.get("name", "check")
                details = vf.get("details", "Safety invariant violated.")
                rule_id = f"RULE-VERIFY-{sha256_text(chk_name)[:6].upper()}"
                cid = f"kc-{sha256_text(rule_id + chk_name)[:12]}"
                raw_sev = vf.get("severity")
                if not raw_sev:
                    return (
                        {"error": f"Missing severity in verify failure for '{chk_name}'"},
                        [f"Missing verify failure severity in '{chk_name}' (fail-closed)"],
                        VerificationStatus.FAIL,
                    )
                try:
                    vf_sev = FindingSeverity(raw_sev)
                except ValueError:
                    return (
                        {"error": f"Invalid severity '{raw_sev}' for verify failure '{chk_name}'"},
                        [f"Unrecognized verify failure severity '{raw_sev}' (fail-closed)"],
                        VerificationStatus.FAIL,
                    )

                candidates.append(
                    KnowledgeAdmissionGate.create_candidate(
                        candidate_id=cid,
                        observation=f"Verification safety check '{chk_name}' failed: {details}",
                        category=FindingCategory.SECURITY,
                        severity=vf_sev,
                        finding_description=details,
                        target_lines=[1],
                        rule_id=rule_id,
                        rule_title=f"Enforce safety invariant for {chk_name}",
                        enforcement_mechanism="TEST_FIXTURE",
                        rationale=details,
                        evidence_references=evidence_refs,
                        suggested_fix="Ensure all safety checks pass prior to verification gate.",
                    )
                )

        # Canonical payload contains clock-free semantic representation for hermetic determinism
        canonical_candidates = [c.to_canonical_dict() for c in candidates]

        checks.append(f"Formulated {len(candidates)} knowledge candidate(s) from upstream findings")
        checks.append("Strict non-canonical invariant enforced: All candidates set to PENDING_REVIEW")

        admission_msg = (
            "Candidates must be reviewed using 'hardening-loop review <file> --admit' before becoming canonical knowledge."
            if candidates
            else "No actionable findings detected in audited target."
        )

        payload = {
            "target": target_path,
            "candidates_count": len(candidates),
            "candidates": canonical_candidates,
            "admission_record": {
                "admission_status": "PENDING_REVIEW" if candidates else "NONE",
                "gate_policy": "NO_AUTO_CANONICAL",
                "message": admission_msg,
            },
        }

        status = VerificationStatus.PASS
        return payload, checks, status
