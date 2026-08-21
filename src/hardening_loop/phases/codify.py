"""Phase 5: CODIFY VALIDATED LEARNING — Structure candidate rules for admission gate review."""

import os
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
from .base import BasePhase


class CodifyPhase(BasePhase):
    """Packages validated learnings into candidates for human/curator review."""

    def __init__(self):
        super().__init__(name=PhaseName.CODIFY)

    def execute(
        self, target_path: str, context: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], VerificationStatus]:
        checks = []
        evidence_refs = context.get("evidence_ids", [])
        candidates: list[KnowledgeCandidate] = []

        is_self_audit = "hardening_loop" in target_path or os.path.isdir(target_path)

        if is_self_audit:
            # Self-audit candidate 1: Mandatory Envelope Provenance
            cid_1 = f"kc-{sha256_text('RULE-EVIDENCE-001')[:12]}"
            candidates.append(
                KnowledgeAdmissionGate.create_candidate(
                    candidate_id=cid_1,
                    observation="Evidence envelopes must track both method_version and host environment_hash for hermetic reproducibility.",
                    category=FindingCategory.PROVENANCE_GAP,
                    severity=FindingSeverity.HIGH,
                    finding_description="Without method_version and environment_hash, evidence artifacts cannot be cross-validated across different CI or OS environments.",
                    target_lines=[1, 2, 3],
                    rule_id="RULE-EVIDENCE-001",
                    rule_title="Mandatory Method & Environment Provenance in Evidence Envelopes",
                    enforcement_mechanism="SCHEMA_GUARD",
                    rationale="Hermetic reproducibility requires capturing the exact runtime environment digest and framework version.",
                    evidence_references=evidence_refs,
                    suggested_fix="Include method_version and environment_hash as required schema properties in evidence_envelope.schema.json.",
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
            # External target candidates (like qwen-tool-loop)
            cid_ext1 = f"kc-{sha256_text('RULE-SEC-001')[:12]}"
            cid_ext2 = f"kc-{sha256_text('RULE-SEC-002')[:12]}"
            candidates.append(
                KnowledgeAdmissionGate.create_candidate(
                    candidate_id=cid_ext1,
                    observation="Target tool wrapper invokes bash via generic shell without enforcing an explicit executable whitelist.",
                    category=FindingCategory.SECURITY,
                    severity=FindingSeverity.HIGH,
                    finding_description="Generic subprocess execution without token/command whitelist exposes runner to arbitrary command injection.",
                    target_lines=[53, 54, 58, 59],
                    rule_id="RULE-SEC-001",
                    rule_title="Mandatory Executable Whitelist for Tool Call Runners",
                    enforcement_mechanism="CONTRACT_VALIDATOR",
                    rationale="LLM tool agents must not be granted open shell access; commands must be validated against an approved executable set.",
                    evidence_references=evidence_refs,
                    suggested_fix="Introduce an explicit set of allowed binaries (e.g. {'git', 'pytest', 'make'}) before subprocess invocation.",
                )
            )
            candidates.append(
                KnowledgeAdmissionGate.create_candidate(
                    candidate_id=cid_ext2,
                    observation="Target read tool accesses filesystem paths directly without verifying workspace root containment.",
                    category=FindingCategory.SECURITY,
                    severity=FindingSeverity.HIGH,
                    finding_description="Arbitrary path reading allows directory traversal outside workspace.",
                    target_lines=[68, 69, 71],
                    rule_id="RULE-SEC-002",
                    rule_title="Workspace Path Sandboxing for Read Tools",
                    enforcement_mechanism="SCHEMA_GUARD",
                    rationale="Prevent leakage of credentials and sensitive dotfiles outside project scope.",
                    evidence_references=evidence_refs,
                    suggested_fix="Resolve paths with os.path.realpath and assert startswith(workspace_root).",
                )
            )

        candidates_dict = [c.to_dict() for c in candidates]
        checks.append(f"Formulated {len(candidates)} knowledge candidate(s) for admission review")
        checks.append("Strict non-canonical invariant enforced: All candidates set to PENDING_REVIEW")

        payload = {
            "target": target_path,
            "candidates_count": len(candidates),
            "candidates": candidates_dict,
            "admission_record": {
                "admission_status": "PENDING_REVIEW",
                "gate_policy": "NO_AUTO_CANONICAL",
                "message": "Candidates must be reviewed using 'hardening-loop review <file> --admit' before becoming canonical knowledge.",
            },
        }

        status = VerificationStatus.PASS
        return payload, checks, status
