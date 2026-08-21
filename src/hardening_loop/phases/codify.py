"""Phase 5: CODIFY VALIDATED LEARNING — Structure candidate rules for admission gate review."""

import os
from typing import Any, Dict, List, Tuple
from ..admission import KnowledgeAdmissionGate
from ..models import (
    FindingCategory,
    FindingSeverity,
    KnowledgeCandidate,
    PhaseName,
    VerificationStatus,
)
from .base import BasePhase


class CodifyPhase(BasePhase):
    """Packages validated learnings into candidates for human/curator review."""

    def __init__(self):
        super().__init__(name=PhaseName.CODIFY)

    def execute(self, target_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], VerificationStatus]:
        checks = []
        evidence_refs = context.get("evidence_ids", [])

        candidates: List[KnowledgeCandidate] = []

        # Candidate 1: Command whitelist rule
        candidates.append(
            KnowledgeAdmissionGate.create_candidate(
                candidate_id="kc-sec-whitelist-01",
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

        # Candidate 2: Filesystem boundary sandbox rule
        candidates.append(
            KnowledgeAdmissionGate.create_candidate(
                candidate_id="kc-sec-sandbox-02",
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

        # Candidate 3: Environment parameterization
        candidates.append(
            KnowledgeAdmissionGate.create_candidate(
                candidate_id="kc-contract-cwd-03",
                observation="Target hardcodes developer absolute directory in execution harness.",
                category=FindingCategory.UNCLEAR_INTERFACE,
                severity=FindingSeverity.MEDIUM,
                finding_description="Hardcoded environment cwd makes code non-portable across machines and test environments.",
                target_lines=[61],
                rule_id="RULE-ARCH-001",
                rule_title="No Hardcoded Absolute Paths in Tool Runners",
                enforcement_mechanism="LINTER",
                rationale="Environment paths must be injected via CLI arguments or environment variables.",
                evidence_references=evidence_refs,
                suggested_fix="Use params.get('cwd', os.getcwd()) and expose --workspace CLI flag.",
            )
        )

        candidates_dict = [c.to_dict() for c in candidates]
        checks.append(f"Formulated {len(candidates)} knowledge candidates for admission review")
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
