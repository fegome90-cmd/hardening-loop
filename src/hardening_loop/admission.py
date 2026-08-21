"""Knowledge Admission Gate — Governs transition from empirical findings to accepted rules."""

from typing import List, Optional
import yaml
from .models import (
    AdmissionStatus,
    Finding,
    FindingCategory,
    FindingSeverity,
    KnowledgeCandidate,
    RuleProposal,
    utc_now_iso,
)


class KnowledgeAdmissionError(RuntimeError):
    """Raised when an illegal knowledge promotion is attempted."""
    pass


class KnowledgeAdmissionGate:
    """Aduana de Conocimiento: enforces review before promoting findings to canonical rules."""

    @staticmethod
    def create_candidate(
        candidate_id: str,
        observation: str,
        category: FindingCategory,
        severity: FindingSeverity,
        finding_description: str,
        target_lines: List[int],
        rule_id: str,
        rule_title: str,
        enforcement_mechanism: str,
        rationale: str,
        evidence_references: List[str],
        suggested_fix: Optional[str] = None,
    ) -> KnowledgeCandidate:
        finding = Finding(
            category=category,
            severity=severity,
            description=finding_description,
            target_lines=target_lines,
        )
        proposal = RuleProposal(
            rule_id=rule_id,
            title=rule_title,
            enforcement_mechanism=enforcement_mechanism,
            rationale=rationale,
            suggested_fix=suggested_fix,
        )
        return KnowledgeCandidate(
            candidate_id=candidate_id,
            observation=observation,
            finding=finding,
            rule_proposal=proposal,
            evidence_references=evidence_references,
            admission_status=AdmissionStatus.PENDING_REVIEW,
        )

    @staticmethod
    def review_candidate(
        candidate: KnowledgeCandidate,
        decision: AdmissionStatus,
        reviewer: str,
        notes: str = "",
    ) -> KnowledgeCandidate:
        if decision not in (AdmissionStatus.ACCEPTED, AdmissionStatus.REJECTED, AdmissionStatus.OBSOLETE):
            raise KnowledgeAdmissionError(
                f"Invalid review decision '{decision}'. Must be ACCEPTED, REJECTED, or OBSOLETE."
            )
        if not reviewer or not reviewer.strip():
            raise KnowledgeAdmissionError("Reviewer identity is mandatory for knowledge admission.")

        candidate.admission_status = decision
        candidate.reviewer = reviewer.strip()
        candidate.reviewed_at = utc_now_iso()
        candidate.review_notes = notes
        return candidate

    @staticmethod
    def export_candidate_yaml(candidate: KnowledgeCandidate) -> str:
        return yaml.dump(candidate.to_dict(), sort_keys=False, allow_unicode=True)

    @staticmethod
    def load_candidate_yaml(yaml_content: str) -> KnowledgeCandidate:
        raw = yaml.safe_load(yaml_content)
        f_raw = raw["finding"]
        r_raw = raw["rule_proposal"]
        finding = Finding(
            category=FindingCategory(f_raw["category"]),
            severity=FindingSeverity(f_raw["severity"]),
            description=f_raw["description"],
            target_lines=f_raw.get("target_lines", []),
        )
        rule_proposal = RuleProposal(
            rule_id=r_raw["rule_id"],
            title=r_raw["title"],
            enforcement_mechanism=r_raw["enforcement_mechanism"],
            rationale=r_raw["rationale"],
            suggested_fix=r_raw.get("suggested_fix"),
        )
        return KnowledgeCandidate(
            candidate_id=raw["candidate_id"],
            observation=raw["observation"],
            finding=finding,
            rule_proposal=rule_proposal,
            evidence_references=raw.get("evidence_references", []),
            admission_status=AdmissionStatus(raw.get("admission_status", AdmissionStatus.PENDING_REVIEW.value)),
            reviewer=raw.get("reviewer"),
            reviewed_at=raw.get("reviewed_at"),
            review_notes=raw.get("review_notes"),
            created_at=raw.get("created_at", utc_now_iso()),
        )
