"""Core domain models and schema types for Algorithmic Code Hardening Loop."""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_dict(data: Dict[str, Any]) -> str:
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class HardeningState(str, Enum):
    DRAFT = "DRAFT"
    AUDITING = "AUDITING"
    PATCH_PROPOSED = "PATCH_PROPOSED"
    VERIFIED = "VERIFIED"
    KNOWLEDGE_CANDIDATE = "KNOWLEDGE_CANDIDATE"
    ADMITTED = "ADMITTED"
    CANONICAL = "CANONICAL"
    DEPRECATED = "DEPRECATED"


class PhaseName(str, Enum):
    QUESTION = "question"
    DELETE = "delete"
    SIMPLIFY = "simplify"
    VERIFY = "verify"
    CODIFY = "codify"


class RequirementType(str, Enum):
    EXPLICIT = "explicit"
    INFERRED = "inferred"
    HISTORICAL = "historical"
    SECURITY_CONSTRAINT = "security_constraint"


class FindingCategory(str, Enum):
    SECURITY = "SECURITY"
    CONTRACT_BREACH = "CONTRACT_BREACH"
    UNCLEAR_INTERFACE = "UNCLEAR_INTERFACE"
    RESOURCE_LEAK = "RESOURCE_LEAK"
    DEAD_HARNESS = "DEAD_HARNESS"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AdmissionStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    OBSOLETE = "OBSOLETE"


class VerificationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    WARN = "WARN"


@dataclass
class Finding:
    category: FindingCategory
    severity: FindingSeverity
    description: str
    target_lines: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value if isinstance(self.category, Enum) else self.category,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "description": self.description,
            "target_lines": self.target_lines,
        }


@dataclass
class RuleProposal:
    rule_id: str
    title: str
    enforcement_mechanism: str
    rationale: str
    suggested_fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "enforcement_mechanism": self.enforcement_mechanism,
            "rationale": self.rationale,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class KnowledgeCandidate:
    candidate_id: str
    observation: str
    finding: Finding
    rule_proposal: RuleProposal
    evidence_references: List[str]
    admission_status: AdmissionStatus = AdmissionStatus.PENDING_REVIEW
    reviewer: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_notes: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "observation": self.observation,
            "finding": self.finding.to_dict(),
            "rule_proposal": self.rule_proposal.to_dict(),
            "evidence_references": self.evidence_references,
            "admission_status": self.admission_status.value if isinstance(self.admission_status, Enum) else self.admission_status,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "review_notes": self.review_notes,
            "created_at": self.created_at,
        }


@dataclass
class EvidenceArtifact:
    path: str
    artifact_type: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "artifact_type": self.artifact_type,
            "payload": self.payload,
        }


@dataclass
class EvidenceVerification:
    passed: bool
    checks: List[str]
    duration_ms: float
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": self.checks,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
        }


@dataclass
class EvidenceEnvelope:
    evidence_id: str
    producer: str
    timestamp: str
    phase: PhaseName
    input_hash: str
    output_hash: str
    artifact: EvidenceArtifact
    verification: EvidenceVerification
    status: VerificationStatus

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "producer": self.producer,
            "timestamp": self.timestamp,
            "phase": self.phase.value if isinstance(self.phase, Enum) else self.phase,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "artifact": self.artifact.to_dict(),
            "verification": self.verification.to_dict(),
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
        }


@dataclass
class WorkUnit:
    work_unit_id: str
    target_path: str
    target_hash: str
    state: HardeningState = HardeningState.DRAFT
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    phases_executed: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "work_unit_id": self.work_unit_id,
            "target_path": self.target_path,
            "target_hash": self.target_hash,
            "state": self.state.value if isinstance(self.state, Enum) else self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "phases_executed": self.phases_executed,
            "metadata": self.metadata,
        }
