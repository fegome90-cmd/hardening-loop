"""Core domain models and schema types for Algorithmic Code Hardening Loop."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .schema_validator import SchemaValidationError, validate_payload

__all__ = [
    "AdmissionStatus",
    "EvidenceArtifact",
    "EvidenceEnvelope",
    "EvidenceVerification",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "HardeningState",
    "KnowledgeCandidate",
    "PhaseName",
    "RequirementType",
    "RuleProposal",
    "SchemaValidationError",
    "VerificationStatus",
    "WorkUnit",
    "compute_environment_hash",
    "compute_target_hash",
    "sha256_dict",
    "sha256_text",
    "utc_now_iso",
    "validate_payload",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_dict(data: dict[str, Any]) -> str:
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_environment_hash() -> str:
    """Computes a deterministic hash of the host runtime environment."""
    env_data = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
    }
    return sha256_dict(env_data)


def compute_target_hash(target_path: str) -> str:
    """Computes a deterministic hash for a single file or an entire directory tree."""
    if not os.path.exists(target_path):
        return sha256_text("")

    if os.path.isfile(target_path):
        with open(target_path, encoding="utf-8", errors="ignore") as f:
            return sha256_text(f.read())

    # Directory target: compute Merkle tree digest
    file_hashes: dict[str, str] = {}
    for root, dirs, files in os.walk(target_path):
        dirs.sort()
        for file in sorted(files):
            if file.endswith((".pyc", ".DS_Store")) or "__pycache__" in root:
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_path)
            try:
                with open(full_path, encoding="utf-8", errors="ignore") as f:
                    file_hashes[rel_path] = sha256_text(f.read())
            except OSError:
                continue
    return sha256_dict(file_hashes)


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
    PROVENANCE_GAP = "PROVENANCE_GAP"


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
    target_lines: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
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
    suggested_fix: str | None = None

    def to_dict(self) -> dict[str, Any]:
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
    evidence_references: list[str]
    admission_status: AdmissionStatus = AdmissionStatus.PENDING_REVIEW
    reviewer: str | None = None
    reviewed_at: str | None = None
    review_notes: str | None = None
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "observation": self.observation,
            "finding": self.finding.to_dict(),
            "rule_proposal": self.rule_proposal.to_dict(),
            "evidence_references": self.evidence_references,
            "admission_status": self.admission_status.value
            if isinstance(self.admission_status, Enum)
            else self.admission_status,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "review_notes": self.review_notes,
            "created_at": self.created_at,
        }

    def validate_schema(self) -> None:
        """Validates this knowledge candidate against normative JSON schema."""
        validate_payload(self.to_dict(), "knowledge_candidate")


@dataclass
class EvidenceArtifact:
    path: str
    artifact_type: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "artifact_type": self.artifact_type,
            "payload": self.payload,
        }


@dataclass
class EvidenceVerification:
    passed: bool
    checks: list[str]
    duration_ms: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
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
    method_version: str = "v0.3"
    environment_hash: str = field(default_factory=compute_environment_hash)

    def to_dict(self) -> dict[str, Any]:
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
            "method_version": self.method_version,
            "environment_hash": self.environment_hash,
        }

    def validate_schema(self) -> None:
        """Validates this envelope against normative JSON schema."""
        validate_payload(self.to_dict(), "evidence_envelope")


@dataclass
class WorkUnit:
    work_unit_id: str
    target_path: str
    target_hash: str
    state: HardeningState = HardeningState.DRAFT
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    phases_executed: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
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

    def validate_schema(self) -> None:
        """Validates this work unit against normative JSON schema."""
        validate_payload(self.to_dict(), "work_unit")
