"""Core domain models and schema types for Algorithmic Code Hardening Loop."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
import platform
import subprocess
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_dict(data: Dict[str, Any]) -> str:
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def get_git_commit_hash(cwd: Optional[str] = None) -> str:
    """Retrieves current Git commit hash or returns uncommitted-dirty."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd or os.getcwd(),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "git-unavailable-or-dirty"


def compute_lockfile_hash(base_dir: Optional[str] = None) -> str:
    """Computes SHA-256 digest of dependency lockfile (uv.lock or pyproject.toml)."""
    search_dir = base_dir or os.getcwd()
    for fname in ["uv.lock", "pyproject.toml", "requirements.txt"]:
        fpath = os.path.join(search_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                return sha256_text(f.read())
    return "no-lockfile-detected"


def compute_execution_context_hash(base_dir: Optional[str] = None, schema_version: str = "v0.1-beta") -> str:
    """Computes a deterministic digest of the complete execution context."""
    context_data = {
        "git_commit": get_git_commit_hash(base_dir),
        "lockfile_digest": compute_lockfile_hash(base_dir),
        "schema_version": schema_version,
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
    }
    return sha256_dict(context_data)


def compute_canonical_directory_digest(target_path: str) -> str:
    """Computes a Canonical Directory Digest (sorted flat file digest) for a target file or tree."""
    if not os.path.exists(target_path):
        return sha256_text("")

    if os.path.isfile(target_path):
        with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
            return sha256_text(f.read())

    # Canonical Directory Digest over recursive sorted files
    file_hashes: Dict[str, str] = {}
    for root, dirs, files in os.walk(target_path):
        dirs.sort()
        for file in sorted(files):
            if file.endswith((".pyc", ".DS_Store")) or "__pycache__" in root:
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_hashes[rel_path] = sha256_text(f.read())
            except OSError:
                continue
    return sha256_dict(file_hashes)


# Backward compatibility alias
compute_target_hash = compute_canonical_directory_digest


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
    created_at: str = "CANONICAL_EPOCH"

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

    def validate_schema(self) -> None:
        from .schema_validator import SchemaValidator
        SchemaValidator.validate_or_raise("knowledge_candidate", self.to_dict())


@dataclass
class CanonicalEvidence:
    """Deterministic, hashable core of the evidence envelope."""
    evidence_id: str
    phase: PhaseName
    input_hash: str
    output_hash: str
    method_version: str
    schema_version: str
    execution_context_hash: str
    artifact_payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "phase": self.phase.value if isinstance(self.phase, Enum) else self.phase,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "method_version": self.method_version,
            "schema_version": self.schema_version,
            "execution_context_hash": self.execution_context_hash,
            "artifact_payload": self.artifact_payload,
        }

    def canonical_hash(self) -> str:
        return sha256_dict(self.to_dict())


@dataclass
class RuntimeReceipt:
    """Non-deterministic runtime telemetry & observability (excluded from canonical hash)."""
    producer: str
    timestamp: str
    duration_ms: float
    checks: List[str]
    status: VerificationStatus
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "producer": self.producer,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 3),
            "checks": self.checks,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "error": self.error,
        }


@dataclass
class EvidenceArtifactHelper:
    payload: Dict[str, Any]


@dataclass
class EvidenceEnvelope:
    """Full envelope coupling deterministic canonical evidence with execution telemetry."""
    canonical: CanonicalEvidence
    runtime: RuntimeReceipt

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical_evidence": self.canonical.to_dict(),
            "runtime_receipt": self.runtime.to_dict(),
        }

    @property
    def evidence_id(self) -> str:
        return self.canonical.evidence_id

    @property
    def phase(self) -> PhaseName:
        return self.canonical.phase

    @property
    def input_hash(self) -> str:
        return self.canonical.input_hash

    @property
    def output_hash(self) -> str:
        return self.canonical.output_hash

    @property
    def status(self) -> VerificationStatus:
        return self.runtime.status

    @property
    def method_version(self) -> str:
        return self.canonical.method_version

    @property
    def schema_version(self) -> str:
        return self.canonical.schema_version

    @property
    def execution_context_hash(self) -> str:
        return self.canonical.execution_context_hash

    @property
    def artifact(self) -> EvidenceArtifactHelper:
        return EvidenceArtifactHelper(payload=self.canonical.artifact_payload)


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

    def validate_schema(self) -> None:
        from .schema_validator import SchemaValidator
        SchemaValidator.validate_or_raise("work_unit", self.to_dict())
