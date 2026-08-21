"""Base phase interface with cryptographic envelope creation and schema validation."""

import abc
import os
import time
from typing import Any, Dict, List, Tuple
from ..models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    compute_canonical_directory_digest,
    compute_execution_context_hash,
    sha256_dict,
    utc_now_iso,
)
from ..schema_validator import SchemaValidator


class BasePhase(abc.ABC):
    """Abstract base class for hardening loop phases."""

    def __init__(self, name: PhaseName, version: str = "0.1.0-beta", method_version: str = "v0.3", schema_version: str = "v0.1-beta"):
        self.name = name
        self.version = version
        self.method_version = method_version
        self.schema_version = schema_version

    def compute_input_hash(self, target_path: str, context: Dict[str, Any]) -> str:
        target_content_hash = compute_canonical_directory_digest(target_path)
        context_payload = {
            "target_path": target_path,
            "target_content_hash": target_content_hash,
            "context": context,
        }
        return sha256_dict(context_payload)

    @abc.abstractmethod
    def execute(self, target_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], VerificationStatus]:
        """Executes phase logic.

        Returns:
            Tuple of (payload, verification_checks, status)
        """
        pass

    def run(self, target_path: str, context: Dict[str, Any], output_dir: str) -> EvidenceEnvelope:
        t0 = time.perf_counter()
        input_hash = self.compute_input_hash(target_path, context)
        
        payload, checks, status = self.execute(target_path, context)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        output_hash = sha256_dict(payload)
        evidence_id = f"evi-{output_hash[:12]}"
        exec_ctx_hash = compute_execution_context_hash(schema_version=self.schema_version)

        canonical = CanonicalEvidence(
            evidence_id=evidence_id,
            phase=self.name,
            input_hash=input_hash,
            output_hash=output_hash,
            method_version=self.method_version,
            schema_version=self.schema_version,
            execution_context_hash=exec_ctx_hash,
            artifact_payload=payload,
        )

        runtime = RuntimeReceipt(
            producer=f"hardening-loop:{self.name.value}:{self.version}",
            timestamp=utc_now_iso(),
            duration_ms=duration_ms,
            checks=checks,
            status=status,
            error=None if status == VerificationStatus.PASS else "One or more checks failed or raised warnings.",
        )

        envelope = EvidenceEnvelope(canonical=canonical, runtime=runtime)

        # Fail-closed Schema Validation
        SchemaValidator.validate_or_raise("evidence_envelope", envelope.to_dict())

        return envelope
