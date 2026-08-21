"""Base phase interface with cryptographic envelope creation."""

import abc
import os
import time
from typing import Any, Dict, List, Tuple
from ..models import (
    EvidenceArtifact,
    EvidenceEnvelope,
    EvidenceVerification,
    PhaseName,
    VerificationStatus,
    sha256_dict,
    sha256_text,
    utc_now_iso,
)


class BasePhase(abc.ABC):
    """Abstract base class for hardening loop phases."""

    def __init__(self, name: PhaseName, version: str = "0.1.0"):
        self.name = name
        self.version = version

    def compute_input_hash(self, target_path: str, context: Dict[str, Any]) -> str:
        content = ""
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
        context_payload = {
            "target_path": target_path,
            "target_content_hash": sha256_text(content),
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
        artifact_filename = f"{self.name.value}_artifact.json"
        artifact_path = os.path.join(output_dir, artifact_filename)

        envelope = EvidenceEnvelope(
            evidence_id=evidence_id,
            producer=f"hardening-loop:{self.name.value}:{self.version}",
            timestamp=utc_now_iso(),
            phase=self.name,
            input_hash=input_hash,
            output_hash=output_hash,
            artifact=EvidenceArtifact(
                path=artifact_path,
                artifact_type=f"{self.name.value}_payload",
                payload=payload,
            ),
            verification=EvidenceVerification(
                passed=(status == VerificationStatus.PASS),
                checks=checks,
                duration_ms=duration_ms,
                error=None if status == VerificationStatus.PASS else "One or more checks failed or raised warnings.",
            ),
            status=status,
        )
        return envelope
