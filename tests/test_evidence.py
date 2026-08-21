"""Tests for Evidence Envelope structure, determinism, and SHA-256 computation."""

from hardening_loop.models import (
    EvidenceArtifact,
    EvidenceEnvelope,
    EvidenceVerification,
    PhaseName,
    VerificationStatus,
    sha256_dict,
    sha256_text,
    utc_now_iso,
)


def test_sha256_determinism():
    data1 = {"b": 2, "a": 1}
    data2 = {"a": 1, "b": 2}
    # Keys should sort canonical before hashing
    assert sha256_dict(data1) == sha256_dict(data2)


def test_evidence_envelope_serialization():
    payload = {"key": "value", "count": 42}
    out_hash = sha256_dict(payload)
    in_hash = sha256_text("target_content")

    envelope = EvidenceEnvelope(
        evidence_id="evi-12345678",
        producer="hardening-loop:test:0.1.0",
        timestamp=utc_now_iso(),
        phase=PhaseName.QUESTION,
        input_hash=in_hash,
        output_hash=out_hash,
        artifact=EvidenceArtifact(
            path="/tmp/test_artifact.json",
            artifact_type="question_payload",
            payload=payload,
        ),
        verification=EvidenceVerification(
            passed=True,
            checks=["Check 1 passed", "Check 2 passed"],
            duration_ms=12.34,
        ),
        status=VerificationStatus.PASS,
    )

    d = envelope.to_dict()
    assert d["evidence_id"] == "evi-12345678"
    assert d["phase"] == "question"
    assert d["status"] == "PASS"
    assert d["verification"]["passed"] is True
    assert len(d["output_hash"]) == 64
    assert len(d["input_hash"]) == 64
