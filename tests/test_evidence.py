"""Tests for Evidence Envelope structure, determinism, and SHA-256 computation."""

from hardening_loop.models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    compute_execution_context_hash,
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
    ctx_hash = compute_execution_context_hash()

    canonical = CanonicalEvidence(
        evidence_id="evi-12345678abcd",
        phase=PhaseName.QUESTION,
        input_hash=in_hash,
        output_hash=out_hash,
        method_version="v0.3",
        schema_version="v0.1-beta",
        execution_context_hash=ctx_hash,
        artifact_payload=payload,
    )

    runtime = RuntimeReceipt(
        producer="hardening-loop:test:0.1.0",
        timestamp=utc_now_iso(),
        duration_ms=12.34,
        checks=["Check 1 passed", "Check 2 passed"],
        status=VerificationStatus.PASS,
    )

    envelope = EvidenceEnvelope(canonical=canonical, runtime=runtime)

    d = envelope.to_dict()
    assert "canonical_evidence" in d
    assert "runtime_receipt" in d
    assert d["canonical_evidence"]["evidence_id"] == "evi-12345678abcd"
    assert d["canonical_evidence"]["phase"] == "question"
    assert d["runtime_receipt"]["status"] == "PASS"
    assert len(d["canonical_evidence"]["output_hash"]) == 64
    assert len(d["canonical_evidence"]["input_hash"]) == 64
    assert len(d["canonical_evidence"]["execution_context_hash"]) == 64
