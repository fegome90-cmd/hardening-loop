---
title: "Diagrama: Autómata de Estados y Flujo de Evidencia"
topic: "hardening-loop"
doc_type: diagram
tags: [diagrama, mermaid, estados, envelopes]
sources:
  - "docs/spec_v0.1.md"
  - "src/hardening_loop/states.py"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# Diagrama: Autómata de Estados y Flujo de Evidencia

## 1. Ciclo de Estados del WorkUnit

```mermaid
stateDiagram-v2
    [*] --> DRAFT: Inicialización con Canonical Digest
    DRAFT --> AUDITING: Inicio de Fase QUESTION
    AUDITING --> PATCH_PROPOSED: Fases DELETE & SIMPLIFY
    PATCH_PROPOSED --> VERIFIED: Fase VERIFY (SLA < 100ms)
    VERIFIED --> KNOWLEDGE_CANDIDATE: Fase CODIFY
    KNOWLEDGE_CANDIDATE --> REJECTED: Rechazo en Aduana
    KNOWLEDGE_CANDIDATE --> ADMITTED: Aserción Humana en Aduana
    ADMITTED --> READY_FOR_PR_REVIEW: Formalización de Tests
    READY_FOR_PR_REVIEW --> CANONICAL: Merge Mainline & External Review
    CANONICAL --> DEPRECATED: Superado por nueva evidencia
```

---

## 2. Estructura Ortogonal del Evidence Envelope

```mermaid
classDiagram
    class EvidenceEnvelope {
        +CanonicalEvidence canonical
        +RuntimeReceipt runtime
        +to_dict() dict
    }
    class CanonicalEvidence {
        +String evidence_id
        +PhaseName phase
        +String input_hash
        +String output_hash
        +String method_version
        +String schema_version
        +String execution_context_hash
        +Dict artifact_payload
        +canonical_hash() String
    }
    class RuntimeReceipt {
        +String producer
        +String timestamp
        +Float duration_ms
        +List checks
        +VerificationStatus status
        +String error
    }
    EvidenceEnvelope *-- CanonicalEvidence
    EvidenceEnvelope *-- RuntimeReceipt
```

---

## Relaciones

- [[loop-5-fases|trata]] — 💊 Fases que disparan las transiciones.
- [[determinismo-canonico|usa]] — 🧠 Modelo formal del envelope.
