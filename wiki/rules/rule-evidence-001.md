---
title: "RULE-EVIDENCE-001: Desacoplamiento Canónico y Contexto de Ejecución"
topic: "hardening-loop"
doc_type: rule
tags: [regla-canonica, envelopes, proveniencia, sha-256]
sources:
  - "DOGFOODING-002 Admission Record"
  - "schemas/evidence_envelope.schema.json"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# RULE-EVIDENCE-001: Desacoplamiento Canónico y Contexto de Ejecución

## Definición Normativa

| Atributo | Valor |
| :--- | :--- |
| **Rule ID** | `RULE-EVIDENCE-001` |
| **Categoría** | `PROVENANCE_GAP` |
| **Severidad** | `HIGH` |
| **Mecanismo** | `SCHEMA_GUARD` (`Draft7Validator`) |
| **Estado de Aduana** | `ACCEPTED` (Aprobado por Revisor Humano) |

## Enunciado de la Regla

Todo sobre de evidencia generado por el framework (`EvidenceEnvelope`) debe desacoplar estrictamente el bloque `canonical_evidence` de la telemetría `runtime_receipt` e incluir obligatoriamente el digest compuesto `execution_context_hash`.

## Esquema Normativo Requerido

```json
{
  "canonical_evidence": {
    "evidence_id": "evi-[a-f0-9]{8,16}",
    "phase": "question | delete | simplify | verify | codify",
    "input_hash": "[a-f0-9]{64}",
    "output_hash": "[a-f0-9]{64}",
    "method_version": "v0.3",
    "schema_version": "v0.1-beta",
    "execution_context_hash": "[a-f0-9]{64}",
    "artifact_payload": { ... }
  },
  "runtime_receipt": {
    "producer": "...",
    "timestamp": "ISO-8601-UTC",
    "duration_ms": 0.0,
    "checks": [ "..." ],
    "status": "PASS | FAIL | BLOCKED | WARN"
  }
}
```

## Racional
Previene la deriva de reloj en manifiestos agregados y garantiza que todo cálculo de evidencia pueda rastrearse al commit de Git exacto y al lockfile de dependencias.

---

## Relaciones

- [[determinismo-canonico|trata]] — 💊 Fundamento teórico de la regla.
- [[adr-001-separacion-canonica-telemetria|usa]] — 🧠 ADR que originó la regla.
