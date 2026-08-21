---
title: "ADR-001: Desacoplamiento de Canonical Evidence y Runtime Receipt"
topic: "hardening-loop"
doc_type: decision
tags: [adr, arquitectura, determinismo, envelopes]
sources:
  - "DOGFOODING-001 Audit Findings"
  - "DOGFOODING-002 Implementation"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# ADR-001: Desacoplamiento de Canonical Evidence y Runtime Receipt

## Contexto
En `v0.1-alpha`, el `EvidenceEnvelope` contenía campos deterministas (`input_hash`, `output_hash`, `artifact`) mezclados con telemetría no determinista (`timestamp = utc_now_iso()`, `duration_ms`). Al calcular el hash del manifiesto sobre todo el sobre, dos ejecuciones consecutivas (`run-A` y `run-B`) sobre el mismo árbol de código producían hashes de manifiesto disímiles debido a la deriva de reloj del sistema.

## Decisión
Dividir formalmente el `EvidenceEnvelope` en dos sub-objetos estancos:
1. `canonical_evidence`: Identidad inmutable y determinista que incluye `evidence_id`, `phase`, `input_hash`, `output_hash`, `method_version`, `schema_version`, `execution_context_hash` y `artifact_payload`.
2. `runtime_receipt`: Metadatos transitorios de observabilidad (`timestamp`, `duration_ms`, `checks`, `status`).

El `canonical_manifest_digest` se computa exclusivamente sobre el bloque `canonical_evidence`.

## Consecuencias
- **Positivas:** Reproducibilidad matemática bit-a-bit garantizada entre ejecuciones independientes.
- **Positivas:** Telemetría de reloj preservada sin contaminar la firma criptográfica.
- **Negativas:** Modificación del schema JSON normativo a `v0.1-beta`.

---

## Relaciones

- [[determinismo-canonico|trata]] — 💊 Concepto que fundamenta este ADR.
- [[rule-evidence-001|indica]] — 🔬 Regla normativa nacida de esta decisión.
