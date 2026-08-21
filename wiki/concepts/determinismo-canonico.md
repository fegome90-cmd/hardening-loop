---
title: "Determinismo de la Capa Canónica y Separación de Telemetría"
topic: "hardening-loop"
doc_type: concept
tags: [criptografia, determinismo, envelopes, sha-256]
sources:
  - "DOGFOODING-002: Evidence Hermeticity Hardening"
  - "schemas/evidence_envelope.schema.json"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# Determinismo de la Capa Canónica y Separación de Telemetría

Para lograr reproducibilidad matemática entre ejecuciones independientes sin deriva de reloj, el **EvidenceEnvelope** se estructura en dos capas ortogonales:

```text
EvidenceEnvelope
├── canonical_evidence (Identidad determinista -> Digest inmutable)
└── runtime_receipt    (Telemetría no determinista -> Observabilidad)
```

## Estructura Criptográfica

### 1. `canonical_evidence` (Determinista)
Contiene exclusivamente los datos que dependen del código fuente, el contexto y los parámetros de ejecución:
- `evidence_id`: Hash determinista del output.
- `phase`: Fase del ciclo (`question`, `delete`, `simplify`, `verify`, `codify`).
- `input_hash`: Digest del target y parámetros de entrada.
- `output_hash`: Digest SHA-256 del artifact payload.
- `method_version`: Versión metodológica (`v0.3`).
- `schema_version`: Versión del esquema (`v0.1-beta`).
- `execution_context_hash`: Digest del commit de Git y lockfile.
- `artifact_payload`: Diccionario de datos canónicos ordenados.

### 2. `runtime_receipt` (Telemetría de Observabilidad)
Datos transitorios que varían en cada ejecución:
- `producer`: Nombre del componente emisor.
- `timestamp`: Marca de tiempo ISO-8601 UTC.
- `duration_ms`: Duración de ejecución en milisegundos.
- `checks`: Lista de comprobaciones ejecutadas.
- `status`: Estado de verificación (`PASS`, `FAIL`, `WARN`).

$$\text{canonical\_manifest\_digest} = \text{SHA-256}(\text{CanonicalEvidence}_1, \dots, \text{CanonicalEvidence}_n)$$

---

## Relaciones

- [[adr-001-separacion-canonica-telemetria|trata]] — 💊 ADR formal que motivó esta separación.
- [[rule-evidence-001|indica]] — 🔬 Regla canónica que exige esta estructura.
- [[matriz-invariantes|usa]] — 🧠 Invariante evaluado en Layer 3 (Epistemic).
