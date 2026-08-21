# Algorithmic Code Hardening Loop — Especificación Operacional v0.1-beta

## 1. Fundamentos y Filosofía

El **Algorithmic Code Hardening Loop** es un marco de endurecimiento determinista para código generado por modelos de lenguaje (LLM), basado en los principios de ingeniería de Zechner y el algoritmo de 5 pasos de Musk:

> "El agente permanece simple.  
> El entorno acumula aprendizaje.  
> La evidencia decide qué conocimiento sobrevive."

### Principios Inquebrantables
1. **Anti-Slop / Anti-Ferrari**: No crear agentes secundarios, MCPs, ni abstracciones antes de validar la necesidad con evidencia y tests.
2. **Determinismo de Evidencia Canónica**: Ninguna afirmación es válida sin un `EvidenceEnvelope` inmutable estructurado en dos bloques:
   - `canonical_evidence`: Identidad determinista libre de reloj (`evidence_id`, `input_hash`, `output_hash`, `method_version`, `schema_version`, `execution_context_hash`, `artifact_payload`).
   - `runtime_receipt`: Telemetría no determinista (`timestamp`, `duration_ms`, `checks`, `status`).
3. **Knowledge Admission Gate**: Las observaciones de un LLM o runner jamás se publican automáticamente como conocimiento canónico o reglas ejecutables. Requieren pasar por la aduana de revisión con una **Aserción de Revisor Humano** explícita (`RULE-GATE-001`).

---

## 2. El Ciclo de Endurecimiento en 5 Fases

```text
1. QUESTION CONTEXT
   ↓ (requirements_audit.json)
2. DELETE HARNESS
   ↓ (deletion_candidates.json, diff.patch, rollback_ref)
3. SIMPLIFY INTERFACES
   ↓ (contract_diff.json)
4. VERIFY FASTER & CANONICAL DETERMINISM
   ↓ (test_results.json, benchmark.json, runtime_evidence.json)
5. CODIFY VALIDATED LEARNING
   ↓ (knowledge_candidate.yaml, admission_record.json)
```

### Contratos de Entrada/Salida por Fase

| Fase | Entrada | Salida Obligatoria | Criterio de Verificación |
| :--- | :--- | :--- | :--- |
| **`question`** | Código objetivo, especificaciones | `requirements_audit.json` | Clasificación de requerimientos en `explicit`, `inferred`, `historical`, `security_constraint`. |
| **`delete`** | Audit de requerimientos, código | `deletion_candidates.json`, `diff.patch`, `rollback_ref` | Detección de código muerto, wrappers superfluos, bypasses y acoplamientos rígidos. |
| **`simplify`** | Código tras eliminación, diffs | `contract_diff.json` | Preservación estricta de interfaces públicas externas y tipos. |
| **`verify`** | Target / patch | `test_results.json`, `benchmark.json`, `runtime_evidence.json` | Medición del ciclo TDD (`< 100ms`) y validación estricta de invariantes ontológicos. |
| **`codify`** | Hallazgos verificados y evidencias | `knowledge_candidate.yaml`, `admission_record.json` | Extracción de reglas candidatas con referencias a `evidence_id` y firma de aduana. |

---

## 3. Modelo de Estados

```text
[DRAFT] 
   │ (Inicio de auditoría / Canonical Directory Digest)
   ▼
[AUDITING] 
   │ (Propuesta de parches/simplificaciones)
   ▼
[PATCH_PROPOSED] 
   │ (Suite de tests en 3 capas)
   ▼
[VERIFIED] 
   │ (Generación de Knowledge Candidate con ID hexadecimal)
   ▼
[KNOWLEDGE_CANDIDATE]
   │
   ├──────► [REJECTED / OBSOLETE] (Rechazado en Aduana)
   │
   ▼ (Aprobación explícita en Knowledge Admission Gate - RULE-GATE-001)
[ADMITTED]
   │ (Formalización en reglas ejecutables / linter / test fixture)
   ▼
[CANONICAL]
   │ (Superado por nuevo aprendizaje)
   ▼
[DEPRECATED]
```

---

## 4. Estratificación de la Suite de Pruebas (3 Layers)

1. **Layer 1 — Implementation Tests (`tests/test_l1_implementation.py`):**
   - Validación de parsers AST, serializadores YAML/JSON, argumentos de CLI y digest de directorios.
2. **Layer 2 — Contract Invariants (`tests/test_l2_contracts.py`):**
   - Transiciones del autómata de estados y validación estricta fail-closed de los esquemas JSON (`Draft7Validator`).
3. **Layer 3 — Epistemic Invariants (`tests/test_l3_epistemic.py`):**
   - Determinismo reproducible bit-a-bit del `canonical_manifest_digest` entre ejecuciones independientes.
   - Prohibición de evidencia sin proveniencia (`execution_context_hash`, `method_version`, `schema_version`).
   - Imposibilidad ontológica de alcanzar el estado `CANONICAL` sin registro de admisión aprobado por un revisor humano.

---

## 5. Reglas Normativas Admitidas en el Repositorio

* **`RULE-EVIDENCE-001` (SCHEMA_GUARD):** Todo sobre de evidencia debe desacoplar el bloque determinista `canonical_evidence` de la telemetría `runtime_receipt` e incluir `execution_context_hash`.
* **`RULE-GATE-001` (CONTRACT_VALIDATOR):** La función de revisión de la Aduana exige obligatoriamente una aserción de revisor humano no vacía (`reviewer.strip()`).
