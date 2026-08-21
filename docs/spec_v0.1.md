# Algorithmic Code Hardening Loop — Especificación Operacional v0.1-beta

## 1. Fundamentos y Filosofía

El **Algorithmic Code Hardening Loop** es un marco de endurecimiento determinista para código generado por modelos de lenguaje (LLM), basado en los principios de ingeniería de Zechner y el algoritmo de 5 pasos de Musk:

> "El agente permanece simple.  
> El entorno acumula aprendizaje.  
> La evidencia decide qué conocimiento sobrevive."

### Principios Inquebrantables
1. **Anti-Slop / Anti-Ferrari**: No crear agentes secundarios, MCPs, ni abstracciones antes de validar la necesidad con evidencia y tests.
2. **Determinismo de la Capa Canónica (Canonical Evidence Determinism)**: Ninguna afirmación es válida sin un `EvidenceEnvelope` inmutable estructurado en dos bloques aislados:
   - `canonical_evidence`: Identidad determinista libre de reloj (`evidence_id`, `input_hash`, `output_hash`, `method_version`, `schema_version`, `execution_context_hash`, `artifact_payload`).
   - `runtime_receipt`: Telemetría no determinista de observabilidad (`producer`, `timestamp`, `duration_ms`, `checks`, `status`).
3. **Knowledge Admission Gate (Aserción de Revisor Humano)**: Las observaciones de un LLM o runner jamás se publican automáticamente como conocimiento canónico o reglas ejecutables. Requieren pasar por la aduana de revisión con una **Aserción de Revisor Humano Declarada** explícita (`RULE-GATE-001`).
4. **Separación de Autoridad vs Evidencia**: El hecho de que un sistema complete sus verificaciones automatizadas declara el estado `READY_FOR_PR_REVIEW`, pero **la promoción a conocimiento CANONICAL requiere siempre revisión externa explícita**.

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
| **`simplify`** | Código tras eliminación, diffs | `contract_diff.json` | Preservación estricta de interfaces públicas externas y firmas de tipos. |
| **`verify`** | Target / patch | `test_results.json`, `benchmark.json`, `runtime_evidence.json` | Medición del ciclo TDD (`< 100ms`), cobertura funcional e invariantes ontológicos. |
| **`codify`** | Hallazgos verificados y evidencias | `knowledge_candidate.yaml`, `admission_record.json` | Extracción de reglas candidatas vinculadas a `evidence_id` y firma de aduana. |

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
   │ (Suite de tests estratificada en 3 capas)
   ▼
[VERIFIED] 
   │ (Generación de Knowledge Candidate con ID hexadecimal determinista)
   ▼
[KNOWLEDGE_CANDIDATE]
   │
   ├──────► [REJECTED / OBSOLETE] (Rechazado en Aduana)
   │
   ▼ (Aserción de Revisor Humano en Knowledge Admission Gate - RULE-GATE-001)
[ADMITTED]
   │ (Formalización en reglas ejecutables / linter / test fixture)
   ▼
[READY_FOR_PR_REVIEW]
   │ (Revisión Externa y Merge Mainline)
   ▼
[CANONICAL]
   │ (Superado por nuevo aprendizaje validado)
   ▼
[DEPRECATED]
```

---

## 4. Matriz de Cobertura de Invariantes (Ontological Invariants)

A diferencia de la cobertura de líneas de código (89%), la validez del sistema se mide por su matriz de invariantes:

| Capa Ontológica | Invariante Verificado | Mecanismo de Enforcement | Estado |
| :--- | :--- | :--- | :---: |
| **Layer 1: Implementation** | Parsing AST determinista, digest de directorios y CLI parsing. | `tests/test_l1_implementation.py` | `PASS` |
| **Layer 2: Contracts** | Autómata de estados acíclico y validación JSON Schema fail-closed. | `tests/test_l2_contracts.py` + `Draft7Validator` | `PASS` |
| **Layer 3: Epistemic** | `canonical_manifest_digest` bit-for-bit match entre ejecuciones independientes. | `tests/test_l3_epistemic.py` | `PASS` |
| **Layer 3: Epistemic** | Prohibición de evidencia sin `execution_context_hash` (Git SHA + Lockfile). | `tests/test_l3_epistemic.py` | `PASS` |
| **Layer 3: Epistemic** | Prohibición de `ADMITTED` sin `reviewer.strip() != ""` (Aserción Humana). | `tests/test_l3_epistemic.py` | `PASS` |
| **Layer 3: Epistemic** | Prohibición de salto de `DRAFT` a `CANONICAL` sin pasar por Aduana. | `tests/test_l3_epistemic.py` | `PASS` |

---

## 5. Reglas Normativas Admitidas en el Repositorio

* **`RULE-EVIDENCE-001` (SCHEMA_GUARD):** Todo sobre de evidencia debe desacoplar el bloque determinista `canonical_evidence` de la telemetría `runtime_receipt` e incluir `execution_context_hash` (Git commit SHA + Lockfile digest).
* **`RULE-GATE-001` (CONTRACT_VALIDATOR):** La función de revisión de la Aduana exige obligatoriamente una aserción de revisor humano declarada no vacía (`reviewer.strip()`).
