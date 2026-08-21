# Algorithmic Code Hardening Loop — Especificación Operacional v0.1-beta

## 1. Fundamentos y Filosofía

El **Algorithmic Code Hardening Loop** es un marco de endurecimiento determinista para código generado por modelos de lenguaje (LLM), basado en los principios de ingeniería de Zechner y el algoritmo de 5 pasos de Musk:

> "El agente permanece simple.  
> El entorno acumula aprendizaje.  
> La evidencia decide qué conocimiento sobrevive."

### Principios Inquebrantables
1. **Anti-Slop / Anti-Ferrari**: No crear agentes secundarios, MCPs, ni abstracciones antes de validar la necesidad con evidencia y tests.
2. **Determinismo y Hermeticidad de Evidencia**: Ninguna afirmación es válida sin un `EvidenceEnvelope` inmutable indexado por SHA-256 de entrada y salida, incluyendo `method_version` y `environment_hash`.
3. **Knowledge Admission Gate**: Las observaciones de un LLM o runner jamás se publican automáticamente como conocimiento canónico o reglas ejecutables. Requieren pasar por la aduana de revisión humana/curatorial con firma de identidad obligatoria (`RULE-GATE-001`).

---

## 2. El Ciclo de Endurecimiento en 5 Fases

```text
1. QUESTION CONTEXT
   ↓ (requirements_audit.json)
2. DELETE HARNESS
   ↓ (deletion_candidates.json, diff.patch, rollback_ref)
3. SIMPLIFY INTERFACES
   ↓ (contract_diff.json)
4. VERIFY FASTER & HERMETICITY
   ↓ (test_results.json, benchmark.json, runtime_evidence.json)
5. CODIFY VALIDATED LEARNING
   ↓ (knowledge_candidate.yaml, admission_record.json)
```

### Contratos de Entrada/Salida por Fase

| Fase | Entrada | Salida Obligatoria | Criterio de Verificación |
| :--- | :--- | :--- | :--- |
| **`question`** | Código objetivo, especificaciones | `requirements_audit.json` | Clasificación de requerimientos en `explicit`, `inferred`, `historical`, `security_constraint`. |
| **`delete`** | Audit de requerimientos, código | `deletion_candidates.json`, `diff.patch`, `rollback_ref` | Detección de código muerto, wrappers superfluos, herramientas no whitelisteadas. |
| **`simplify`** | Código tras eliminación, diffs | `contract_diff.json` | Preservación de interfaces externas y tipos, reducción de firmas complejas. |
| **`verify`** | Target / patch | `test_results.json`, `benchmark.json`, `runtime_evidence.json` | Medición de ciclo TDD, SLA de latencia (`< 100ms`) y consistencia de hashes herméticos. |
| **`codify`** | Hallazgos verificados y evidencias | `knowledge_candidate.yaml`, `admission_record.json` | Extracción de reglas candidatas con referencias a `evidence_id` y firma de aduana. |

---

## 3. Modelo de Estados

```text
[DRAFT] 
   │ (Inicio de auditoría / hashing Merkle)
   ▼
[AUDITING] 
   │ (Propuesta de parches/simplificaciones)
   ▼
[PATCH_PROPOSED] 
   │ (Suite de tests y verificación de hermeticidad)
   ▼
[VERIFIED] 
   │ (Generación de Knowledge Candidate con ID hexadecimal determinista)
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

## 4. Dogfooding & Reglas Canónicas Admitidas

El framework fue validado exitosamente contra sí mismo (`DOGFOODING-001`), admitiendo las siguientes reglas normativas:

* **`RULE-EVIDENCE-001` (SCHEMA_GUARD):** Todo sobre de evidencia (`EvidenceEnvelope`) debe incluir explícitamente `method_version` y `environment_hash` para garantizar reproducibilidad hermética cross-platform.
* **`RULE-GATE-001` (CONTRACT_VALIDATOR):** La función de revisión de la Aduana (`review_candidate`) exige obligatoriamente un identificador de revisor humano no vacío (`reviewer.strip()`) para prevenir auto-admisiones espurias.
* **`RULE-SEC-001` (CONTRACT_VALIDATOR):** Los wrappers de ejecución de herramientas LLM deben validar los comandos contra un set estricto de binarios permitidos (no shell abierto).
* **`RULE-SEC-002` (SCHEMA_GUARD):** Toda lectura de archivo debe resolver rutas canónicas (`os.path.realpath`) y verificar la contención estricta dentro del directorio del workspace.
