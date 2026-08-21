# Algorithmic Code Hardening Loop — Especificación Operacional v0.1

## 1. Fundamentos y Filosofía

El **Algorithmic Code Hardening Loop** es un marco de endurecimiento determinista para código generado por modelos de lenguaje (LLM), basado en los principios de ingeniería de Zechner y el algoritmo de 5 pasos de Musk:

> "El agente permanece simple.  
> El entorno acumula aprendizaje.  
> La evidencia decide qué conocimiento sobrevive."

### Principios Inquebrantables
1. **Anti-Slop / Anti-Ferrari**: No crear agentes secundarios, MCPs, ni abstracciones antes de validar la necesidad con evidencia y tests.
2. **Determinismo de Evidencia**: Ninguna afirmación es válida sin un `EvidenceEnvelope` inmutable indexado por SHA-256 de entrada y salida.
3. **Knowledge Admission Gate**: Las observaciones de un LLM o runner jamás se publican automáticamente como conocimiento canónico o reglas ejecutables. Requieren pasar por la aduana de revisión humana/curatorial.

---

## 2. El Ciclo de Endurecimiento en 5 Fases

```text
1. QUESTION CONTEXT
   ↓ (requirements_audit.json)
2. DELETE HARNESS
   ↓ (deletion_candidates.json, diff.patch, rollback_ref)
3. SIMPLIFY INTERFACES
   ↓ (contract_diff.json)
4. VERIFY FASTER
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
| **`verify`** | Target / patch | `test_results.json`, `benchmark.json`, `runtime_evidence.json` | Medición de ciclo TDD y tiempos de respuesta. |
| **`codify`** | Hallazgos verificados y evidencias | `knowledge_candidate.yaml`, `admission_record.json` | Extracción de reglas candidatas con referencias a `evidence_id`. |

---

## 3. Modelo de Estados

```text
[DRAFT] 
   │ (Inicio de auditoría)
   ▼
[AUDITING] 
   │ (Propuesta de parches/simplificaciones)
   ▼
[PATCH_PROPOSED] 
   │ (Suite de tests y verificación completa)
   ▼
[VERIFIED] 
   │ (Generación de Knowledge Candidate)
   ▼
[KNOWLEDGE_CANDIDATE]
   │
   ├──────► [REJECTED / OBSOLETE] (Rechazado en Aduana)
   │
   ▼ (Aprobación explícita en Knowledge Admission Gate)
[ADMITTED]
   │ (Formalización en reglas ejecutables / linter / test fixture)
   ▼
[CANONICAL]
   │ (Superado por nuevo aprendizaje)
   ▼
[DEPRECATED]
```

### Reglas de Transición
1. `DRAFT -> AUDITING`: Al inicializar el `WorkUnit` y computar el `target_hash` inicial.
2. `AUDITING -> PATCH_PROPOSED`: Al completar las fases `question`, `delete` y `simplify`.
3. `PATCH_PROPOSED -> VERIFIED`: Solo si la fase `verify` retorna `status: PASS` y todos los checks son exitosos.
4. `VERIFIED -> KNOWLEDGE_CANDIDATE`: Al generar la propuesta formal de regla en `codify`.
5. `KNOWLEDGE_CANDIDATE -> ADMITTED`: **Exclusivamente mediante revisión explícita en la Aduana**.
6. `ADMITTED -> CANONICAL`: Cuando se genera una regla ejecutable (test o linter) vinculada al repositorio.
7. `CANONICAL -> DEPRECATED`: Cuando se invalida la regla con nueva evidencia.

---

## 4. Gobernanza del Knowledge Admission Gate

Queda terminantemente prohibido el flujo:
`Observación -> Wiki / Regla Automática`

El flujo formal y auditado es:
```text
Observation (Dato empírico)
   ↓
Finding (Problema clasificado con severidad y líneas afectadas)
   ↓
Knowledge Candidate (Propuesta de regla y justificación con hash de evidencia)
   ↓
Review (Aduana con decisión explícita: ACCEPTED / REJECTED)
   ↓
Accepted Knowledge (Registro de conocimiento admitido con firma de revisor)
   ↓
Executable Rule (Linter / Test Fixture / Guard en CI)
```

---

## 5. Esquemas de Datos

Los esquemas JSON normativos se encuentran en:
- `schemas/work_unit.schema.json`
- `schemas/evidence_envelope.schema.json`
- `schemas/knowledge_candidate.schema.json`
