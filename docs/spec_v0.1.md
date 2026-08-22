# Algorithmic Code Hardening Loop — Especificación Operacional v0.3

## 1. Fundamentos y Filosofía

El **Algorithmic Code Hardening Loop** es un marco de endurecimiento determinista para código generado por modelos de lenguaje (LLM) y sistemas agénticos, basado en los principios de ingeniería de Zechner y el algoritmo de 5 pasos de Musk:

> "El agente permanece simple.
> El entorno acumula aprendizaje.
> La evidencia decide qué conocimiento sobrevive."

### Invariantes Constitucionales (AGENTS.md)
1. **Anti-Slop / Anti-Ferrari (Ley III):** Arquitectura minimalista sin dependencias pesadas ni capas de abstracción innecesarias.
2. **Determinismo de la Capa Canónica (Leyes IX y XI):** Ninguna afirmación es válida sin un `EvidenceEnvelope` inmutable estructurado en dos bloques aislados:
   - `canonical_evidence`: Identidad determinista libre de reloj (`evidence_id`, `input_hash`, `output_hash`, `method_version`, `schema_version`, `execution_context_hash`, `artifact_payload`).
   - `runtime_receipt`: Telemetría no determinista de observabilidad (`producer`, `timestamp`, `duration_ms`, `checks`, `status`).
3. **Principio Fail-Closed (Ley VIII):** Ante cualquier fallo de seguridad, violación de esquema, hash discrepante o excepción no recuperable, el sistema aborta de inmediato (`fail-closed`).
4. **Knowledge Admission Gate (Leyes VIII y XII):** Prohibición terminante de auto-admisión o promoción automática a estado canónico. Toda regla exige revisión humana explícita (`RULE-GATE-001`).
5. **Aislamiento y Sandboxing de Workspace (Ley VIII):** Toda operación de lectura/escritura está confinada estrictamente a los límites del workspace (`workspace_root`), fallando cerrado ante intentos de escape o path traversal.

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

| Fase | Entrada | Salida Obligatoria | Criterio de Verificación & Enforcement |
| :--- | :--- | :--- | :--- |
| **`question`** | Código objetivo, especificaciones | `requirements_audit.json` | Clasificación de requerimientos en `explicit`, `inferred`, `historical`, `security_constraint`. Atribución AST exacta `archivo:línea (scope)`. |
| **`delete`** | Audit de requerimientos, código | `deletion_candidates.json`, `diff.patch`, `rollback_ref` | Detección y poda de invocaciones `os.system`, `subprocess shell=True`, `eval`/`exec` y paths absolutos hardcodeados. |
| **`simplify`** | Código tras eliminación, diffs | `contract_diff.json` | Inferencia y preservación de tipos de retorno (`infer_return_type`) e interfaces públicas. |
| **`verify`** | Target / patch aplicado | `test_results.json`, `benchmark.json`, `runtime_evidence.json` | Verificación AST estática target-centric. Falla cerrado (`FAIL`) ante errores de sintaxis o violaciones de seguridad `CRITICAL`/`HIGH` (`eval`/`exec`, `shell=True`, core invariants). Emite advertencia (`WARN`) no bloqueante ante problemas de portabilidad/calidad (`paths_check` `MEDIUM`/`LOW`). |
| **`codify`** | Hallazgos verificados y evidencias | `knowledge_candidate.yaml`, `admission_record.json` | Extracción dinámica de reglas candidatas estructuradas en estado `PENDING_REVIEW` listas para la Aduana. |

---

## 3. Arquitectura del CLI y Subcomandos

El framework provee una interfaz CLI unificada:

```bash
# 1. Ejecución del ciclo de endurecimiento
hardening-loop run --target <path> --phase all --output evidence/run-001 [--json] [-q]

# 2. Revisión y decisión en la Aduana (Knowledge Admission Gate)
hardening-loop review <candidate.yaml> --admit|--reject --reviewer <id> [--notes <txt>]

# 3. Inspección criptográfica e integridad de archivos físicos
hardening-loop inspect <evidence_dir> [--workspace-root <dir>] [--json]

# 4. Validación estricta de esquemas JSON / YAML
hardening-loop validate <artifact_file> [--schema <name>]

# 5. Telemetría de rendimiento y exportación a PostHog
hardening-loop telemetry <evidence_dir> [--posthog] [--api-key <key>] [--dry-run] [--json]
```

---

## 4. Manifiesto Unificado v0.2 y Structured WAL (`telemetry.jsonl`)

El runner genera un manifiesto criptográficamente verificable `evidence_manifest.json` respaldado por un log append-only WAL (`telemetry.jsonl`):

```json
{
  "schema_version": "hardening-loop.manifest.v0.2",
  "run_id": "hl_324c01071106",
  "trace_id": "tr_324c010711060000",
  "created_at": "2026-08-21T20:00:00+00:00",
  "git_sha": "c4cfbdf...",
  "dirty_worktree": false,
  "final_status": "PASS",
  "artifacts": [
    { "path": "requirements_audit.json", "type": "evidence", "sha256": "..." },
    { "path": "deletion_candidates.json", "type": "evidence", "sha256": "..." },
    { "path": "diff.patch", "type": "patch", "sha256": "..." },
    { "path": "test_results.json", "type": "evidence", "sha256": "..." },
    { "path": "telemetry.jsonl", "type": "telemetry", "sha256": "..." }
  ],
  "integrity": {
    "hash_algorithm": "sha256",
    "manifest_hash": "...",
    "artifact_count": 5,
    "integrity_status": "PASS"
  },
  "canonical_manifest_digest": "...",
  "work_unit": { ... },
  "envelopes": [ ... ],
  "runtime_telemetry": {
    "total_duration_ms": 42.5,
    "total_loc_analyzed": 119,
    "total_ast_nodes_visited": 350,
    "throughput_loc_per_sec": 2800.0,
    "initial_memory_mb": 18.2,
    "peak_memory_mb": 19.4,
    "memory_delta_mb": 1.2,
    "final_status": "PASS"
  }
}
```

> [!NOTE]
> **Modelo de Amenazas de Integridad (Anti-Ferrari):** `manifest_hash` proporciona detección determinista de corrupción accidental, inconsistencias internas de serialización y desincronización parcial entre los artefactos físicos y el manifiesto. Los hashes SHA-256 de los artefactos verifican la inmutabilidad de cada archivo individual. Este mecanismo autocontenido no pretende sustituir autenticación criptográfica con claves secretas (como HMAC simétrico o firmas digitales asimétricas basadas en infraestructura PKI) cuando un atacante posee permisos totales de reescritura sobre el sistema de archivos local.

---

## 5. Modelo de Estados y Transiciones

```text
[DRAFT]
   │ (Inicio de auditoría / Canonical Directory Digest)
   ▼
[AUDITING]
   │ (Ejecución de fases question, delete, simplify)
   ▼
[PATCH_PROPOSED]
   │ (Suite de verificación y checks de seguridad AST en VerifyPhase)
   ▼
[VERIFIED]
   │ (Generación de KnowledgeCandidate en CodifyPhase)
   ▼
[KNOWLEDGE_CANDIDATE] (Estado: PENDING_REVIEW)
   │
   ├──────► [REJECTED / OBSOLETE] (Rechazado en Aduana)
   │
   ▼ (Aserción de Revisor Humano en Knowledge Admission Gate)
[ADMITTED]
   │ (Formalización en test determinista / linter / fixture en CI)
   ▼
[READY_FOR_PR_REVIEW]
   │ (Revisión Externa y Merge Mainline)
   ▼
[CANONICAL]
   │ (Superado por nuevo aprendizaje empírico)
   ▼
[DEPRECATED]
```
