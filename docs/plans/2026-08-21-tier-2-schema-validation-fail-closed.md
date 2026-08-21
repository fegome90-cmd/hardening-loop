# Plan: Tier 2 — Enforcement Fail-Closed de Schemas JSON (Leyes VI y VIII)

## 1. Problem Statement
Actualmente, el repositorio cuenta con esquemas normativos en `schemas/` (`work_unit.schema.json`, `evidence_envelope.schema.json`, `knowledge_candidate.schema.json`), pero su cumplimiento no se valida en tiempo de ejecución. Los artefactos y envelopes se emiten mediante serialización directa de dataclasses sin contrastar formalmente contra los esquemas JSON.

Esto viola dos leyes fundamentales de [AGENTS.md](file:///Users/felipe_gonzalez/Developer/hardening-loop/AGENTS.md):
- **Ley VI (Fuente de Verdad):** Los esquemas JSON son el SSOT y deben regir la estructura de intercambio.
- **Ley VIII (Seguridad Agéntica & Fail-Closed):** Ante cualquier discrepancia en un contrato o schema, el sistema debe abortar de inmediato (`fail-closed`), sin asumir éxito silencioso.

## 2. Invariantes y Reglas Constitucionales
1. **Validación Obligatoria en Runtime:** Todo `EvidenceEnvelope`, `WorkUnit` y `KnowledgeCandidate` generado o cargado debe validarse deterministamente contra su respectivo esquema JSON.
2. **Fail-Closed Estricto:** Si un payload contiene campos faltantes, tipos inválidos, formatos incorrectos de hashes (SHA-256 $\ne 64$ caracteres hex) o propiedades no autorizadas (`additionalProperties: false`), se lanza `SchemaValidationError` y se interrumpe la ejecución.
3. **Cero Dependencias Circulares:** El módulo `schema_validator.py` residirá en el core de `src/hardening_loop/` conforme a la Regla de Scope (Ley III, Inciso 7.1).

## 3. Arquitectura y Cambios Propuestos

### A. Dependencias en `pyproject.toml`
- Agregar `jsonschema>=4.20.0` a las dependencias del proyecto.
- Agregar `types-jsonschema` en `[project.optional-dependencies].dev`.

### B. Core Schema Validator (`src/hardening_loop/schema_validator.py`)
- Implementar `SchemaValidationError(Exception)`.
- Implementar función `validate_payload(data: dict[str, Any], schema_name: str) -> None` con carga y caching eficiente de schemas desde `schemas/`.
- Mapeo de schemas canónicos:
  - `"evidence_envelope"` $\to$ `schemas/evidence_envelope.schema.json`
  - `"knowledge_candidate"` $\to$ `schemas/knowledge_candidate.schema.json`
  - `"work_unit"` $\to$ `schemas/work_unit.schema.json`

### C. Integración en el Loop de Ejecución
- **`BasePhase.run()` ([src/hardening_loop/phases/base.py](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/phases/base.py)):** Validar el `EvidenceEnvelope.to_dict()` antes de retornar.
- **`KnowledgeAdmissionGate` ([src/hardening_loop/admission.py](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/admission.py)):** Validar `candidate.to_dict()` en `create_candidate()`, `review_candidate()` y `load_candidate_yaml()`.
- **`HardeningRunner` ([src/hardening_loop/runner.py](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/runner.py)):** Validar `work_unit.to_dict()` al instanciar y al registrar en el manifest.

### D. Suite de Pruebas TDD (`tests/test_schema_validation.py`)
- Test de validación exitosa de los 3 tipos de artefactos.
- Test fail-closed ante hashes SHA-256 inválidos (longitud, caracteres no-hex).
- Test fail-closed ante ids malformados (`evi-*`, `kc-*`, `wu-*`).
- Test fail-closed ante enums no reconocidos o campos faltantes.
- Test fail-closed ante propiedades adicionales no declaradas.

## 4. Verification Plan

### Automated Gates
1. `make install` para actualizar dependencias en el virtualenv.
2. `pytest tests/test_schema_validation.py -v` (Red $\to$ Green).
3. `make check` (Gate unificado: `lint` + `typecheck` + `test`).
