---
name: hardening-loop
description: Audita, simplifica, verifica y codifica reglas de calidad determinísticamente sobre código con el ciclo de 5 fases (CLOOP). Incluye comandos de ejecución modular (run), revisión en la Aduana (review), auditoría criptográfica (inspect) y validación de esquemas (validate).
---

# Hardening Loop CLI Reference

Framework determinista de endurecimiento algorítmico en 5 fases (`question` $\to$ `delete` $\to$ `simplify` $\to$ `verify` $\to$ `codify`) con validación JSON Schema Fail-Closed, Sandboxing de Workspace y Aduana de Conocimiento.

---

## 🛠️ Subcomandos Disponibles en el CLI

### 1. `hardening-loop run` — Ejecución del Ciclo de Endurecimiento
Ejecuta las fases del pipeline sobre un archivo o módulo objetivo.

```bash
# Corrida completa con salida estructurada JSON para subagentes
hardening-loop run --target <path> --phase all --output evidence/<run-id> --workspace-root <ws-root> --json

# Corrida silenciosa (minimiza tokens en contexto)
hardening-loop run --target <path> --phase all --output evidence/<run-id> -q

# Ejecución de fases modulares individuales
hardening-loop run --target <path> --phase question --output evidence/<run-id> --json  # 1. Cuestionar supuestos
hardening-loop run --target <path> --phase delete   --output evidence/<run-id> --json  # 2. Podar código muerto y diff.patch
hardening-loop run --target <path> --phase simplify --output evidence/<run-id> --json  # 3. Reducir complejidad ciclomática
hardening-loop run --target <path> --phase verify   --output evidence/<run-id> --json  # 4. Tests deterministas (Status: PASS)
hardening-loop run --target <path> --phase codify   --output evidence/<run-id> --json  # 5. Generar KnowledgeCandidate
```

**Flags disponibles:**
- `--target <path>` *(Obligatorio)*: Archivo o directorio objetivo.
- `--phase <name>`: `all` (default), `question`, `delete`, `simplify`, `verify`, `codify`.
- `--output <dir>`: Directorio de destino de artefactos (default: `./evidence/run-001`).
- `--workspace-root <dir>`: Directorio raíz que confina el acceso seguro de archivos (Sandboxing).
- `--json`: Emite el manifest JSON estructurado a `stdout`.
- `-q, --quiet`: Silencia banners decorativos.

---

### 2. `hardening-loop inspect` — Auditoría Criptográfica e Integridad Anti-Tampering
Inspecciona un directorio de evidencias, valida schemas y recalcula los digests SHA-256 canónicos.

```bash
hardening-loop inspect evidence/<run-id> --json
```

**Garantías:**
- Valida que `canonical_manifest_digest` coincida exactamente con los bloques canónicos recalculados.
- Detecta manipulación, corrupción o alteración de datos (*Anti-Tampering*).
- Si detecta alteración o violación de schema, aborta con **Exit Code `2`**.

---

### 3. `hardening-loop validate` — Validación Rápida de Esquemas Normativos
Valida cualquier archivo JSON o YAML contra los esquemas normativos Draft-7 (`schemas/`).

```bash
# Autodetecta el esquema por contenido y extensión
hardening-loop validate evidence/<run-id>/knowledge_candidate.yaml --json

# Validación con esquema explícito
hardening-loop validate payload.json --schema evidence_envelope --json
```

**Esquemas disponibles en `--schema`:**
- `evidence_envelope` (`schemas/evidence_envelope.schema.json`)
- `knowledge_candidate` (`schemas/knowledge_candidate.schema.json`)
- `work_unit` (`schemas/work_unit.schema.json`)

---

### 4. `hardening-loop review` — Conocimiento en la Aduana (Knowledge Admission Gate)
Permite a un revisor humano o curador evaluar formalmente un `KnowledgeCandidate`.

```bash
# Admitir candidato
hardening-loop review evidence/<run-id>/knowledge_candidate.yaml --admit --reviewer "<curator-id>" --notes "<justification>" --json

# Rechazar candidato
hardening-loop review evidence/<run-id>/knowledge_candidate.yaml --reject --reviewer "<curator-id>" --notes "<reason>" --json
```

**Regla de Oro Constitucional (Leyes VIII y XII):**
- Queda terminantemente prohibida la auto-admisión directa a canónico.
- Todo candidato nace en `PENDING_REVIEW` y exige la firma de un revisor (`--reviewer`).

---

## 🚦 Tabla de Códigos de Salida POSIX

| Exit Code | Estado | Significado Técnico y Acción del Agente |
| :--- | :--- | :--- |
| **`0`** | `PASS` / `VALID` | Éxito total. Todos los contratos, schemas e invariantes fueron superados. |
| **`1`** | `FAIL` | Fallo funcional, test no superado o archivo no encontrado. Leer `test_results.json` o `contract_diff.json` para corregir. |
| **`2`** | `FAIL-CLOSED` | Violación de Schema JSON (`SchemaValidationError`), escape de workspace (`PathSandboxError`) o alteración criptográfica (`TAMPER_DETECTED`). Abortar inmediatamente. |
