---
name: hardening-loop
description: Audita, simplifica, verifica y codifica reglas de calidad determinísticamente sobre código con el ciclo de 5 fases (CLOOP). Incluye comandos de ejecución modular (run), revisión en la Aduana (review), auditoría criptográfica (inspect), validación de esquemas (validate) y telemetría de rendimiento (telemetry).
---

# Hardening Loop CLI Reference

Framework determinista de endurecimiento algorítmico en 5 fases (`question` $\to$ `delete` $\to$ `simplify` $\to$ `verify` $\to$ `codify`) con validación JSON Schema Fail-Closed, Sandboxing de Workspace, Telemetría de Rendimiento y Aduana de Conocimiento.

---

## 🛠️ Subcomandos Disponibles en el CLI

### 1. `hardening-loop run` — Ejecución del Ciclo de Endurecimiento
Ejecuta las fases del pipeline sobre un archivo o módulo objetivo.

```bash
# Corrida completa con salida estructurada JSON para subagentes
hardening-loop run --target <path> --phase all --output evidence/<run-id> --workspace-root <ws-root> --json

# Corrida silenciosa (minimiza tokens en contexto)
hardening-loop run --target <path> --phase all --output evidence/<run-id> -q
```

---

### 2. `hardening-loop telemetry` — Telemetría, Latencias y Throughput
Mide y reporta el rendimiento de procesamiento del loop (latencias por fase, LOC/s, memoria RSS).

```bash
# Reporte visual tabular
hardening-loop telemetry evidence/<run-id>

# Reporte JSON para agentes o dashboards
hardening-loop telemetry evidence/<run-id> --json
```

**Métricas provistas:**
- ⏱️ `phase_durations_ms`: Latencia individual de cada fase (`question`, `delete`, `simplify`, `verify`, `codify`).
- 🚀 `throughput_loc_per_sec`: Velocidad de procesamiento (líneas de código por segundo).
- 💾 `peak_memory_mb`: Memoria RSS residente consumida.
- 🏁 `total_duration_ms` y `final_status` (`PASS` / `WARN` / `FAIL`).

---

### 3. `hardening-loop inspect` — Auditoría Criptográfica e Integridad Anti-Tampering
Inspecciona un directorio de evidencias, valida schemas y recalcula los digests SHA-256 canónicos.

```bash
hardening-loop inspect evidence/<run-id> --json
```

---

### 4. `hardening-loop validate` — Validación Rápida de Esquemas Normativos
Valida cualquier archivo JSON o YAML contra los esquemas normativos Draft-7 (`schemas/`).

```bash
hardening-loop validate evidence/<run-id>/knowledge_candidate.yaml --json
```

---

### 5. `hardening-loop review` — Conocimiento en la Aduana (Knowledge Admission Gate)
Permite a un revisor humano o curador evaluar formalmente un `KnowledgeCandidate`.

```bash
hardening-loop review evidence/<run-id>/knowledge_candidate.yaml --admit --reviewer "<curator-id>" --notes "<justification>" --json
```

---

## 🚦 Tabla de Códigos de Salida POSIX

| Exit Code | Estado | Significado Técnico y Acción del Agente |
| :--- | :--- | :--- |
| **`0`** | `PASS` / `VALID` | Éxito total. Todos los contratos, schemas e invariantes fueron superados. |
| **`1`** | `FAIL` | Fallo funcional, test no superado o archivo no encontrado. Leer `test_results.json` o `contract_diff.json` para corregir. |
| **`2`** | `FAIL-CLOSED` | Violación de Schema JSON (`SchemaValidationError`), escape de workspace (`PathSandboxError`) o alteración criptográfica (`TAMPER_DETECTED`). Abortar inmediatamente. |
