---
name: hardening-loop
description: Audita, simplifica, verifica y codifica reglas de calidad determinísticamente sobre código con el ciclo de 5 fases (CLOOP). Incluye comandos de inspección criptográfica (inspect) y validación de esquemas (validate).
---

# Hardening Loop CLI

Framework de endurecimiento algorítmico en 5 fases (`question` $\to$ `delete` $\to$ `simplify` $\to$ `verify` $\to$ `codify`) con validación JSON Schema Fail-Closed, Sandboxing de Workspace y Aduana de Conocimiento.

## Cuándo Usar Esta Skill
- Al auditar código generado por modelos de IA o pipelines automáticos.
- Al podar wrappers innecesarios, abstracciones superfluas o código muerto.
- Para verificar regresiones y contratos de interfaces públicas.
- Al comprobar la integridad criptográfica de artefactos de evidencia (`inspect`).
- Al validar archivos contra schemas normativos (`validate`).

---

## Recetario Operativo para Agentes

### 1. Auditoría Completa (Modo Agente / JSON)
```bash
hardening-loop run --target <path-to-target> --phase all --output evidence/<run-id> --workspace-root <ws-root> --json
```

### 2. Inspección Criptográfica e Integridad de Evidencias (`inspect`)
```bash
hardening-loop inspect evidence/<run-id> --json
```
*Garantía:* Recalcula los digests SHA-256 canónicos y detecta alteraciones (retorna `exit 2` si hay manipulación de datos).

### 3. Validación Aislada de Esquemas (`validate`)
```bash
# Validar KnowledgeCandidate o WorkUnit
hardening-loop validate evidence/<run-id>/knowledge_candidate.yaml --json
```

### 4. Aduana de Conocimiento (Knowledge Admission Gate)
```bash
# Admitir candidato
hardening-loop review evidence/<run-id>/knowledge_candidate.yaml --admit --reviewer "<agent-id>" --notes "<justification>" --json

# Rechazar candidato
hardening-loop review evidence/<run-id>/knowledge_candidate.yaml --reject --reviewer "<agent-id>" --notes "<reason>" --json
```

---

## Tabla de Códigos de Salida POSIX
| Exit Code | Estado | Acción Requerida por el Agente |
| :--- | :--- | :--- |
| **`0`** | `PASS` / `INTEGRITY_PASS` | Éxito total. Continuar con la siguiente tarea. |
| **`1`** | `FAIL` | Leer `test_results.json` o `contract_diff.json` para reparar el código. |
| **`2`** | `FAIL-CLOSED` | Violación de Schema JSON, escape de workspace (`PathSandboxError`) o alteración criptográfica. Abortar inmediatamente. |
