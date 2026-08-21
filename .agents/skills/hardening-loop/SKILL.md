---
name: hardening-loop
description: Audita, simplifica, verifica y codifica reglas de calidad determinísticamente sobre código con el ciclo de 5 fases (CLOOP). Usar cuando se audite código generado por IA, se pode código muerto, se verifiquen contratos o se extraigan reglas de admisión.
---

# Hardening Loop CLI

Framework de endurecimiento algorítmico en 5 fases (`question` $\to$ `delete` $\to$ `simplify` $\to$ `verify` $\to$ `codify`) con validación JSON Schema Fail-Closed y Aduana de Conocimiento.

## Cuándo Usar Esta Skill
- Al auditar código generado por modelos de IA o pipelines automáticos.
- Al podar wrappers innecesarios, abstracciones superfluas o código muerto.
- Para verificar regresiones y contratos de interfaces públicas.
- Al formalizar hallazgos empíricos en candidatos de conocimiento (`knowledge_candidate.yaml`).

## Cuándo NO Usar
- Para formateo estético simple (usar `make format` o `ruff`).
- Para diseño de arquitectura desde cero (usar `sdd-design` o `sdd-spec`).

---

## Recetario Operativo para Agentes

### 1. Auditoría Completa (Modo Agente / JSON)
```bash
hardening-loop run --target <path-to-target> --phase all --output evidence/<run-id> --json
```
*Interpretación:* Si retorna `exit 0`, el código cumple la constitución y genera `evidence/<run-id>/evidence_manifest.json`.

### 2. Ejecución Silenciosa (Token-Efficient)
```bash
hardening-loop run --target <path-to-target> --phase all --output evidence/<run-id> -q
```

### 3. Ejecución Selectiva por Fase
```bash
# Fase 1: Cuestionar supuestos y clasificar requerimientos
hardening-loop run --target <path> --phase question --output evidence/<run-id> --json

# Fase 2: Podar código muerto y generar diff.patch
hardening-loop run --target <path> --phase delete --output evidence/<run-id> --json

# Fase 3: Reducir complejidad ciclomática
hardening-loop run --target <path> --phase simplify --output evidence/<run-id> --json

# Fase 4: Ejecutar suite de pruebas y verificar estado PASS
hardening-loop run --target <path> --phase verify --output evidence/<run-id> --json

# Fase 5: Codificar reglas candidatas en PENDING_REVIEW
hardening-loop run --target <path> --phase codify --output evidence/<run-id> --json
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
| **`0`** | `PASS` | Continuar con la siguiente tarea. Todos los contratos superados. |
| **`1`** | `FAIL` | Leer `evidence/<run-id>/test_results.json` o `contract_diff.json` para reparar el código. |
| **`2`** | `SCHEMA ERROR` | Violación de Schema JSON. Abortar inmediatamente (`fail-closed`). |
