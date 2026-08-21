# Algorithmic Code Hardening Loop v0.3 — Implementation Plan

## Problem Statement
Los modelos de lenguaje generan código razonable pero fallan en detalles locales críticos: contratos implícitos, convenciones del repositorio, seguridad, integración y regresiones. El objetivo del proyecto no es agrandar el agente ni sumar abstracciones complejas ("Anti-Ferrari"), sino proveer una capa de endurecimiento algorítmica minimalista y verificable donde **el entorno acumula aprendizaje y la evidencia decide qué conocimiento sobrevive**.

## Principles
1. **Musk/Zechner 5-step loop**:
   - `QUESTION CONTEXT` → `DELETE HARNESS` → `SIMPLIFY INTERFACES` → `VERIFY FASTER` → `CODIFY VALIDATED LEARNING`.
2. **Evidence Layer**: Todo paso emite un Envelope inmutable con SHA-256 de entrada y salida.
3. **Knowledge Admission Gate**: Prohibición de escritura automática a wikis o bases canónicas (`Observation → Finding → Knowledge Candidate → Review → Accepted Knowledge → Executable Rule`).
4. **Anti-Slop / Anti-Ferrari**: Sin subagentes recursivos, sin MCP innecesarios, sin dependencias pesadas; Python nativo + `pytest`.

## Architecture & File Structure

```text
/Users/felipe_gonzalez/Developer/hardening-loop/
├── docs/
│   ├── spec_v0.1.md                   # Especificación operacional completa
│   └── plans/
│       └── 2026-08-20-hardening-loop-v0.1.md
├── schemas/
│   ├── work_unit.schema.json          # Schema JSON WorkUnit
│   ├── evidence_envelope.schema.json  # Schema JSON Evidence Envelope
│   └── knowledge_candidate.schema.json# Schema JSON Knowledge Candidate & Admission
├── src/
│   └── hardening_loop/
│       ├── __init__.py
│       ├── models.py                  # Modelos de datos (WorkUnit, Evidence, Candidate, States)
│       ├── states.py                  # Máquina de estados DRAFT -> CANONICAL / DEPRECATED
│       ├── admission.py               # Lógica del Knowledge Admission Gate
│       ├── phases/
│       │   ├── __init__.py
│       │   ├── base.py                # Clase base de fase y cálculo de hashes SHA-256
│       │   ├── question.py            # Genera requirements_audit.json
│       │   ├── delete.py              # Genera deletion_candidates.json, diff.patch, rollback_ref
│       │   ├── simplify.py            # Genera contract_diff.json
│       │   ├── verify.py              # Genera test_results.json, benchmark.json, runtime_evidence.json
│       │   └── codify.py              # Genera knowledge_candidate.yaml, admission_record.json
│       ├── runner.py                  # Orquestador del ciclo completo o por fase
│       └── cli.py                     # Entrypoint CLI `hardening-loop`
├── tests/
│   ├── __init__.py
│   ├── test_states.py                 # Validación de transiciones válidas e inválidas
│   ├── test_evidence.py               # Integridad de hashes y schemas
│   ├── test_admission.py              # Rechazo de auto-admisión y flujo de revisión
│   ├── test_phases.py                 # Tests unitarios por fase
│   └── test_qwen_loop_audit.py        # Test fixture de auditoría sobre qwen-tool-loop.py
├── pyproject.toml                     # Configuración de paquete y CLI console_scripts
└── Makefile                           # Comandos de test y ejecución
```

## State Model
```text
[DRAFT] → [AUDITING] → [PATCH_PROPOSED] → [VERIFIED] → [KNOWLEDGE_CANDIDATE]
                                                               ↓ (Aduana / Review)
                                                          [ADMITTED]
                                                               ↓ (Formalización)
                                                          [CANONICAL]
                                                               ↓ (Obsolescencia)
                                                         [DEPRECATED]
```

## Target Validation Case
Target: `/Users/felipe_gonzalez/Developer/examen_grado/scripts/qwen-tool-loop.py`
Expected findings producidos por el audit loop:
1. `bash` genérico sin whitelist real (`/bin/zsh -c cmd`).
2. `read` sin boundary check de workspace (posible directory traversal).
3. Status `PASS`/`FAIL` en prompt no verificado formalmente en output del modelo.
4. `cwd` hardcodeado a `/Users/felipe_gonzalez/Developer/examen_grado`.
5. Falta de structured evidence logging (solo prints a stderr).

## Verification Plan
1. `pytest` sobre todos los módulos (estados, envelopes, hashes, admission, phases).
2. Ejecución CLI de `hardening-loop run --target /Users/felipe_gonzalez/Developer/examen_grado/scripts/qwen-tool-loop.py --phase all --output evidence/run-001`.
3. Verificación de artefactos JSON/YAML generados en `evidence/run-001/` con sus respectivos envelopes y hashes SHA-256.
