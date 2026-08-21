# Plan: Creación de AGENTS.md bajo la Constitución Agéntica v1.1

## 1. Problem Statement
El repositorio `hardening-loop` implementa el Algorithmic Code Hardening Loop v0.3 (Musk/Zechner) pero carece de un archivo `AGENTS.md` normativo en la raíz. Los agentes que operan sobre este repositorio necesitan un marco de gobernanza explícito que ancle los principios de la **Constitución de Código Agéntico v1.1** (13 Leyes), técnicas de optimización de atención de LLMs (Agent Onboarding & Optimization), y los invariantes del Knowledge Admission Gate.

## 2. Invariantes y Leyes Aplicables

### A. Leyes Constitucionales Nucleares (constitucion-ai v1.1)
1. **Ley I (Cambio Legítimo):** Toda mutación exige intención explícita, plan proporcional y evidencia verificable.
2. **Ley II (Lectura Previa):** Lectura obligatoria de schemas y código antes de cualquier mutación. Cero duplicación.
3. **Ley III (Arquitectura Base & Scope Rule):** Respetar 2+ features = shared / 1 feature = local. Anti-Ferrari / Anti-Slop (sin sobreingeniería ni wrappers superfluos).
4. **Ley IV (Control de Versiones y Aislamiento):** Prohibido mutar directo en `main`. Commits convencionales atómicos sin atribuciones artificiales.
5. **Ley V (Verificabilidad Automatizada):** Suite de tests con `pytest` y validación de schemas JSON como gate mínimo obligatorio. "La herramienta sin ejecución no vale".
6. **Ley VI & X (Fuente de Verdad y Contratos):** Schemas JSON en `schemas/` y dataclasses en `models.py` como SSOT inmutable. Sin *documentation drift*.
7. **Ley VII (Neutralidad de Modelo):** Código agnóstico a vendors. No hardcodear referencias cerradas.
8. **Ley VIII (Seguridad Agéntica & Fail-Closed):** Principio de fallo cerrado. Aprobación humana obligatoria para admisión de conocimiento (`KnowledgeAdmissionGate`).
9. **Ley XI & XII (Evidencia Operativa y Jurisdicción):** "Señales antes que relato". Generación de `EvidenceEnvelope` indexado por SHA-256 en cada fase. Prohibida la auto-elevación o auto-aprobación del agente.

### B. Patrones de Optimización de AGENTS.md (Writing for Agents & Attention Anchoring)
- **Top-Level Warning Banner:** Invariantes innegociables al inicio para capturar atención en el primer cuarto del context window.
- **Formato Imperativo y Conciso:** Cero prosa innecesaria; instrucciones directas por rol y fase.
- **Cheatsheet de Comandos Deterministas:** Comandos exactos para test, lint y ejecución del runner.
- **Workflow Operativo:** 5 fases del Hardening Loop mapeadas con entradas, salidas y gates de validación.

## 3. Estructura Propuesta para `AGENTS.md`

```markdown
# AGENTS.md — Algorithmic Code Hardening Loop

> [!CRITICAL]
> **INVARIANTES INQUEBRANTABLES DE LA CONSTITUCIÓN AGÉNTICA (v1.1)**
> 1. NUNCA auto-admitir un Knowledge Candidate: La transición a ADMITTED exige revisión humana explícita en la Aduana (admission.py).
> 2. FAIL-CLOSED: Si un hash SHA-256 o schema validation falla, la fase se ABORTA inmediatamente.
> 3. ANTI-SLOP / ANTI-FERRARI: Prohibido crear subagentes, wrappers o abstracciones complejas sin test de evidencia previa.
> 4. SIGNALS > NARRATIVE: Ninguna afirmación es válida sin un EvidenceEnvelope inmutable verificable.

## 1. Quick Start & Comandos de Verificación
- make test / pytest
- hardening-loop run --target <file> --phase <phase> --output <dir>

## 2. Gobernanza Constitucional del Repositorio (13 Leyes)
- Mapeo de Leyes I a XIII adaptadas al runtime de hardening-loop.

## 3. Workflow de las 5 Fases (Musk/Zechner)
- Question -> Delete -> Simplify -> Verify -> Codify

## 4. Contratos de Datos y Schemas (SSOT)
- work_unit.schema.json, evidence_envelope.schema.json, knowledge_candidate.schema.json

## 5. Reglas de Código y Convenciones
- Python 3.10+, Tipado estricto, Dataclasses, Conventional Commits sin co-authoring AI.
```

## 4. Verification Plan
- Validar sintaxis Markdown.
- Comprobar que `AGENTS.md` cubra el 100% de los requisitos de gobernanza sin ambigüedades.
- Ejecutar `pytest` para asegurar que el repositorio continúe en estado verde.
