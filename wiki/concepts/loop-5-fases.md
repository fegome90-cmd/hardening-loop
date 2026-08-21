---
title: "El Ciclo de Endurecimiento en 5 Fases"
topic: "hardening-loop"
doc_type: concept
tags: [metodologia, arquitectura, musk-zechner, 5-fases]
sources:
  - "Algorithmic Code Hardening Loop v0.3"
  - "docs/spec_v0.1.md"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# El Ciclo de Endurecimiento en 5 Fases

El **Hardening Loop** implementa el algoritmo de 5 pasos de Musk/Zechner adaptado a la gobernanza y endurecimiento de código generado por modelos de lenguaje:

```text
1. QUESTION CONTEXT ──► 2. DELETE HARNESS ──► 3. SIMPLIFY INTERFACES ──► 4. VERIFY FASTER ──► 5. CODIFY LEARNING
```

## Las 5 Fases Operacionales

### 1. QUESTION CONTEXT
Cuestiona todo requerimiento antes de escribir código. Clasifica supuestos en:
- `explicit`: Requerimientos normativos declarados.
- `inferred`: Expectativas derivadas de prompts o contexto.
- `historical`: Rutas o variables hardcodeadas heredadas que deben eliminarse.
- `security_constraint`: Invariantes de seguridad indispensables.

### 2. DELETE HARNESS
Busca complejidad accidental, abstracciones sin evidencia y permisos excesivos (ej. invocación abierta de shell sin whitelist). Produce `deletion_candidates.json` y `diff.patch`.

### 3. SIMPLIFY INTERFACES
Reduce firmas internas complejas sin romper interfaces públicas externas ni contratos de tipos. Produce `contract_diff.json`.

### 4. VERIFY FASTER & CANONICAL DETERMINISM
Ejecuta la suite de verificación con un SLA de respuesta rápida (`< 100 ms`) y genera métricas herméticas.

### 5. CODIFY VALIDATED LEARNING
Empaqueta los hallazgos validados como `KnowledgeCandidate` listos para ser revisados en la Aduana.

---

## Relaciones

- [[determinismo-canonico|usa]] — 🧠 Genera sobres de evidencia deterministas en cada fase.
- [[aduana-conocimiento|trata]] — 💊 Los hallazgos de la fase 5 ingresan al Knowledge Admission Gate.
- [[anti-ferrari-anti-slop|asociado-a]] — ↔️ Filosofía de austeridad y eliminación de harnesses.
