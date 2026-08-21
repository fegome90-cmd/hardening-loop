---
title: "RULE-GATE-001: Aserción Obligatoria de Revisor en la Aduana"
topic: "hardening-loop"
doc_type: rule
tags: [regla-canonica, aduana, revision-humana, gobernanza]
sources:
  - "DOGFOODING-002 Admission Record"
  - "src/hardening_loop/admission.py"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# RULE-GATE-001: Aserción Obligatoria de Revisor en la Aduana

## Definición Normativa

| Atributo | Valor |
| :--- | :--- |
| **Rule ID** | `RULE-GATE-001` |
| **Categoría** | `SECURITY` |
| **Severidad** | `CRITICAL` |
| **Mecanismo** | `CONTRACT_VALIDATOR` |
| **Estado de Aduana** | `ACCEPTED` (Aprobado por Revisor Humano) |

## Enunciado de la Regla

El componente `KnowledgeAdmissionGate` debe rechazar de forma estricta (`fail-closed`) cualquier intento de transición hacia `ADMITTED` o `CANONICAL` que no cuente con una aserción de revisor humano declarada no vacía (`reviewer.strip() != ""`).

## Código de Validación Canónico

```python
if not reviewer or not reviewer.strip():
    raise KnowledgeAdmissionError(
        "Reviewer identity assertion is mandatory for knowledge admission."
    )
```

## Racional
Evita que agentes autónomos o scripts de CI promuevan observaciones o hallazgos no verificados a reglas canónicas del repositorio sin supervisión humana.

---

## Relaciones

- [[aduana-conocimiento|trata]] — 💊 Concepto que fundamenta esta regla.
- [[adr-003-human-reviewer-assertion|usa]] — 🧠 ADR que originó la regla.
