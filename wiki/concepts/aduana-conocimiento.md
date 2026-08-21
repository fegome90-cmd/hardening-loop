---
title: "Knowledge Admission Gate (La Aduana de Conocimiento)"
topic: "hardening-loop"
doc_type: concept
tags: [gobernanza, aduana, knowledge-gate, revision-humana]
sources:
  - "Algorithmic Code Hardening Loop v0.3"
  - "src/hardening_loop/admission.py"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# Knowledge Admission Gate (La Aduana de Conocimiento)

El **Knowledge Admission Gate** es la barrera ontológica de control que previene la degradación y alucinación de la base de conocimiento del repositorio.

## Prohibición Absoluta de "Auto-Wiki"

Queda terminantemente prohibido el flujo:
$$\text{Observación del LLM} \xrightarrow{\text{Automático}} \text{Regla Canónica / Wiki}$$

## El Flujo Formal de Admisión

```text
Observation (Dato empírico)
   ↓
Finding (Problema clasificado con severidad y líneas)
   ↓
Knowledge Candidate (Propuesta formal con evidence_references - PENDING_REVIEW)
   ↓
Aduana de Revisión (hardening-loop review --admit --reviewer "nombre")
   ↓
Accepted Knowledge (Conocimiento formalizado con firma de revisor declarada)
   ↓
Executable Rule (Linter / Test Fixture en CI)
```

## Aserción de Revisor Humano Declarada (`RULE-GATE-001`)

Todo candidato admitido exige obligatoriamente un parámetro `reviewer` no vacío:
- `reviewer.strip() != ""`
- Registra fecha ISO de revisión y notas justificativas.
- No es una autenticación criptográfica de identidad, sino una **aserción de responsabilidad declarada**.

---

## Relaciones

- [[rule-gate-001|trata]] — 💊 Regla canónica que implementa la aduana.
- [[adr-003-human-reviewer-assertion|asociado-a]] — ↔️ Decisión arquitectónica sobre aserción de revisor.
- [[matriz-invariantes|usa]] — 🧠 Verificado en Layer 3 (Epistemic Invariants).
