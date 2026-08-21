---
title: "ADR-003: Requisito de Aserción de Revisor Humano Declarada"
topic: "hardening-loop"
doc_type: decision
tags: [adr, gobernanza, aduana, asercion-humana]
sources:
  - "DOGFOODING-001 Audit Findings"
  - "src/hardening_loop/admission.py"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# ADR-003: Requisito de Aserción de Revisor Humano Declarada

## Contexto
En `v0.1-alpha`, se contemplaba una validación de `reviewer != ""` en la Aduana. El reporte inicial utilizaba la frase "autenticación humana", lo que sugería erróneamente la existencia de una verificación de identidad criptográfica asimétrica (firmas GPG/SSH/WebAuthn).

## Decisión
1. Definir formalmente el mecanismo como **`Human Reviewer Assertion`** (Aserción de Revisor Humano Declarada).
2. Hacer obligatoria la comprobación `reviewer.strip() != ""` en `KnowledgeAdmissionGate.review_candidate` en modo fail-closed.
3. Declarar en la especificación que la garantía actual es la presencia de una identidad humana declarada con responsabilidad explícita, posponiendo firmas criptográficas PKI para versiones posteriores.

## Consecuencias
- **Positivas:** Transparencia epistemológica sobre las capacidades del sistema de gobernanza.
- **Positivas:** Bloqueo efectivo de promociones huérfanas o auto-promociones autónomas.

---

## Relaciones

- [[aduana-conocimiento|trata]] — 💊 Concepto que fundamenta este ADR.
- [[rule-gate-001|indica]] — 🔬 Regla normativa que ejecuta esta decisión.
