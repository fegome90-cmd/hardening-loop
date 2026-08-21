---
title: "Matriz de Invariantes Ontológicos (3 Layers)"
topic: "hardening-loop"
doc_type: concept
tags: [testing, ontologia, invariantes, 3-layers]
sources:
  - "DOGFOODING-002: Evidence Hermeticity Hardening"
  - "tests/test_l1_implementation.py"
  - "tests/test_l2_contracts.py"
  - "tests/test_l3_epistemic.py"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# Matriz de Invariantes Ontológicos (3 Layers)

En el marco del Hardening Loop, la **cobertura de líneas de código** (actualmente 89%) es una métrica insuficiente por sí sola. La solidez del sistema se mide a través de su **Matriz de Invariantes Ontológicos**, dividida en 3 capas jerárquicas:

```text
Layer 3: Epistemic Invariants  (Determinismo, proveniencia, leyes de admisión)
   ▲
Layer 2: Contract Invariants   (Autómata de estados, schemas JSON fail-closed)
   ▲
Layer 1: Implementation Tests  (Parsers AST, serialización, CLI, unit tests)
```

## Estructura de las 3 Capas

| Capa | Archivo de Tests | Tipo de Aserción | Ejemplo de Invariante |
| :--- | :--- | :--- | :--- |
| **Layer 1: Implementation** | `tests/test_l1_implementation.py` | Funcionalidad unitaria y parsers | `test_canonical_directory_digest()` |
| **Layer 2: Contracts** | `tests/test_l2_contracts.py` | Restricciones de esquema y autómata | `test_state_machine_invalid_skips_fail_closed()` |
| **Layer 3: Epistemic** | `tests/test_l3_epistemic.py` | Leyes epistemológicas del sistema | `test_canonical_manifest_reproducibility()` |

---

## Invariantes Epistémicos Críticos

1. **Determinismo Criptográfico:** `sha256(canonical_manifest_A) == sha256(canonical_manifest_B)` bit-a-bit.
2. **Proveniencia Obligatoria:** Todo sobre debe vincularse a `execution_context_hash` (Git commit + lockfile).
3. **No-Canon sin Admisión:** Es imposible alcanzar el estado `CANONICAL` sin una aserción firmada en la Aduana.

---

## Relaciones

- [[determinismo-canonico|indica]] — 🔬 Valida la igualdad bit-a-bit del digest.
- [[aduana-conocimiento|usa]] — 🧠 Valida la imposibilidad de bypass de la aduana.
