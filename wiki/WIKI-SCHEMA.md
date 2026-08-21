# Algorithmic Code Hardening Loop — Wiki Schema

## Propósito

Esta wiki documenta el marco de ingeniería, la ontología y las reglas canónicas del **Algorithmic Code Hardening Loop** (capa determinista de endurecimiento de código generado por LLM basada en evidencia criptográfica, gobernanza por aduana y auto-auditoría recursiva).

---

## Archivos y Directorios Obligatorios

* `WIKI-SCHEMA.md` — Contrato editorial, tipado de referencias y reglas de integridad.
* `METHODOLOGY.md` — Flujo de ingestión, actualización y escala de madurez.
* `index.md` — Catálogo maestro de páginas con estado de validación.
* `log.md` — Registro cronológico de actividad y adiciones.
* `concepts/` — Conceptos fundamentales del método (5 fases, determinismo, aduana, invariantes).
* `decisions/` — Architectural Decision Records (ADRs) de diseño ontológico y técnico.
* `rules/` — Reglas ejecutables admitidas formalmente tras pasar la Aduana.
* `references/` — Fundamentos teóricos, papers y fuentes de autoridad externas.
* `diagrams/` — Diagramas y modelos visuales de estados y flujos de evidencia.

---

## Frontmatter Canónico (YAML)

Toda página de la wiki debe comenzar obligatoriamente con el siguiente bloque YAML:

```yaml
---
title: "Título de la Página"
topic: "hardening-loop"
doc_type: concept | decision | rule | reference | diagram
tags: [tag1, tag2]
sources:
  - "Ruta, commit o paper de referencia"
created: 2026-08-21
updated: 2026-08-21
status: active # draft | active | archived | needs-review
review_state: validated # draft | reviewed | validated
owner: Felipe
ai_generated: none # none | partial | full
caveats: false
---
```

---

## Cross-Reference Typing (Patrón Karpathy)

Para navegación y construcción de grafos semánticos:
* `[[pagina|trata]]` — 💊 Solución, regla o herramienta concreta.
* `[[pagina|usa]]` — 🧠 Concepto técnico o mecanismo criptográfico utilizado.
* `[[pagina|indica]]` — 🔬 Invariante, métrica o criterio de diseño.
* `[[pagina|asociado-a]]` — ↔️ Relación temática conceptual (default).
* `[[pagina|ver-tambien]]` — 📖 Lectura recomendada complementaria.

---

## Principios Editoriales
1. **Atomicidad Karpathy:** Páginas concisas de 30-90 líneas, focalizadas en un único concepto o regla.
2. **Sin Prosa Inflada:** Cero humo, definiciones directas, tablas estructuradas y ejemplos de código reales.
3. **Cero Auto-Wiki:** Ninguna página canónica se crea por alucinación autónoma de un LLM; todo conocimiento debe nacer de un `KnowledgeCandidate` con evidencia criptográfica (`evidence_id`) aprobado en la Aduana.
