---
title: "Principios Anti-Ferrari y Anti-Slop"
topic: "hardening-loop"
doc_type: concept
tags: [filosofia, anti-ferrari, anti-slop, simplicidad]
sources:
  - "Algorithmic Code Hardening Loop v0.3"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# Principios Anti-Ferrari y Anti-Slop

El diseño del **Hardening Loop** rechaza explícitamente la tendencia contemporánea a inflar los sistemas con capas artificiales de complejidad (subagentes recursivos sin propósito, servidores MCP innecesarios, o frameworks de orquestación masivos).

## Las 5 Preguntas Anti-Slop

Antes de agregar cualquier nuevo componente, módulo o abstracción, el sistema exige responder:
1. **¿Es estrictamente necesario?**
2. **¿Puede eliminarse sin romper invariantes?**
3. **¿Puede resolverse con un archivo o esquema normativo?**
4. **¿Puede resolverse con un test automatizado?**
5. **¿Puede resolverse con una regla determinista simple?**

Si la respuesta a cualquiera de las preguntas 2 a 5 es **SÍ**, **queda terminantemente prohibido crear nueva infraestructura**.

## Anti-Ferrari en la Práctica

- **Sin dependencias infladas:** El runner opera con Python 3.10+ estándar, `pyyaml`, `jsonschema` y `pytest`.
- **Sin agentes charlando entre sí:** Un solo pipeline determinista de 5 fases.
- **Sin bases de datos complejas:** Todo el estado se persiste en artefactos JSON/YAML inmutables con hashes SHA-256 en el filesystem.

---

## Relaciones

- [[loop-5-fases|trata]] — 💊 Fase 2 (DELETE HARNESS) ejecuta este principio.
- [[determinismo-canonico|asociado-a]] — ↔️ Simplicidad en la capa de datos.
