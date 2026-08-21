---
title: "ADR-002: Estandarización de Canonical Directory Digest"
topic: "hardening-loop"
doc_type: decision
tags: [adr, nomenclatura, hashing, merkle]
sources:
  - "DOGFOODING-001 Audit Findings"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# ADR-002: Estandarización de Canonical Directory Digest

## Contexto
El reporte inicial de `DOGFOODING-001` referenciaba la función de cálculo de hash de directorios como un "Merkle Tree". Técnicamente, la función implementada recorre recursivamente los archivos del target, excluye cachés volátiles (`.pyc`, `__pycache__`), ordena las rutas en forma lexicográfica y calcula un SHA-256 agregado sobre el diccionario plano. No existe un grafo acíclico jerárquico de nodos intermedios.

## Decisión
1. Reemplazar la denominación "Merkle Tree" por **`Canonical Directory Digest`** en el código, los docstrings y la especificación formal.
2. Reservar el término `Merkle DAG` para futuras extensiones donde se requieran pruebas de inclusión de ramas parciales sin digest integral.

## Consecuencias
- **Positivas:** Precisión epistemológica en el paper y en el código.
- **Positivas:** Eliminación de ambigüedades teóricas.

---

## Relaciones

- [[matriz-invariantes|usa]] — 🧠 Verificado en Layer 1 (`test_canonical_directory_digest`).
