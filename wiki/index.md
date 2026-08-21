# ÍNDICE — Hardening Loop Wiki

Catálogo maestro de páginas vigentes de la wiki de **Algorithmic Code Hardening Loop**.

---

## 1. Documentos de Infraestructura y Gobernanza

| Página | Tipo | Descripción | Estado |
| :--- | :--- | :--- | :---: |
| [`WIKI-SCHEMA.md`](WIKI-SCHEMA.md) | Contrato | Contrato editorial, frontmatter YAML y reglas de integridad. | 🟢 Validada |
| [`METHODOLOGY.md`](METHODOLOGY.md) | Workflow | Flujo de ingestión por Aduana y escala de madurez. | 🟢 Validada |
| [`log.md`](log.md) | Registro | Historial cronológico de cambios y promociones. | 🟢 Activa |

---

## 2. Conceptos Fundamentales (`concepts/`)

| Página | Tipo | Descripción | Estado |
| :--- | :--- | :--- | :---: |
| [`concepts/loop-5-fases.md`](concepts/loop-5-fases.md) | Concepto | El algoritmo de 5 fases (Question, Delete, Simplify, Verify, Codify). | 🟢 Validada |
| [`concepts/determinismo-canonico.md`](concepts/determinismo-canonico.md) | Concepto | Desacoplamiento de Canonical Evidence vs Runtime Receipt. | 🟢 Validada |
| [`concepts/aduana-conocimiento.md`](concepts/aduana-conocimiento.md) | Concepto | Knowledge Admission Gate y Aserción de Revisor Humano. | 🟢 Validada |
| [`concepts/matriz-invariantes.md`](concepts/matriz-invariantes.md) | Concepto | Estratificación de la suite de pruebas en 3 capas ontológicas. | 🟢 Validada |
| [`concepts/anti-ferrari-anti-slop.md`](concepts/anti-ferrari-anti-slop.md) | Concepto | Las 5 preguntas de austeridad y diseño minimalista. | 🟢 Validada |

---

## 3. Decisiones Arquitectónicas (`decisions/`)

| Página | Tipo | Descripción | Estado |
| :--- | :--- | :--- | :---: |
| [`decisions/adr-001-separacion-canonica-telemetria.md`](decisions/adr-001-separacion-canonica-telemetria.md) | ADR | Desacoplamiento de evidencia determinista y telemetría de reloj. | 🟢 Validada |
| [`decisions/adr-002-canonical-directory-digest.md`](decisions/adr-002-canonical-directory-digest.md) | ADR | Estandarización de Canonical Directory Digest vs Merkle Tree. | 🟢 Validada |
| [`decisions/adr-003-human-reviewer-assertion.md`](decisions/adr-003-human-reviewer-assertion.md) | ADR | Requisito de Aserción de Revisor Humano Declarada en Aduana. | 🟢 Validada |

---

## 4. Reglas Canónicas Admitidas (`rules/`)

| Página | Tipo | Descripción | Estado |
| :--- | :--- | :--- | :---: |
| [`rules/rule-evidence-001.md`](rules/rule-evidence-001.md) | Regla | Inclusión obligatoria de bloque canónico y execution_context_hash. | 🟢 Validada |
| [`rules/rule-gate-001.md`](rules/rule-gate-001.md) | Regla | Aserción obligatoria de revisor humano en fail-closed mode. | 🟢 Validada |

---

## 5. Referencias y Diagramas (`references/`, `diagrams/`)

| Página | Tipo | Descripción | Estado |
| :--- | :--- | :--- | :---: |
| [`references/zechner-musk-principios.md`](references/zechner-musk-principios.md) | Referencia | Bases teóricas de Zechner y Musk aplicadas a software. | 🟢 Validada |
| [`diagrams/ciclo-estados-y-envelopes.md`](diagrams/ciclo-estados-y-envelopes.md) | Diagrama | Modelos Mermaid del autómata de estados y clases de sobres. | 🟢 Validada |
