# METHODOLOGY.md — Flujo de Mantenimiento de la Wiki

## 1. Principios de Operación
* **El Entorno Acumula Aprendizaje:** La wiki es la memoria persistente formalizada del repositorio.
* **Separación de Autoridad vs Evidencia:** Un hallazgo empírico no es una regla canónica hasta que se somete a revisión y se registra en `wiki/rules/`.
* **Caché Documental sin Build Step:** Formato Markdown plano compatible con Obsidian, Foam, Logseq y lectores de terminal.

---

## 2. Flujo de Ingestión de Conocimiento

```text
1. Ejecución de Hardening Loop
   ↓ (requirements, deletions, verify)
2. Fase CODIFY
   ↓ (knowledge_candidate.yaml con evidence_id)
3. Knowledge Admission Gate
   ↓ (hardening-loop review --admit --reviewer "name")
4. Creación / Actualización en wiki/rules/ o wiki/concepts/
   ↓
5. Actualización de wiki/index.md y wiki/log.md
```

---

## 3. Escala de Madurez de Páginas

| Nivel de Madurez | Descripción | Criterio de Promoción |
| :--- | :--- | :--- |
| **`stub`** | Estructura inicial con preguntas o placeholders. | Se identificó el concepto pero falta evidencia completa. |
| **`inicial`** | Contenido base redactado y frontmatter válido. | Cuenta con referencias mínimas y definición conceptual. |
| **`útil`** | Documentación práctica con ejemplos y relaciones. | Aplicable directamente por ingenieros o agentes. |
| **`robusta`** | Validada contra tests de invariantes o casos reales. | Evidencia determinista vinculada en `sources`. |
| **`validada`** | Aprobada explícitamente en Aduana como regla canónica. | Estado `review_state: validated` con firma en `log.md`. |
