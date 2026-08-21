# AGENTS.md — Constitución de Código Agéntico & Directrices de Operación

> **Versión Normativa:** v1.1 (Adaptación Operacional para `hardening-loop`)  
> **Ámbito:** Vinculante para todo agente de IA, subagente, runner automatizado o proceso de desarrollo en este repositorio.

---

> [!CRITICAL]
> **INVARIANTES INQUEBRANTABLES DE ORDEN CERO**
> 
> 1. **PROHIBICIÓN DE AUTO-ADMISIÓN (Leyes VIII y XII):** Ningún agente puede auto-aprobar o promover un `KnowledgeCandidate` al estado `ADMITTED` o `CANONICAL`. Toda admisión exige revisión humana explícita y firma en el [KnowledgeAdmissionGate](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/admission.py). La auto-admisión o bypass de la Aduana constituye una violación crítica de gobernanza.
> 2. **PRINCIPIO FAIL-CLOSED (Ley VIII):** Si un hash SHA-256 no coincide, un schema JSON falla, un test no pasa o surge una ambigüedad de seguridad, el sistema **ABORTA INMEDIATAMENTE** en modo seguro. Queda prohibido asumir éxito silencioso o continuar la ejecución con advertencias no resueltas.
> 3. **ANTI-SLOP / ANTI-FERRARI (Ley III):** Prohibido crear subagentes secundarios, MCPs, dependencias externas no autorizadas o capas de abstracción innecesarias antes de validar la necesidad con evidencia empírica y tests. La arquitectura premia la simplicidad y el minimalismo determinista.
> 4. **SEÑALES ANTES QUE RELATO (Ley XI):** Ninguna tarea se considera completa sin un [EvidenceEnvelope](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/models.py) inmutable indexado por SHA-256 de entrada y salida. Las explicaciones en lenguaje natural ("debería funcionar", "parece correcto") carecen de validez sin evidencia observable y reproducible.
> 5. **AISLAMIENTO Y NO CONTAMINACIÓN DE RUTAS (Leyes IV y VIII):** Toda mutación, auditoría y ejecución debe realizarse en un contexto aislado (worktree o rama transitoria) y confinada estrictamente a los límites del target (`target_path`). Prohibido mezclar paths locales del entorno de desarrollo o mutar directamente sobre `main`.

---

## 1. Preámbulo y Jerarquía Interpretativa

Esta constitución establece las reglas fundacionales para diseñar, auditar, modificar, validar e integrar código dentro de `hardening-loop`.

Su propósito es proteger:
- La **trazabilidad** y reproducibilidad de cada cambio.
- La **calidad** y determinismo frente a modelos probabilísticos.
- La **reversibilidad** total mediante snapshots y diffs limpios.
- La **coherencia arquitectónica** contra la sobreingeniería ornamental.
- La **seguridad agéntica** mediante fallos cerrados y mínima superficie de ataque.

### Definiciones Vinculantes
- **Mutación (Art. 1):** Toda acción que cree, modifique, elimine o reordene código, tests, esquemas, configuración o documentación.
- **Tarea (Art. 2):** Unidad de trabajo con objetivo explícito, alcance identificable y resultado esperado medible.
- **Validación (Art. 3):** Mecanismo reproducible usado para comprobar que una tarea cumplió su objetivo sin introducir regresiones.
- **Evidencia (Art. 4):** Resultado observable y trazable (tests, exit codes, hashes SHA-256, diffs, schema validations).
- **Fuente de Verdad (SSOT) (Art. 5):** Artefacto oficialmente reconocido como referencia primaria (esquemas en `schemas/`, modelos en `src/hardening_loop/models.py`).
- **Excepción (Art. 6):** Desviación explícita, delimitada y justificada aprobada por autoridad competente.
- **Riesgo (Art. 7):**
  - *Bajo:* Cambio local, acotado, sin impacto en contratos.
  - *Medio:* Cambio en interfaces de fase, CLI o interacción entre módulos.
  - *Alto:* Cambio en la máquina de estados, el gate de admisión, persistencia o seguridad.

---

## 2. Quick Reference & Verification Gates (Ley V)

Comandos deterministas de un solo paso. **"La herramienta sin ejecución no vale"** (Ley V, Art. 4).

```bash
# 1. Gate Unificado (Lint + Typecheck + Tests en 1 solo comando)
make check

# 2. Ejecutar suite completa de tests unitarios
.venv/bin/pytest -v --tb=short

# 3. Comandos individuales de calidad
make lint
make typecheck
make format

# 4. Ejecutar el ciclo completo de endurecimiento algorítmico sobre un target
python3 -m hardening_loop.cli run --target <path-to-target> --phase all --output evidence/run-001

# 4. Ejecutar fases individuales del runner
python3 -m hardening_loop.cli run --target <path-to-target> --phase question --output evidence/run-001
python3 -m hardening_loop.cli run --target <path-to-target> --phase delete --output evidence/run-001
python3 -m hardening_loop.cli run --target <path-to-target> --phase simplify --output evidence/run-001
python3 -m hardening_loop.cli run --target <path-to-target> --phase verify --output evidence/run-001
python3 -m hardening_loop.cli run --target <path-to-target> --phase codify --output evidence/run-001
```

---

## 3. Tratado de Gobernanza: Las 13 Leyes Constitucionales

### Ley I. Del Cambio Legítimo
- **Art. 1 (Intención Explícita):** Ninguna mutación puede iniciarse sin declarar intención, alcance y resultado esperado.
- **Art. 2 (Planificación Proporcional):** Todo cambio medio o alto exige plan previo documentado en `docs/plans/YYYY-MM-DD-<nombre>.md`.
- **Art. 3 (Validación Previa):** Antes de tocar código, debe quedar establecido cómo se verificará la solución (TDD Red-Green).
- **Art. 4 (Evidencia Obligatoria):** Ningún cambio se da por cerrado sin pruebas reproducibles ejecutadas.
- **Art. 6 (Coherencia Plan-Diff-Revisión):** La revisión final debe contrastar el plan original contra el diff real. Si durante la ejecución cambió el alcance, debe actualizarse el plan; no se toleran expansiones silenciosas de alcance.

### Ley II. De la Lectura Previa y No Duplicación
- **Art. 1 (Lectura Obligatoria):** Leer schemas JSON normativos, modelos de datos y tests existentes antes de escribir código.
- **Art. 2 (Prioridad de Reutilización):** Reutilizar y consolidar utilidades existentes (`sha256_text`, `sha256_dict`, `models.py`) antes de crear nuevas funciones.
- **Art. 4 (Prohibición de Duplicación):** Prohibido crear helpers paralelos que implementen hashing, serialización o validaciones ya provistas por el core.

### Ley III. De la Arquitectura Base y Regla de Scope
- **Art. 1 & 2 (Disciplina antes que moda):** Mantener arquitectura limpia, funcional y directa sin sobreingeniería ornamental (*Anti-Ferrari*).
- **Art. 5 (Simplicidad Estructural):** Elegir siempre la solución más simple que preserve calidad y testabilidad.
- **Art. 7 (Regla de Scope Obligatoria):**
  - **Inciso 7.1:** Si un artefacto, modelo o helper es utilizado por **2 o más fases o módulos**, debe ubicarse en `src/hardening_loop/` (core/shared).
  - **Inciso 7.2:** Si un artefacto es utilizado por **1 sola fase**, debe permanecer co-ubicado dentro de su módulo específico en `src/hardening_loop/phases/`.
  - **Inciso 7.3 (Dependencias Hacia Adentro):** Módulos de alto nivel consumen el core; el core jamás importa fases hijas.

### Ley IV. Del Control de Versiones, Aislamiento e Higiene
- **Art. 1 & 5 (Aislamiento y Protección de `main`):** Prohibido trabajar directo sobre `main`. Usar ramas transitorias o worktrees (`git worktree`).
- **Art. 4 (Commit Atómico por Tarea):** Commits convencionales (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`) que representen unidades atómicas de cambio.
- **Art. 7 (Orden e Higiene del Trabajo):** Prohibido cerrar tareas dejando archivos basura, logs temporales, dumps, caches o código comentado/muerto. El working tree debe quedar 100% limpio.
- **Regla Estricta de Autoría:** **NUNCA** añadir `Co-Authored-By AI`, créditos sintéticos o atribuciones de modelos a los commits.

### Ley V. De la Verificabilidad y Calidad Automatizada
- **Art. 1 & 2 (Testeabilidad y Calidad Mínima):** Todo código nuevo debe contar con tests unitarios correspondientes en `tests/`.
- **Art. 3 (Gates Mínimos):** Toda mutación debe superar: (1) Sintaxis Python 3.10+, (2) Validación de Schemas JSON, (3) Suite `pytest` en verde.
- **Art. 6 (Determinismo Primero):** Priorizar siempre validaciones deterministas (assertions, schemas, diffs de AST) por sobre verificaciones probabilísticas de LLMs.
- **Art. 7 (Deber de Simplificación):** La revisión de código debe activamente buscar y eliminar complejidad accidental y abstracciones innecesarias.

### Ley VI. De la Fuente de Verdad (SSOT) y Reconciliación
- **Art. 1 & 2 (SSOT Explícito):** Los esquemas en `schemas/` y los dataclasses en `src/hardening_loop/models.py` son la única fuente de verdad técnica.
- **Art. 3 & 4 (Prohibición de Contradicción y Reconciliación):** Prohibido el *documentation drift*. Todo cambio en contratos o CLI debe actualizar inmediatamente [docs/spec_v0.1.md](file:///Users/felipe_gonzalez/Developer/hardening-loop/docs/spec_v0.1.md) y [AGENTS.md](file:///Users/felipe_gonzalez/Developer/hardening-loop/AGENTS.md).
- **Art. 5 (Cierre Inválido):** Cerrar una tarea sin reconciliar código, tests y documentación constituye un cierre falso.

### Ley VII. De la Primacía del Sistema y Neutralidad de Modelo
- **Art. 1 (Neutralidad):** La arquitectura, tooling y contratos no deben acoplarse a vendors específicos ni a formatos propietarios de modelos cerrados.
- **Art. 2 (Independencia Operativa):** El sistema debe operar con cualquier modelo LLM o runner que respete las interfaces CLI y schemas JSON.

### Ley VIII. De la Seguridad Agéntica y Modo de Falla
- **Art. 1 (Fallo Cerrado):** Ante cualquier excepción, corrupción de datos o duda de seguridad, el sistema aborta de inmediato (`fail-closed`).
- **Art. 4 (Sanitización y Límites de Workspace):** Toda herramienta de ejecución de subprocesos o lectura de archivos debe validar que las rutas se encuentren dentro de los límites del workspace y sanitizar comandos para evitar inyecciones.
- **Art. 14 (Aprobación Humana Obligatoria):**
  - Exige intervención humana: (a) Admisión de conocimiento a canónico, (b) Mutaciones destructivas o eliminación de historial, (c) Modificación de políticas de seguridad o esquemas normativos.

### Ley IX. De la Persistencia y Manejo de Estado
- **Art. 1 & 3 (Persistencia Justificada y Modelo Explícito):** Estados inmutables respaldados por `WorkUnit` y `EvidenceEnvelope`.
- **Art. 6 (Serialización Determinista):** Los payloads JSON y YAML exportados deben generarse con claves ordenadas (`sort_keys=True` o canónicas) para garantizar invariabilidad de hashes SHA-256.

### Ley X. De los Contratos, Interfaces y Compatibilidad
- **Art. 1 & 2 (Contratos Explícitos):** Entradas, salidas, invariantes y códigos de error tipados en dataclasses y schemas JSON.
- **Art. 3 (Prohibición de Interfaces Implícitas):** Prohibido asumir que un componente "devolverá algo parecido". Toda comunicación entre fases es estrictamente estructurada.
- **Art. 5 & 6 (Compatibilidad y Deprecación):** Toda modificación en la firma de una fase o comando CLI debe garantizar compatibilidad hacia atrás o declarar deprecación explícita.

### Ley XI. De la Observabilidad, Auditoría y Evidencia Operativa
- **Art. 1 & 2 (Observabilidad y Evidencia Proporcional):** Toda fase genera un archivo de evidencia auditable en el directorio de salida (`evidence_id`, `input_hash`, `output_hash`, `verification`).
- **Art. 3 (Distinción Éxito Aparente vs Sano):** Que un proceso retorne exit code 0 no basta; la verificación debe validar el estado estructural y la ausencia de anomalías.
- **Art. 6 (Señales antes que Relato):** La evidencia empírica demostrable manda sobre cualquier explicación narrativa.

### Ley XII. Roles, Capacidades y Jurisdicción Operativa
- **Art. 1 & 3 (Separación de Capacidades):**
  - `reader`: Análisis y lectura de código (Low risk).
  - `editor`: Generación de parches y refactorización (Medium risk).
  - `reviewer`: Auditoría y verificación de contratos (Low risk).
  - `sensitive-operator`: Mutación de esquemas y estados (High risk).
  - `human-approver`: Aprobación en la Aduana y admisión canónica (Critical risk).
- **Art. 5 (Prohibición de Auto-Elevación):** Un agente no puede mutar su propio rol ni auto-aprobar sus propios hallazgos (*Separation of Duties*).

### Ley XIII. De la Primacía Conceptual en la Interacción
- **Art. 1 (Conceptos > Código):** Comprender los fundamentos y la arquitectura antes de escribir código. No aplicar parches sin entender la causa raíz.
- **Art. 2 (Diseño Determinista):** Priorizar soluciones elegantes, mínimas y deterministas por sobre complejidad algorítmica innecesaria.

---

## 4. Arquitectura del Hardening Loop (Musk/Zechner) & CLOOP

El ciclo de 5 fases implementa operativamente el workflow **CLOOP** (Clarify $\to$ Layout $\to$ Operate $\to$ Observe $\to$ Reflect $\to$ Reconcile $\to$ Handoff):

```text
       1. QUESTION                 2. DELETE                 3. SIMPLIFY                4. VERIFY                  5. CODIFY
  ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
  │  QuestionPhase    │ ───► │   DeletePhase     │ ───► │  SimplifyPhase    │ ───► │   VerifyPhase     │ ───► │   CodifyPhase     │
  └───────────────────┘      └───────────────────┘      └───────────────────┘      └───────────────────┘      └───────────────────┘
            │                          │                          │                          │                          │
            ▼                          ▼                          ▼                          ▼                          ▼
  requirements_audit.json    deletion_candidates.json   contract_diff.json         test_results.json          knowledge_candidate.yaml
                             diff.patch / rollback_ref                             benchmark.json             admission_record.json
```

### Contratos de Entrada, Salida y Verificación por Fase

| Fase | Entrada | Salida Obligatoria | Criterio de Verificación & Enforcement |
| :--- | :--- | :--- | :--- |
| **`question`** | Código target, especificaciones | `requirements_audit.json` | Clasificación de requerimientos en `explicit`, `inferred`, `historical`, `security_constraint`. Cuestiona supuestos no justificados. |
| **`delete`** | `requirements_audit.json`, target | `deletion_candidates.json`, `diff.patch`, `rollback_ref` | Detección y poda de código muerto, wrappers superfluos y herramientas no whitelisteadas. Genera rollback snapshot. |
| **`simplify`** | Código podado, diffs | `contract_diff.json` | Preservación estricta de firmas públicas e interfaces, reducción de complejidad ciclomática y simplificación estructural. |
| **`verify`** | Target / patch aplicado | `test_results.json`, `benchmark.json`, `runtime_evidence.json` | Ejecución de suite de tests, medición de tiempos de ciclo TDD y verificación de ausencia de regresiones. Status `PASS`. |
| **`codify`** | Hallazgos verificados y evidencias | `knowledge_candidate.yaml`, `admission_record.json` | Extracción de reglas formales vinculadas a `evidence_id`. Se genera en estado `PENDING_REVIEW` listo para la Aduana. |

---

## 5. Máquina de Estados y Gobernanza del Knowledge Admission Gate

```text
 [DRAFT] 
    │ (Inicio de auditoría y cálculo de target_hash inicial)
    ▼
 [AUDITING] 
    │ (Ejecución de fases question, delete y simplify)
    ▼
 [PATCH_PROPOSED] 
    │ (Suite de verificación y tests TDD en VerifyPhase)
    ▼
 [VERIFIED] 
    │ (Generación de KnowledgeCandidate en CodifyPhase)
    ▼
 [KNOWLEDGE_CANDIDATE] (Estado: PENDING_REVIEW)
    │
    ├──────────────────────────────────────────┐
    ▼ (Aprobación explícita en la Aduana)      ▼ (Rechazo fundamentado en la Aduana)
 [ADMITTED]                                [REJECTED / OBSOLETE]
    │
    │ (Formalización en test determinista / linter / fixture en CI)
    ▼
 [CANONICAL]
    │
    │ (Superado por nuevo aprendizaje empírico)
    ▼
 [DEPRECATED]
```

### Protocolo de la Aduana (Knowledge Admission Gate)
Queda terminantemente prohibido el flujo directo `Observación -> Regla Canónica`.

El flujo legítimo es:
1. **Observation:** Dato empírico observable en ejecución.
2. **Finding:** Problema clasificado por categoría y severidad (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
3. **KnowledgeCandidate:** Propuesta formal de regla estructurada con hash de evidencia referenciado.
4. **Review (Aduana):** Decisión humana explícita (`ACCEPTED`, `REJECTED`, `OBSOLETE`) con firma del revisor y notas en [admission.py](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/admission.py).
5. **Accepted Knowledge:** Registro inmutable admitido.
6. **Executable Rule:** Conversión en fixture de prueba (`tests/`), assert o guard estático en el repositorio.

---

## 6. Régimen de Excepciones

Toda desviación de las reglas de esta constitución debe cumplir los siguientes requisitos:
1. **Excepción Explícita (Art. 1):** Declarar qué regla específica no aplica y por qué.
2. **Justificación Mínima (Art. 2):** Detallar necesidad técnica real, análisis de riesgo y controles compensatorios aplicados.
3. **Alcance Acotado y Temporalidad (Art. 3 & 6):** Límite temporal estricto (máximo 30 días). Si una excepción se repite más de 3 veces, debe evaluarse una enmienda constitucional formal, no perpetuar la excepción.
4. **Autoridad de Aprobación (Art. 4):**
   - *Bajo riesgo:* Desarrollador responsable.
   - *Medio riesgo:* Tech Lead / Arquitecto.
   - *Alto riesgo / Seguridad:* Responsable del proyecto / Humano a cargo.

---

## 7. Convenciones de Código y Buenas Prácticas

- **Lenguaje & Tipado:** Python 3.10+ con tipado estricto (`typing`, `from __future__ import annotations`).
- **Modelado:** Dataclasses puras con serializadores explícitos `.to_dict()` en [models.py](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/models.py).
- **Hashing:** Uso de `sha256_text()` y `sha256_dict()` (JSON canónico ordenado con separadores compactos) para garantizar determinismo estricto.
- **Manejo de Errores:** Excepciones de dominio tipadas (`KnowledgeAdmissionError`, `SchemaValidationError`, etc.), fallo cerrado sin supresión silenciosa.
- **Git Hygiene:** Commits atómicos convencionales. Workspace 100% limpio antes de cada entrega. Cero atribución sintética AI.

---

## 8. Metodología de Desarrollo: Flujo "Ask to Cole" & Selección Viva con Context7

### A. Doctrina "Smallest Sufficient Skill" (Cole Pattern)
- **Herramienta Mínima:** Siempre preferir la herramienta o script determinista más magro sobre pipelines pesados o capas innecesarias (*Anti-Ferrari*).
- **Intake & PRP (Problem-Rules-Plan):** Antes de cualquier desarrollo medio o alto, definir el problema, reglas e invariantes aplicables y el plan acotado.
- **Single-Source of Truth (SSOT):** Escribir el plan en `docs/plans/YYYY-MM-DD-<nombre>.md`.
- **Aduana Visual con Plannotator:** Ejecutar `plannotator annotate <plan-path>` para permitir la revisión y aprobación explícita del humano antes de mutar código.
- **3-Tier Verification:**
  1. *Lógica de Código:* Red-Green TDD obligatorio en `tests/`.
  2. *Contratos y Esquemas:* Validación JSON Schema fail-closed (`validate_payload`).
  3. *Higiene y Documentación:* Lint estricto (`ruff`), typecheck (`mypy`) y reconciliación documental sin drift.

### B. Selección de Versiones y Consulta Viva con Context7
- **Prohibición de Suposiciones de Versión:** Toda adición o actualización de paquetes en `pyproject.toml` o uso de APIs externas debe verificarse previamente utilizando `context7` (`resolve-library-id` y `query-docs`).
- **Eliminación de Alucinaciones de API:** Verificar firmas de funciones, opciones de configuración y compatibilidad con Python 3.10+ en la documentación oficial indexada por Context7 antes de consolidar código.
