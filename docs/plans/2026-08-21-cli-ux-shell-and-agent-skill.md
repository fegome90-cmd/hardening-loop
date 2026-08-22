# Plan: CLI UX Enhancement, Shell Completions & Agent Skill (Ask-to-Cole Flow)

> **Fecha:** 2026-08-21
> **Metodología:** Ask-to-Cole (Smallest Sufficient Skill + 3-Tier Verification)
> **SSOT Plan:** `docs/plans/2026-08-21-cli-ux-shell-and-agent-skill.md`

---

## 1. Problem-Rules-Plan (PRP)

### A. Problem Statement
1. **Exit Codes Deterministas:** `src/hardening_loop/cli.py` retorna `0` incluso cuando alguna fase de verificación falla (`VerificationStatus.FAIL`) o se produce una violación de schema JSON, imposibilitando el fallo cerrado en scripts de agentes y CI.
2. **Salida para Máquinas y Subagentes:** `cli.py` carece de los flags `--json` (emisión de manifest estructurado a stdout) y `--quiet` / `-q` (supresión de banners para minimizar consumo de tokens).
3. **Ergonomía de Shell:** No existen autocompletados nativos para `fish` (`completions/hardening-loop.fish`) ni `bash` (`completions/hardening-loop.bash`).
4. **Skill para Agentes de IA:** No existe una skill liviana (~150 tokens) de descubrimiento progresivo en `.agents/skills/hardening-loop/SKILL.md` bajo el estándar de Mario Zechner.

### B. Invariantes y Reglas Aplicables
- **Ley VIII (Fail-Closed):** Exit code `0` = PASS, `1` = FAIL/WARN/BLOCKED, `2` = SchemaValidationError, `130` = SIGINT.
- **Ley XI (Señales antes que Relato):** `--json` emite el JSON ordenado y determinista del `EvidenceEnvelope` o `evidence_manifest.json`.
- **Cole Pattern (Smallest Sufficient Skill):** Implementación sin dependencias externas pesadas adicionales (usando `argparse` estándar y scripts de shell nativos).
- **3-Tier Verification:**
  - *Tier 1 (Lógica):* Tests unitarios en `tests/test_l1_implementation.py` y `tests/test_cli_ux.py`.
  - *Tier 2 (Esquemas):* Validación fail-closed de los payloads emitidos con `--json`.
  - *Tier 3 (Higiene):* `make check` (Ruff + Mypy + Pytest) 100% en verde.

---

## 2. Tareas de Implementación

### Tarea 1: Tests TDD para el CLI UX (`tests/test_cli_ux.py`)
- Test de `--json` emitiendo JSON parseable válido.
- Test de `--quiet` suprimiendo cabeceras.
- Test de exit codes: `0` para éxito, `1` para falla de verificación, `2` para violación de schema.

### Tarea 2: Refactorización de `src/hardening_loop/cli.py`
- Añadir flags `--json` y `--quiet` / `-q` a los subparsers `run` y `review`.
- Manejo de códigos de retorno según el estado de los envelopes y captura de `SchemaValidationError`.
- Manejo limpio de excepciones y redirección de errores a `stderr`.

### Tarea 3: Generación de Autocompletados de Shell
- `completions/hardening-loop.fish` para Fish shell.
- `completions/hardening-loop.bash` para Bash shell.

### Tarea 4: Creación de la Skill Ligera para Agentes
- `.agents/skills/hardening-loop/SKILL.md` (<150 tokens) para integración con Antigravity, Claude Code, Pi y Qwen.

---

## 3. Criterio de Verificación

1. `tests/test_cli_ux.py` pasando al 100%.
2. `make check` ejecutado sin errores (25+ archivos limpios, 35+ tests en verde).
3. Prueba manual de ejecución de CLI con `--json | jq .` y `--quiet`.
