# Plan: Corrección Integral de Verify, Findings AST, Fail-Closed y Portabilidad

> **Fecha:** 2026-08-21
> **Metodología:** Ask-to-Cole (PRP + TDD Red-Green + 3-Tier Verification)
> **SSOT Plan:** `docs/plans/2026-08-21-fix-verify-findings-and-portability.md`

---

## 1. Problem-Rules-Plan (PRP)

### A. Diagnóstico de Problemas
1. **[Bug 1] Verify checks framework invariants en targets externos:**
   `VerifyPhase` busca strings como `KnowledgeAdmissionGate`, `HardeningState` en el target auditado, fallando siempre en código externo.
2. **[Bug 2] Verify retorna PASS con safety checks fallidos (Viola Ley VIII):**
   `overall_status` solo evalúa `ast_pass` ignorando fallos críticos en `safety_checks`.
3. **[Enhancement 3] Findings de Question, Delete y Simplify son plantillas sin atribución:**
   Hardcoding de nombres de funciones inventadas (`execute_function`, `file_reader`), `DEL-004` exigiendo `EvidenceEnvelope` en código no-framework, y `SimplifyPhase` afirmando que cualquier `run()` devuelve `EvidenceEnvelope`.
4. **[Bug 4] `created_at: 1970-01-01` en KnowledgeCandidates y enlaces absolutos:**
   Epoch hardcodeado en `models.py` y `admission.py`, symlink `wiki` roto en Linux, y enlaces markdown con rutas locales `file:///Users/...`.

---

## 2. Plan de Acción y Cambios por Componente

### A. `src/hardening_loop/phases/verify.py`
- Reemplazar checks hardcodeados del framework por **Safety Checks Reales del Target**:
  - `eval_exec_safety`: Detección AST de llamadas a `eval()` o `exec()`.
  - `unconstrained_shell_safety`: Detección AST de `shell=True` o comandos no sanitizados.
  - `hardcoded_env_paths`: Detección de paths absolutos locales (`/Users/`, `/home/`).
- **Enforcement Fail-Closed (Ley VIII):**
  - Si `ast_errors > 0` o cualquier check con `severity in ("CRITICAL", "HIGH")` falla $\to$ `overall_status = VerificationStatus.FAIL`.
  - Si solo hay warnings $\to$ `overall_status = VerificationStatus.WARN`.

### B. `src/hardening_loop/phases/question.py`, `delete.py`, `simplify.py`
- **Atribución Estricta `file:lineno` mediante AST:**
  - Visitar nodos con `ast.walk` / `ast.NodeVisitor` para capturar `filename:lineno` exacto.
  - Atribuir el finding al nombre real de la función (`def func_name`) o scope de clase/módulo.
  - Eliminar plantillas de código ajeno (eliminar `DEL-004` que exige `EvidenceEnvelope` a targets externos).
  - En `SimplifyPhase`, deducir el tipo de retorno real inspeccionando nodos `ast.Return` o anotaciones de tipo (`-> CompletedProcess`, `-> int`, etc.).

### C. `src/hardening_loop/models.py` y `src/hardening_loop/admission.py`
- Cambiar `created_at: str = "1970-01-01T00:00:00+00:00"` por `field(default_factory=utc_now_iso)`.
- En `admission.py`, usar `utc_now_iso()` si no viene `created_at`.

### D. Portabilidad e Higiene (Git & Docs)
- Eliminar o ignorar en `.gitignore` el symlink `wiki`.
- Convertir enlaces markdown absolutos (`file:///Users/felipe_gonzalez/...`) a rutas relativas (`./AGENTS.md`, `./src/...`).

---

## 3. Criterio de Verificación (3-Tier Verification)

1. **Tier 1 (TDD Tests):**
   - Test de verificación en target externo (debe evaluar el target real, no el framework).
   - Test de fail-closed: check crítico fallido $\to$ `VerificationStatus.FAIL`.
   - Test de atribución `file:lineno` exacta en deletion candidates y findings.
   - Test de timestamp `created_at` real en `KnowledgeCandidate`.
2. **Tier 2 (Esquemas):** Validación de todos los envelopes contra `schemas/`.
3. **Tier 3 (Calidad):** `make check` (Ruff + Mypy + Pytest) 100% en verde.
