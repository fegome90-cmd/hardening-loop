# Plan: CLI Expansion — Subcomandos `inspect`, `validate` & Workspace Sandboxing

> **Fecha:** 2026-08-21
> **Metodología:** Ask-to-Cole (Problem-Rules-Plan + TDD Red-Green + 3-Tier Verification)
> **SSOT Plan:** `docs/plans/2026-08-21-cli-inspect-validate-sandboxing.md`

---

## 1. Problem-Rules-Plan (PRP)

### A. Problem Statement
1. **Auditoría e Integridad Criptográfica (`inspect`):** No existe un comando para que un agente o auditor independiente tome un directorio de evidencia (`evidence/<run-id>/`), recalcule todos los hashes SHA-256 de los artefactos canónicos y verifique que no haya habido alteración de datos (*Anti-Tampering / Hermeticity*).
2. **Validación Rápida de Esquemas (`validate`):** Los agentes no pueden validar esquemas JSON/YAML aislados (`evidence_envelope`, `knowledge_candidate`, `work_unit`) sin ejecutar todo el ciclo del runner.
3. **Sandboxing de Rutas y Límite de Workspace (Ley VIII - Fail-Closed):** El CLI debe asegurar que todas las operaciones de lectura y escritura (`--target`, `--output`) estén confinadas estrictamente dentro del límite de workspace permitido (`workspace_root` con `os.path.realpath`), bloqueando directory traversal (`../../etc/passwd`).

### B. Invariantes y Reglas Aplicables
- **Ley VIII (Fallo Cerrado y Sanitización):** Si una ruta escapa los límites del workspace o un hash criptográfico en `inspect` no coincide, el sistema aborta de inmediato con exit code `2` (`[FAIL-CLOSED]`).
- **Ley XI (Señales antes que Relato):** `inspect` emite un reporte auditable (`INTEGRITY_PASS` vs `TAMPER_DETECTED`) con los hashes calculados vs registrados.
- **Ley III (Simplicidad y Alcance):** Implementación directa en Python puro con `argparse` y utilidades del core (`sha256_dict`, `SchemaValidator`).

---

## 2. Nuevos Subcomandos del CLI

```text
hardening-loop
├── run       [--target <path>] [--phase <phase>] [--output <dir>] [--workspace-root <dir>] [--json] [-q]
├── review    <candidate_file> (--admit | --reject) --reviewer <id> [--notes <txt>] [--json] [-q]
├── inspect   <evidence_dir> [--workspace-root <dir>] [--json] [-q]   # [NUEVO]
└── validate  <file> [--schema <schema_name>] [--json] [-q]          # [NUEVO]
```

### 1. `hardening-loop inspect <evidence_dir>`
- Lee `evidence_manifest.json` y todos los archivos canónicos del directorio.
- Recalcula los digests SHA-256 de entrada y salida.
- Compara `canonical_manifest_digest` contra el hash recalculado.
- Retorna `0` si la integridad es hermética, `2` si hay discrepancia criptográfica o corrupción.

### 2. `hardening-loop validate <file> [--schema <name>]`
- Autodetecta o valida explícitamente contra `schemas/*.schema.json`.
- Retorna `0` si el archivo cumple la especificación formal, `2` si hay violación de schema.

### 3. Sandboxing de Workspace (`src/hardening_loop/sandbox.py`)
- Módulo shared con función `assert_within_workspace(path: str, workspace_root: str) -> str`.
- Aplica `os.path.realpath` y previene escapes fuera del proyecto.

---

## 3. Criterio de Verificación TDD

1. Tests en `tests/test_cli_inspect.py` y `tests/test_sandbox.py`.
2. Detección de alteración de archivos de evidencia (tampering test $\to$ exit code 2).
3. Detección de path traversal (`/etc/passwd` o `../../` $\to$ exit code 2).
4. `make check` (Ruff + Mypy + Pytest) 100% en verde.
