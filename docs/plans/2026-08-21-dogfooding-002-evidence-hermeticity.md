# DOGFOODING-002: Evidence Hermeticity Hardening & Epistemic Separation

## 1. Problem Statement & Audit Findings
La auditoría de **DOGFOODING-001** reveló precisiones críticas necesarias antes de considerar la especificación como canónica:
1. **Sobreafirmación de Hermeticidad:** `EvidenceEnvelope` mezclaba campos deterministas (`output_hash`, `input_hash`) con telemetría no determinista (`timestamp`, `duration_ms`), provocando que el hash integral del manifiesto (`evidence_manifest.json`) variara entre corridas.
2. **Ambivalencia en el Host Fingerprint:** `environment_hash` reflejaba solo la plataforma base sin capturar el commit de git, la versión del schema ni el lockfile de dependencias (`uv.lock`).
3. **Imprecisión de Nomenclatura:** Se denominó "Merkle Tree" a un `Canonical Directory Digest` (hash plano ordenado de archivos).
4. **Distinción de Identidad:** `RULE-GATE-001` garantiza una *Aserción de Revisor Humano* (Human Reviewer Assertion), no una *Autenticación Criptográfica de Identidad*.
5. **Estratificación de Tests:** La suite requiere separación explícita en 3 capas (Implementación, Invariantes de Contrato e Invariantes Epistémicos).

---

## 2. Cambios Arquitectónicos Propuestos

### 2.1. Separación Estricta: Canonical Evidence vs Runtime Receipt
Reestructurar `EvidenceEnvelope` en dos bloques aislados:

```json
{
  "canonical_evidence": {
    "evidence_id": "evi-...",
    "phase": "verify",
    "input_hash": "...",
    "output_hash": "...",
    "method_version": "v0.3",
    "schema_version": "v0.1-beta",
    "execution_context_hash": "...",
    "artifact_payload": { ... }
  },
  "runtime_receipt": {
    "timestamp": "2026-08-21T...",
    "duration_ms": 1.45,
    "checks": [ "..." ],
    "status": "PASS"
  }
}
```

* **Invariante Criptográfico:** `canonical_evidence_hash = sha256_dict(canonical_evidence)`.
* El `evidence_manifest.json` computará `canonical_manifest_digest = sha256_dict([e.canonical_evidence for e in envelopes])`, logrando determinismo 100% reproducible bit-a-bit entre ejecuciones independientes sobre el mismo árbol y commit.

### 2.2. Contexto de Ejecución Ampliado (`execution_context_hash`)
Computar el digest del contexto incorporando:
- `git_commit_hash`: Hash del commit HEAD o `uncommitted-dirty`.
- `dependency_lock_hash`: SHA-256 de `uv.lock` / `pyproject.toml`.
- `schema_version`: `"v0.1-beta"`.
- `python_version` y `platform_system`.

### 2.3. Estratificación de la Suite de Pruebas (3 Layers)
1. **Layer 1 — Implementation Tests (`tests/test_l1_implementation.py`):**
   - Hashing básico, serialización YAML/JSON, argumentos de CLI.
2. **Layer 2 — Contract Invariants (`tests/test_l2_contracts.py`):**
   - Transiciones de la máquina de estados, validación fail-closed de schemas, rechazo de campos espurios.
3. **Layer 3 — Epistemic Invariants (`tests/test_l3_epistemic.py`):**
   - `test_canonical_manifest_reproducibility`: `sha256(canonical_manifest_A) == sha256(canonical_manifest_B)`.
   - `test_no_evidence_without_context_provenance`: Falla cerrada si falta `execution_context_hash` o `schema_version`.
   - `test_no_canonical_without_admission`: Imposibilidad de alcanzar `CANONICAL` sin registro de aduana firmado.

---

## 3. Plan de Verificación
1. `pytest tests/ -v`: Ejecución de las 3 capas pasando al 100%.
2. Ejecución de `hardening-loop run` sobre `src/hardening_loop` en `evidence/self-audit-003` y `evidence/self-audit-004`.
3. Aserción formal de igualdad: `canonical_manifest_digest` de Run-A == Run-B.
4. Actualización de `schemas/evidence_envelope.schema.json` y `docs/spec_v0.1.md`.
