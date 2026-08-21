# Plan: Telemetría, Benchmarking y Observabilidad de Alto Rendimiento (Ley XI)

> **Fecha:** 2026-08-21  
> **Metodología:** Ask-to-Cole (Problem-Rules-Plan + TDD Red-Green + 3-Tier Verification)  
> **SSOT Plan:** `docs/plans/2026-08-21-telemetry-and-metrics-observability.md`

---

## 1. Problem-Rules-Plan (PRP)

### A. Problem Statement
Para que `hardening-loop` opere a nivel industrial en pipelines agénticos y CI/CD, se requiere instrumentación y telemetría de precisión sobre todo lo que hace el ciclo:
1. **Medición de Tiempos de Ciclo por Fase:** Duración exacta con `time.perf_counter()` de cada una de las 5 fases (`question`, `delete`, `simplify`, `verify`, `codify`).
2. **Métricas de Rendimiento y Throughput:** Líneas de código procesadas por segundo (LOC/s), conteo de nodos AST visitados y memoria RSS consumida.
3. **Observabilidad Agregada en Manifiesto:** Bloque `runtime_telemetry` en `evidence_manifest.json` que consolide latencias, throughput y estado de checks.
4. **Comando de Inspección de Telemetría (`hardening-loop telemetry <dir>`):** Visualización tabular de métricas para humanos y formato JSON para agentes y dashboards (PostHog/CI).

### B. Invariantes Constitucionales (Ley XI & Ley III)
- **Separación Canónica vs Telemetría (Ley XI, Art. 1):** La telemetría en `RuntimeReceipt` es observable y no altera el hash canónico (`CanonicalEvidence`), manteniendo la reproducibilidad hermética.
- **Minimalismo y Cero Dependencias Pesadas (Ley III - Anti-Ferrari):** Uso de `time.perf_counter()` y `resource.getrusage()` de la biblioteca estándar de Python sin sobrecargar con frameworks pesados.
- **Validación Fail-Closed (Ley VIII):** Schemas JSON actualizados para admitir métricas opcionales estructuradas sin romper retrocompatibilidad.

---

## 2. Componentes a Implementar

### A. Módulo `src/hardening_loop/telemetry.py`
- `PhaseMetrics`: Dataclass para métricas individuales (`duration_ms`, `loc_count`, `ast_nodes_count`, `memory_rss_mb`).
- `TelemetryCollector`: Orquestador que mide inicio/fin de cada fase, calcula deltas de memoria y agrega throughput.
- Formateador de reporte visual y serialización JSON.

### B. Integración en `HardeningRunner` y Fases
- `HardeningRunner.run_all()` y `run_phase()` instrumentados con `TelemetryCollector`.
- Enriquecimiento del bloque `runtime_telemetry` en `evidence_manifest.json`.

### C. Subcomando `hardening-loop telemetry <evidence_dir>`
- Lee `evidence_manifest.json` y emite tabla de rendimiento o JSON.

---

## 3. Criterio de Verificación TDD (3-Tier Verification)

1. **Tier 1 (Lógica TDD):** Tests en `tests/test_telemetry.py` verificando precisión de tiempos, conteo de LOC/s y memoria.
2. **Tier 2 (Esquemas):** Validación de envelopes con métricas contra `evidence_envelope.schema.json`.
3. **Tier 3 (Calidad):** `make check` (Ruff + Mypy + Pytest) 100% en verde.
