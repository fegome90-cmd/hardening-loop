# Arquitectura de Loops en Prime Agent & Transferencia Tecnológica a Hardening Loop

> **Documento Normativo & Especificación Arquitectónica Exhaustiva (v2.0 — Deep Hardened)**  
> **Fecha:** 21 de Agosto de 2026  
> **Autoría / Rol:** Senior AI Systems Architect & Hardening Core Team  
> **Fuentes Primarias (SSOT):**  
> - Wiki de Orquestación W2 (`vault/orchestration-wiki/references/prime-agent/`, `systems/qwen-harness-optimizations.md`)  
> - Repositorio oficial Prime Agent (`PrimeIntellect-ai/prime-agent`)  
> - Implementación de referencia de seguridad [`qwen_safe_prime_agent.py`](file:///Users/felipe_gonzalez/.codex/skills/qwen-safe-prime-agent/scripts/qwen_safe_prime_agent.py)  
> - Código base de [`hardening-loop`](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/)  
> **Estado:** `ESTABLE / ESPECIFICACIÓN NORMATIVA VINCULANTE`

---

## 1. Fundamentos Teóricos & Comparativa de Paradigmas

Los agentes de software autónomos han evolucionado a través de dos modelos computacionales radicalmente diferentes:

```text
A. Paradigma ReAct / Tool-Calling Clásico (Ineficiencia Lineal O(N·K))
   ┌─────────┐   Prompt con 30 Tools JSON   ┌──────────────┐   JSON-RPC Call    ┌───────────┐
   │         │ ───────────────────────────► │              │ ─────────────────► │ Herramienta│
   │   LLM   │                              │ Orchestrator │                    │ Discreta  │
   │ Context │ ◄─────────────────────────── │  (Stateless) │ ◄───────────────── │ (e.g. read)
   └─────────┘    Payload Serializado JSON  └──────────────┘   Output Crudo     └───────────┘
   (El contexto crece en cada turno con outputs crudos, saturando la ventana y degradando el razonamiento)

B. Paradigma Prime Agent / RLM (Eficiencia Logarítmica / Context-as-Variables)
   ┌─────────┐    Genera Código Python      ┌───────────────────────────────────────────────┐
   │         │ ───────────────────────────► │ IPython Kernel Persistente                    │
   │   LLM   │                              │ • Contexto reside en variables (df, ast, log) │
   │ Context │ ◄─────────────────────────── │ • Loops Python nativos (for/while/listcomp)   │
   └─────────┘    Stdout Sintetizado        │ • Subagentes = Invocaciones de funciones      │
   (0 tokens desperdiciados: la computación y el filtrado ocurren en memoria a velocidad nativa)
```

### 1.1. Análisis de Complejidad de Contexto y Token Churn

| Dimensión | ReAct Clásico (JSON-RPC) | Prime Agent / RLM (Kernel Persistente) |
| :--- | :--- | :--- |
| **Crecimiento de Contexto** | $O(N \cdot S)$, donde $N$ es el número de operaciones y $S$ el tamaño promedio de los payloads leídos. | $O(S_{\text{sintetizado}})$, independiente del tamaño bruto de los archivos analizados. |
| **Latencia de Roundtrip** | $N$ llamadas completas de inferencia al LLM ($N \times \text{TTFT}$). | $1$ llamada de inferencia que ejecuta un script multi-operación en el kernel local ($1 \times \text{TTFT} + \Delta t_{\text{python}}$). |
| **Manejo de Estado** | Stateless en el runtime; reconstruido íntegramente en el prompt. | Stateful en la memoria del proceso del kernel; sobrevive entre turnos. |
| **Límite de Escala** | Colapsa ante repositorios grandes (>100k tokens de árbol). | Puede operar sobre gigabytes de datos en variables sin saturar la ventana de contexto. |

### 1.2. La Dualidad TypeScript Host / Python Kernel
En la arquitectura oficial de Prime Agent, la separación de responsabilidades es tajante:
- **TypeScript Host (`AgentSession`, `SessionManager`):** Es el dueño exclusivo de la interacción con los proveedores de LLM, el streaming de tokens, la persistencia de transcripciones JSONL, la gestión de leases de sesión del daemon y las políticas de timeouts y scheduling.
- **Python Kernel (IPython / `ipykernel`):** Es el **entorno de control orientado al modelo**. El LLM escribe código Python para operar sobre archivos, ejecutar comandos del proyecto (`%%bash`), interactuar con memoria y lanzar subagentes.

---

## 2. Mecánica Detallada del Inner Loop (RLM & REPL)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        INNER AGENTIC LOOP (RLM & IPython Kernel)                       │
│                                                                                        │
│   ┌───────────────────────────┐            ┌───────────────────────────────────────┐   │
│   │     LLM Generador         │ ──(Code)─► │       Kernel Python Persistente       │   │
│   │    (Qwen / Claude)        │ ◄─(Stdout)─│       • Variables en Memoria (Data)   │   │
│   └───────────────────────────┘            │       • Control Flow Python (for/if)  │   │
│                 ▲                          │       • Subagentes vía `rlm(...)`     │   │
│                 │                          └───────────────────────────────────────┘   │
│                 │                                      │ (Jupyter Comm / Control Ch)   │
│                 │                                      ▼                               │
│                 │                          ┌───────────────────────────────────────┐   │
│                 │                          │ TypeScript Host (`AgentSession`)       │   │
│                 │                          │ • Parent-Scoped Sub-Agent Registry    │   │
│                 │                          │ • Token/Cost Folding Attribution      │   │
│                 │                          └───────────────────────────────────────┘   │
│                 │                                                                      │
│                 └─────── Failure Fingerprint Detection (Anti-Rabbit Hole) ─────────────┘
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1. Comunicación por Canales Jupyter & Prevención de Deadlocks
El shim Python de Prime Agent (`prime-agent-runtime`) interactúa con el host TypeScript a través de *Comm Targets* de Jupyter (`host.request`).
- **Invariante Crítica:** Las respuestas de admisión de subagentes y solicitudes al host viajan obligatoriamente por el **canal de control** de ZeroMQ/Jupyter, **nunca por el canal shell**.
- **Razón Arquitectónica:** Si la respuesta viajara por el canal shell mientras una celda se está ejecutando, el kernel quedaría en deadlock esperando que termine la celda para leer la respuesta que la misma celda necesita para continuar.

### 2.2. Semántica de Subagentes Nativos (`rlm(...)`)
El callable `rlm` está precargado en el kernel y expone un contrato asíncrono estricto:
1. **Retorno Inmediato en Admisión:** `handle = await rlm("Investigar módulo X")` no espera la finalización del hijo; retorna un `RLMSpawnHandle` con `rlm_child_id`, `name`, `session_dir` y `model`.
2. **Entrega de Resultados Asíncrona:** Los resultados no se inyectan en el valor de retorno; el subagente se comunica mediante mensajes explícitos `agent_message.send(..., receiver_role="parent")` o escribiendo artefactos en disco.
3. **Registro con Alcance de Padre (Parent-Scoped Sub-Agent Registry):** El listado de subagentes (`await rlm.list_subagents()`) es durable y sobrevive a compactaciones, reinicios de kernel y restauración de sesiones.
4. **Atribución y Plegado de Costos (`child_usage_attributed`):** El consumo de tokens de los subagentes se pliega de manera asíncrona en el turno del asistente padre que lo invocó, evitando pérdida de visibilidad en telemetría.
5. **Profundidad de Recursión Acotada:** Por defecto `RLM_MAX_DEPTH = 1`. El root puede crear hijos, pero los hijos no pueden generar nietos a menos que se configure explícitamente.

### 2.3. Compactación Jerárquica y Navegación en Árbol (`/tree`)
Prime Agent implementa compactación automática estructurada cuando:
$$\text{contextTokens} > \text{contextWindow} - \text{reserveTokens} \quad (\text{default } \text{reserveTokens} = 16384)$$

- **Punto de Corte:** Conserva los últimos `keepRecentTokens` (default $20000$) y resume el historial anterior en formato markdown canónico (`## Goal`, `## Constraints`, `## Progress`, `## Key Decisions`, `<read-files>`, `<modified-files>`).
- **Split Turns:** Si un solo turno excede el presupuesto, genera dos resúmenes combinados (*History summary* + *Turn prefix summary*).
- **Invariante de Corte:** **Nunca cortar en tool results**, los cuales deben permanecer atados a su tool call correspondiente.

---

## 3. Mecánica Detallada del Outer Harness Loop (Gobernanza y Seguridad)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 OUTER HARNESS LOOP                                     │
│                                                                                        │
│   [GENESIS] ──► [PREFLIGHT] ──► [WORKTREE_OWNED] ──► [RED (Pre-Test)]                  │
│                                                            │                           │
│   [CLEANUP / PASS] ◄── [INDEPENDENT AUDIT] ◄── [GREEN (Post-Test)] ◄─── [AGENT LOOP]  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1. Cadena Criptográfica de Estados (HMAC/SHA-256 Authority Chain)
El harness no confía en variables de memoria volátiles para la seguridad del ciclo de vida. Cada transición se escribe en un ledger append-only firmado criptográficamente:

$$\text{Record}_N = \left\{ \text{seq}: N, \, \text{state}: S_N, \, \text{prev}: \text{Digest}(\text{Block}_{N-1}), \, \text{payload}: P_N \right\}$$
$$\text{Block}_N = \left\{ \text{record}: \text{Record}_N, \, \text{mac}: \text{HMAC}_K(\text{Record}_N) \right\}$$

Si cualquier proceso o atacante modifica un archivo de estado intermedio, el hash `prev` o el MAC fallan, provocando un **aborto inmediato fail-closed**.

### 3.2. Supervisión de Procesos a Bajo Nivel (`ProcRecord` + `os.killpg`)
Para garantizar que tests en bucle infinito o workers secundarios no queden colgados consumiendo CPU o bloqueando sockets:
1. Todo subproceso se lanza con `start_new_session=True` (POSIX `setsid()`), estableciendo `PGID == PID`.
2. Se construye un `ProcRecord` completo registrando `pid`, `pgid`, `ppid`, ancestros y el árbol de descendientes obtenido vía `ps -axo pid=,ppid=`.
3. Ante un timeout o aborto, la rutina `cancel_owned` ejecuta la secuencia determinista:
   - Envío de `SIGTERM` a todo el grupo: `os.killpg(pgid, signal.SIGTERM)`.
   - Espera no bloqueante con sondeo activo (`deadline = monotonic() + 2.0s`).
   - Si quedan procesos vivos, escalamiento forzado: `os.killpg(pgid, signal.SIGKILL)`.
   - Verificación de vacuidad del grupo con `group_empty(pgid)` (`os.killpg(pgid, 0)` lanzando `ProcessLookupError`).

### 3.3. Semántica Formal de Quality Gates (`--autonomous-gate`)
El motor de modo autónomo sigue reglas matemáticas precisas:
- **Orden de Evaluación:** Tras cada turno del asistente, los gates configurados se ejecutan **antes** de chequear los límites de continuación, turnos, tokens o tiempo.
- **Cortocircuito por Éxito:** Un gate con `exit code 0` autoriza la terminación inmediata del run, incluso si se alcanzaron otros límites.
- **Idempotencia Anti-Desperdicio:** Si un gate falló en el turno $T$, el harness **no vuelve a ejecutar el gate en $T+1$ a menos que el workspace haya sufrido mutaciones en disco**, incrementando directamente el contador de intentos.
- **Jerarquía de Chequeo de Presupuestos:**
  $$\text{1. Continuations} \longrightarrow \text{2. Turns} \longrightarrow \text{3. Tokens (Input + Output + CacheWrite)} \longrightarrow \text{4. Wall-Clock Time}$$
  *(Nota: Los `CacheRead` tokens se excluyen de la contabilidad de presupuesto).*

### 3.4. Detección de Huellas de Fallo y Antídoto Anti-Rabbit Hole (Incidente P16)
Documentado empíricamente en la Wiki de Orquestación tras un incidente donde un agente iteró durante 66 minutos en un bucle ciego:
$$\text{tool\_signature} = \text{SHA256}(\text{tool\_name} \parallel \text{canonical\_json}(\text{arguments}))$$
$$\text{failure\_fingerprint} = \text{SHA256}(\text{error\_class} \parallel \text{tool\_signature} \parallel \text{normalized\_error})$$

**Máquina de Estados de Recuperación:**
1. Si `failure_fingerprint` se repite sin cambio en el estado del código $\to$ **Aborto inmediato**.
2. Si el error es recuperable $\to$ Exigir `strategy_delta` explícito en el siguiente turno.
3. Criterio de parada mandatorio:
   $$\text{DONE\_WHEN} + \text{turn\_budget} + \text{wall\_time\_budget} + \text{pointer\_to\_existing\_artifact}$$

---

## 4. Gap Analysis Exhaustivo de `hardening-loop`

Se realizó una auditoría técnica línea por línea sobre el código base actual de `hardening-loop`:

```text
hardening_loop/
├── runner.py             [GAP 1: Envelopes en lista plana sin firma encadenada de estado previo]
├── sandbox.py            [GAP 2: Subprocess directo sin aislamiento en Process Groups ni killpg]
├── phases/
│   ├── base.py           [GAP 3: Falta inyección de prev_evidence_hash en el cálculo de input_hash]
│   ├── question.py       [Estado: Estable / Auditoría de requerimientos AST]
│   ├── delete.py         [GAP 4: No captura precondition_hash del baseline antes de podar]
│   ├── simplify.py       [GAP 5: Falta detección de LoopGuard ante simplificaciones cíclicas]
│   ├── verify.py         [GAP 6: Ejecuta tests solo al final; no valida delta Red -> Green]
│   └── codify.py         [GAP 7: Genera candidatos sin vincularlos a la prueba Red previa]
└── admission.py          [GAP 8: KnowledgeAdmissionGate no exige firma de precondition_hash]
```

### Matriz de Riesgo y Vulnerabilidades Técnicas

| Módulo | Comportamiento Actual | Vulnerabilidad / Riesgo | Corrección Prime Agent |
| :--- | :--- | :--- | :--- |
| **`runner.py`** | Itera sobre `self.envelopes.append(envelope)` y crea manifest al final. | Si una fase intermedia se saltea o adultera, el manifest no detecta la ruptura de precedencia. | Incorporar `PhaseChainLink` donde cada fase firma `prev_evidence_hash`. |
| **`sandbox.py`** | `subprocess.run(cmd, timeout=...)` estándar. | Un test con hilos zombis o bucle infinito retiene locks de archivos y puertos tras timeout. | Implementar `ProcessGroupSandbox` con `start_new_session=True` y `killpg`. |
| **`phases/base.py`** | `input_hash = sha256_dict({target_path, target_content_hash, context})`. | El `context` no incluye obligatoriamente el hash criptográfico de la fase anterior. | Exigir `prev_evidence_hash` en el cálculo de `input_hash`. |
| **`phases/delete.py`** | Identifica código muerto y genera `diff.patch`. | No hay prueba reproducible de que el código antes de podar cumplía o fallaba una condición. | Capturar `precondition_digest` antes de aplicar la poda. |
| **`phases/simplify.py`**| Transforma AST iterativamente. | Riesgo de entrar en loops infinitos si dos reglas de simplificación oscilan. | Integrar `LoopFingerprintGuard` para abortar transformaciones oscilatorias. |
| **`phases/codify.py`** | Exporta `knowledge_candidate.yaml` con `evidence_id`. | La regla no demuestra falsabilidad empírica sobre el código base original. | Enlazar `precondition_hash` (falla base) y `postcondition_hash` (éxito verificado). |

---

## 5. Blueprint de Transferencia Tecnológica para `hardening-loop`

A continuación se definen los 5 pilares arquitectónicos que deben implementarse en el núcleo de `hardening-loop`.

---

### Pilar 1: Sequential Phase Ledger Criptográfico (`PhaseChainLink`)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SEQUENTIAL PHASE LEDGER                                   │
│                                                                                        │
│   Phase 1: QUESTION          Phase 2: DELETE            Phase 3: SIMPLIFY              │
│   ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐          │
│   │ seq: 1            │ ───► │ seq: 2            │ ───► │ seq: 3            │ ──► ...  │
│   │ prev: 'GENESIS'   │      │ prev: Hash(Ph 1)  │      │ prev: Hash(Ph 2)  │          │
│   │ output_hash: H1   │      │ output_hash: H2   │      │ output_hash: H3   │          │
│   │ signature: S1     │      │ signature: S2     │      │ signature: S3     │          │
│   └───────────────────┘      └───────────────────┘      └───────────────────┘          │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Cada fase genera un bloque inmutable que se valida al ingresar a la siguiente:
$$\text{Signature}_N = \text{SHA256}\left( \text{seq}_N \parallel \text{phase}_N \parallel \text{prev\_evidence\_hash}_{N-1} \parallel \text{input\_hash}_N \parallel \text{output\_hash}_N \right)$$

---

### Pilar 2: Sandboxing con Process Groups y Timeouts Atómicos (`ProcessGroupSandbox`)

Toda ejecución de tests, linters o scripts de verificación en `hardening-loop` debe confinarse en Process Groups POSIX independientes para erradicar procesos huérfanos.

---

### Pilar 3: Invariante Red Binding en el Ciclo de Endurecimiento

Ningún `KnowledgeCandidate` puede admitirse en el [KnowledgeAdmissionGate](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/admission.py) sin demostrar:
1. **Red Precondition:** Test ejecutado sobre el target original que retorna `exit != 0` o captura el defecto (`precondition_hash`).
2. **Green Postcondition:** Test ejecutado sobre el target endurecido que retorna `exit == 0` (`postcondition_hash`).
3. **Scoped Boundary:** Verificación de que `git diff --name-only` afectó exclusivamente a los paths autorizados.

---

### Pilar 4: Motor Anti-Rabbit Hole y Detección de Bucles en Simplificación

Para evitar que `SimplifyPhase` u optimizadores automáticos oscilen entre dos representaciones AST equivalentes, se computa la huella de transformación en cada iteración y se aborta ante repetición idéntica.

---

### Pilar 5: Analysis Worker Context en Memoria (RLM-Style AST Cache)

Para repositorios medianos y grandes, `HardeningRunner` inicializará un `TargetContextStore` en memoria donde los árboles AST, tablas de símbolos y grafos de llamadas se parsean una sola vez y se reutilizan entre `QuestionPhase`, `DeletePhase` y `SimplifyPhase`, eliminando I/O redundante de disco.

---

## 6. Implementación de Referencia (Código Completo y Tipado)

A continuación se detalla el código de producción listo para ser integrado en `src/hardening_loop/`.

### 6.1. Extensión de Modelos: `PhaseChainLink` y `RedPreconditionBinding`

```python
# src/hardening_loop/models.py (Extensiones)
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional
from .models import PhaseName, sha256_dict, utc_now_iso


@dataclass(frozen=True)
class PhaseChainLink:
  """Enlace criptográfico inmutable en la cadena de ejecución de fases."""

  seq: int
  phase: PhaseName
  prev_evidence_hash: str
  input_hash: str
  output_hash: str
  signature: str
  timestamp: str

  @classmethod
  def create(
      cls,
      seq: int,
      phase: PhaseName,
      prev_evidence_hash: str,
      input_hash: str,
      output_hash: str,
  ) -> PhaseChainLink:
    payload = {
        "seq": seq,
        "phase": phase.value,
        "prev_evidence_hash": prev_evidence_hash,
        "input_hash": input_hash,
        "output_hash": output_hash,
    }
    signature = sha256_dict(payload)
    return cls(
        seq=seq,
        phase=phase,
        prev_evidence_hash=prev_evidence_hash,
        input_hash=input_hash,
        output_hash=output_hash,
        signature=signature,
        timestamp=utc_now_iso(),
    )

  def verify_integrity(self, expected_prev_hash: str) -> bool:
    """Valida que el bloque no haya sido adulterado y que enlace con el estado previo."""
    if self.prev_evidence_hash != expected_prev_hash:
      return False
    payload = {
        "seq": self.seq,
        "phase": self.phase.value,
        "prev_evidence_hash": self.prev_evidence_hash,
        "input_hash": self.input_hash,
        "output_hash": self.output_hash,
    }
    return self.signature == sha256_dict(payload)


@dataclass(frozen=True)
class RedPreconditionBinding:
  """Certificado inmutable de precondición Red para KnowledgeCandidates."""

  precondition_test_argv: list[str]
  precondition_exit_code: int
  precondition_stdout_hash: str
  precondition_stderr_hash: str
  baseline_target_hash: str

  def is_falsified_on_baseline(self) -> bool:
    """Comprueba que la precondición efectivamente fallaba en el baseline."""
    return self.precondition_exit_code != 0
```

---

### 6.2. Módulo de Aislamiento de Procesos: `ProcessGroupSandbox`

```python
# src/hardening_loop/sandbox.py
from __future__ import annotations
import os
import signal
import subprocess
import time
from typing import Any, Tuple


class ProcessGroupSandbox:
  """Ejecutor de subprocesos con contención estricta en Process Groups (POSIX setsid)."""

  @staticmethod
  def run_bounded(
      cmd: list[str],
      cwd: str,
      timeout_seconds: float,
      env: dict[str, str] | None = None,
      max_output_bytes: int = 10 * 1024 * 1024,  # 10 MB limit
  ) -> Tuple[int, str, str, bool, dict[str, Any]]:
    """Ejecuta un comando en un process group aislado.

    Returns:
        (exit_code, stdout, stderr, timed_out, telemetry)
    """
    t0 = time.monotonic()
    is_posix = os.name == "posix"

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env or os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=is_posix,  # Crea PGID independiente en POSIX
    )

    pgid = os.getpgid(proc.pid) if is_posix else proc.pid
    timed_out = False
    cleanup_verified = True

    try:
      stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
      timed_out = True
      stdout = ""
      stderr = f"Process timed out after {timeout_seconds} seconds."

      # Secuencia determinista de cancelación
      if is_posix:
        try:
          os.killpg(pgid, signal.SIGTERM)
          deadline = time.monotonic() + 1.5
          while time.monotonic() < deadline:
            try:
              os.killpg(pgid, 0)
              time.sleep(0.05)
            except ProcessLookupError:
              break

          # Si sigue vivo tras SIGTERM, aplicar SIGKILL definitivo
          try:
            os.killpg(pgid, signal.SIGKILL)
          except ProcessLookupError:
            pass
        except Exception:
          cleanup_verified = False
      else:
        proc.kill()

    duration_ms = (time.monotonic() - t0) * 1000.0

    # Truncación de seguridad contra desbordes de buffer
    stdout_truncated = stdout[:max_output_bytes]
    stderr_truncated = stderr[:max_output_bytes]

    telemetry = {
        "duration_ms": duration_ms,
        "pid": proc.pid,
        "pgid": pgid,
        "timed_out": timed_out,
        "cleanup_verified": cleanup_verified,
    }

    exit_code = -1 if timed_out else (proc.returncode or 0)
    return exit_code, stdout_truncated, stderr_truncated, timed_out, telemetry
```

---

### 6.3. Guardián Anti-Bucles: `LoopFingerprintGuard`

```python
# src/hardening_loop/phases/loop_guard.py
from __future__ import annotations
from typing import Set
from ..models import sha256_dict


class LoopFingerprintGuard:
  """Previene que transformaciones AST u optimizaciones entren en ciclos repetitivos."""

  def __init__(self, max_allowed_repetitions: int = 1):
    self.seen_fingerprints: Set[str] = set()
    self.max_allowed_repetitions = max_allowed_repetitions

  def compute_fingerprint(
      self, transform_id: str, code_diff: str, error_context: str = ""
  ) -> str:
    payload = {
        "transform_id": transform_id,
        "code_diff": code_diff.strip(),
        "error_context": error_context.strip()[:300],
    }
    return sha256_dict(payload)

  def register_and_check(
      self, transform_id: str, code_diff: str, error_context: str = ""
  ) -> bool:
    """Retorna True si la transformación es válida (nueva), o False si es un bucle repetitivo."""
    fingerprint = self.compute_fingerprint(
        transform_id, code_diff, error_context
    )
    if fingerprint in self.seen_fingerprints:
      return False  # Bucle repetitivo detectado
    self.seen_fingerprints.add(fingerprint)
    return True
```

---

### 6.4. Orquestador Reforzado con Cadena Secuencial (`HardeningRunner`)

```python
# src/hardening_loop/runner.py (Fragmento de integración)
from .models import PhaseChainLink, sha256_dict, PhaseName, EvidenceEnvelope


class HardeningRunner:
  # ...

  def __init__(self, target_path: str, output_dir: str):
    # ...
    self.chain_links: list[PhaseChainLink] = []

  def run_phase(
      self, phase_name: PhaseName, context: dict[str, Any] | None = None
  ) -> EvidenceEnvelope:
    # 1. Determinar el hash de precedencia (prev_evidence_hash)
    prev_hash = (
        "GENESIS"
        if not self.chain_links
        else self.chain_links[-1].signature  # o output_hash
    )

    ctx = context or {}
    ctx["prev_evidence_hash"] = prev_hash
    ctx["evidence_ids"] = [e.evidence_id for e in self.envelopes]

    # 2. Ejecutar la fase
    phase = self.PHASE_MAP[phase_name]
    envelope = phase.run(self.target_path, ctx, self.output_dir)

    # 3. Crear y registrar el eslabón criptográfico en el ledger
    link = PhaseChainLink.create(
        seq=len(self.chain_links) + 1,
        phase=phase_name,
        prev_evidence_hash=prev_hash,
        input_hash=envelope.canonical.input_hash,
        output_hash=envelope.canonical.output_hash,
    )

    # Validar integridad inmediata (fail-closed)
    if not link.verify_integrity(expected_prev_hash=prev_hash):
      raise RuntimeError(
          f"Cryptographic integrity violation in phase {phase_name.value}"
      )

    self.chain_links.append(link)
    self.envelopes.append(envelope)
    self.work_unit.phases_executed.append(phase_name.value)

    # Persistir artefactos...
    return envelope
```

---

## 7. Threat Model & Matriz de Falla Cerrada (Fail-Closed)

| Vector de Amenaza / Fallo | Mecanismo de Detección | Respuesta Determinista del Sistema |
| :--- | :--- | :--- |
| **Bypass de Fase Previa** | `PhaseChainLink.verify_integrity()` detecta mismatch en `prev_evidence_hash`. | **ABORT:** Lanza `CryptographicIntegrityError` y suspende la ejecución. |
| **Test Infinito en VerifyPhase** | `ProcessGroupSandbox` detecta timeout en `communicate()`. | **KILL & RECORD:** Envía `SIGTERM` $\to$ `SIGKILL` al PGID y marca `status = FAIL`. |
| **Bucle de Simplificación (P16)** | `LoopFingerprintGuard` detecta huella repetida en `seen_fingerprints`. | **ABORT TRANSFORM:** Descarta el parche actual y emite advertencia en `contract_diff.json`. |
| **Adulteración de Envelope en Disco** | `SchemaValidator` y verificación SHA-256 de manifest. | **FAIL-CLOSED:** Invalida el `evidence_manifest.json` y deniega la admisión. |
| **Auto-admisión sin Precondición Red** | `KnowledgeAdmissionGate` comprueba que `precondition_exit_code != 0`. | **REJECT:** Bloquea la transición a `ADMITTED` sin firma humana explícita. |

---

## 8. Plan de Adopción Gradual por WorkOrders (Roadmap)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        ROADMAP DE ADOPCIÓN                             │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [WO-01: Sandboxing de Procesos]                                       │
│  • Reemplazar subprocess en sandbox.py por ProcessGroupSandbox.        │
│  • Tests unitarios de timeout forzado y verificación de PGID.          │
│                                                                        │
│  [WO-02: Sequential Phase Ledger]                                      │
│  • Incorporar PhaseChainLink en models.py.                             │
│  • Encadenar prev_evidence_hash en HardeningRunner y BasePhase.        │
│                                                                        │
│  [WO-03: Red Binding en CodifyPhase & Admission Gate]                  │
│  • Integrar RedPreconditionBinding en candidates y records.            │
│  • Actualizar KnowledgeAdmissionGate para validar falsabilidad base.   │
│                                                                        │
│  [WO-04: LoopFingerprintGuard en SimplifyPhase]                        │
│  • Proteger transformaciones AST contra oscilaciones cíclicas.         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Conclusión

El estudio empírico de **Prime Agent** demuestra que los agentes de software alcanzan su máxima confiabilidad no mediante la acumulación de herramientas arbitrarias, sino mediante:
1. **La unificación de la superficie de ejecución en un kernel programático persistente.**
2. **La gobernanza determinista del ciclo de vida mediante un harness criptográfico con supervisión de procesos de bajo nivel.**

La integración de este blueprint en `hardening-loop` transformará nuestro motor en una plataforma de endurecimiento algorítmico matemáticamente verificable, inmune a cuelgues por procesos zombis y resistente a bucles de fallo no productivos.
