# Informe de Investigación: Arquitectura de Loops en Prime Agent & Transferencia a Hardening Loop

> **Documento Vivo — Iteración 1**  
> **Fecha:** 21 de Agosto de 2026  
> **Área:** Arquitectura de Sistemas Agénticos, RLM & Hardening Determinista  
> **Estado:** `DRAFT / EN EXPANSIÓN`  
> **Target:** [hardening-loop](file:///Users/felipe_gonzalez/Developer/hardening-loop)

---

## 1. Resumen Ejecutivo

Los sistemas agénticos de primera generación (basados en catálogos extensos de herramientas JSON-RPC) sufren de **inflación de contexto, alta latencia de roundtrip y fragilidad ante bucles largos**. Cada interacción —como leer archivos, listar directorios o ejecutar pruebas— requiere serializar payloads JSON y reenviar transcripciones completas al LLM.

**Prime Agent** (desarrollado por Prime Intellect e implementado con extensiones de seguridad en el ecosistema local) introduce una ruptura de paradigma resolviendo el problema en dos niveles desacoplados:
1. **Inner Loop (REPL / RLM):** Reemplaza el menú de herramientas por un único entorno de ejecución Python persistente (IPython kernel). El contexto no se vuelca en el prompt, sino que reside como **variables en memoria**, y los loops sobre archivos o datos se ejecutan en código Python nativo a velocidad de cómputo local.
2. **Outer Harness Loop (Control y Seguridad):** Un ciclo de gobernanza fail-closed con encadenamiento criptográfico (HMAC/SHA-256), supervisión estricta de subprocesos (`ProcRecord` con `os.killpg`) y contratos inmutables Red $\to$ Green (TDD).

Este informe analiza en profundidad ambos mecanismos y define cómo transferir estas lecciones a [`hardening-loop`](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/runner.py) para robustecer su orquestador de 5 fases.

---

## 2. Arquitectura de Loops en Prime Agent

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            OUTER HARNESS LOOP                               │
│                                                                             │
│  [GENESIS] ──► [PREFLIGHT] ──► [WORKTREE] ──► [RED (Pre-Test)]             │
│                                                     │                       │
│  [CLEANUP / PASS] ◄── [INDEPENDENT VERDICT] ◄── [GREEN (Post-Test)]        │
│                                                     ▲                       │
└─────────────────────────────────────────────────────┼───────────────────────┘
                                                      │ Control Turn
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       INNER AGENTIC LOOP (RLM / REPL)                       │
│                                                                             │
│  ┌───────────────────────┐              ┌────────────────────────────────┐  │
│  │   LLM Generador       │ ──(Código)─► │   Kernel Python Persistente    │  │
│  │   (Qwen / Claude)     │ ◄──(Stdout)─ │   • Variables en memoria       │  │
│  └───────────────────────┘              │   • Loops Python (for/while)   │  │
│                                         │   • Subagentes = Funciones     │  │
│                                         └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 2.1. El Loop Agéntico Interno (Recursive Language Model & Code-as-Action)

#### A. "Context as Variables" vs "Context in Prompt"
En lugar de volcar 10.000 líneas de código o un log de 50 MB en el prompt para que el LLM lo analice, Prime Agent carga la información en el kernel Python:

```python
# Patrón Prime Agent: El LLM escribe código para inspeccionar datos masivos
import json
from pathlib import Path

# Carga en memoria del kernel: 0 tokens gastados en el prompt
with open("massive_audit.json") as f:
  data = json.load(f)

# Filtrado local inmediato
dead_code_candidates = [
    item["symbol"]
    for item in data["findings"]
    if item["references"] == 0 and item["severity"] == "HIGH"
]

# Solo se emite al LLM el resultado sintetizado
print(f"Total candidatos: {len(dead_code_candidates)}")
print(dead_code_candidates[:5])
```

#### B. Subagentes como Llamadas a Funciones Programáticas
La delegación no requiere un protocolo complejo de orquestación externa. Un subagente es simplemente una función dentro del runtime que recibe parámetros estructurados y retorna objetos tipados:

```python
# Invocación recursiva dentro del REPL
worker_result = run_specialized_subagent(
    task="AST_SIMPLIFY",
    target_file="src/module/service.py",
    budget_seconds=30,
)
```

---

### 2.2. El Outer Harness Loop (Gobernanza y Supervisión en Python)

El archivo de producción [`qwen_safe_prime_agent.py`](file:///Users/felipe_gonzalez/.codex/skills/qwen-safe-prime-agent/scripts/qwen_safe_prime_agent.py) demuestra cómo blindar un loop agéntico contra fallos silenciosos, cuelgues y fugas de recursos:

#### A. Supervisión de Procesos y Eliminación de Procesos Zombis (`ProcRecord` + `os.killpg`)
Cuando se ejecutan scripts o tests generados por IA, es común encontrar loops infinitos o bloqueos por I/O. Prime Agent no confía en `subprocess.run(timeout=...)` simple, sino que rastrea el árbol de procesos completo:

```python
@dataclass
class ProcRecord:
  pid: int
  pgid: int
  ppid: int
  start: str
  executable: str
  argv: list[str]
  owner_token: str
  worktree: str
  command: str
  ancestors: list[dict]
  descendants: dict[str, dict]


def cancel_owned(rec: ProcRecord, timeout=2.0) -> dict:
  """Cancela de forma atómica todo el Process Group."""
  for sig in (signal.SIGTERM, signal.SIGKILL):
    if group_empty(rec.pgid):
      break
    try:
      os.killpg(rec.pgid, sig)
    except ProcessLookupError:
      break
    # Espera acotada con sondeo
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not group_empty(rec.pgid):
      time.sleep(0.02)
  return {"verified": group_empty(rec.pgid)}
```

#### B. Cadena Criptográfica de Estados (Authority Chain)
Cada transición de estado en el harness se registra en un archivo append-only (`chain`), firmado con HMAC y SHA-256:

$$\text{Block}_{N} = \text{HMAC}_{K}\left( \text{Seq}_N \,\|\, \text{State}_N \,\|\, \text{Digest}(\text{Block}_{N-1}) \,\|\, \text{Payload}_N \right)$$

Si un proceso externo o un bug intenta alterar un resultado intermedio, la validación de la cadena aborta en modo `fail-closed`.

#### C. Invariante Red $\to$ Green Estricto
1. **Fase Red:** Ejecuta el plan de pruebas antes de cualquier edición y exige que **fallen** con una firma de error esperada (`expect: fail`). Genera un artefacto inmutable `red.json`.
2. **Ejecución:** El agente muta el código únicamente dentro de un `git worktree` aislado.
3. **Fase Green:** Exige que los tests pasen (`expect: pass`) y verifica con `git diff --name-only` que no haya mutaciones fuera de los `expected_paths` autorizados.

---

## 3. Diagnóstico de `hardening-loop` (Estado Actual vs. Oportunidades)

Actualmente, [`hardening-loop`](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/) cuenta con una arquitectura limpia de 5 fases:
1. `QuestionPhase`
2. `DeletePhase`
3. `SimplifyPhase`
4. `VerifyPhase`
5. `CodifyPhase`

### Matriz de Comparación Técnica

| Característica | Estado Actual (`hardening-loop`) | Patrón Prime Agent | Nivel de Impacto |
| :--- | :--- | :--- | :--- |
| **Encadenamiento de Fases** | Envelopes en lista simple; manifest al final. | Cadena criptográfica secuencial ($H_n = \text{SHA256}(H_{n-1} + P_n)$). | **Crítico (Seguridad e Integridad)** |
| **Supervisión de Procesos** | `subprocess` estándar en [`sandbox.py`](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/sandbox.py). | Process Group (`start_new_session=True`) + `killpg` jerárquico. | **Alto (Robustez ante cuelgues)** |
| **Invariante Red-Preflight** | Pruebas ejecutadas únicamente al final en `VerifyPhase`. | Pre-test obligatorio (Red) antes de `DeletePhase`/`SimplifyPhase`. | **Alto (Determinismo TDD)** |
| **Contexto de Análisis** | Visitas AST estáticas y re-lectura de disco por fase. | Entorno / Worker en memoria con estado persistente. | **Medio (Rendimiento)** |

---

## 4. Propuestas de Transferencia para `hardening-loop`

### Propuesta 1: Sequential Phase Ledger (Encadenamiento Criptográfico)
Modificar [`BasePhase`](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/phases/base.py) y [`HardeningRunner`](file:///Users/felipe_gonzalez/Developer/hardening-loop/src/hardening_loop/runner.py) para que cada fase reciba y valide el hash de la fase anterior:

```python
# hardening_loop/models.py
@dataclass(frozen=True)
class PhaseLedgerEntry:
  seq: int
  phase: PhaseName
  prev_evidence_hash: str  # Hash del envelope previo (o 'GENESIS')
  canonical_hash: str  # Hash del payload canónico actual
  signature: str  # SHA-256(seq + phase + prev + canonical)
```

### Propuesta 2: Process Group Isolation en `sandbox.py`
Blindar la ejecución de comandos y suites de tests contra procesos huérfanos implementando `run_bounded_process` con `start_new_session=True` y rescate `killpg`:

```python
# hardening_loop/sandbox.py
def execute_bounded_command(
    cmd: list[str], cwd: str, timeout_seconds: float
) -> tuple[int, str, str, bool]:
  proc = subprocess.Popen(
      cmd,
      cwd=cwd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
      start_new_session=True,  # PGID propio
  )
  pgid = os.getpgid(proc.pid)
  try:
    stdout, stderr = proc.communicate(timeout=timeout_seconds)
    return proc.returncode, stdout, stderr, False
  except subprocess.TimeoutExpired:
    try:
      os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
      pass
    return -1, "", "Timeout exceeded", True
```

### Propuesta 3: Enlace de Pre-condición Red en `VerifyPhase` y `CodifyPhase`
Garantizar que todo `KnowledgeCandidate` formulado en `CodifyPhase` demuestre:
1. Qué fallo exacto ocurría en el estado base (`precondition_hash`).
2. La evidencia de que el patch de `Delete`/`Simplify` resolvió dicho fallo sin alterar contratos.

---

## 5. Roadmap de Investigación & Próximos Pasos

1. [ ] **Módulo de Benchmarking Comparativo:** Medir el tiempo de ejecución y consumo de memoria entre análisis AST estático vs. Worker en memoria.
2. [ ] **Prototipo de `ProcessGroupSandbox`:** Integrar la supervisión con `pgid` en el suite de tests de `hardening-loop`.
3. [ ] **Especificación de `EvidenceLedger`:** Documentar la enmienda en `docs/spec_v0.1.md` para formalizar la cadena criptográfica secuencial de fases.
