#!/usr/bin/env python3
"""qwen-tool-loop.py — Tool loop manual para Qwen3.8-27B MLX (:1234).

Qwen emite <tool_call> XML como texto (sin function calling nativo).
Este wrapper: llama al modelo → parsea tool_call → ejecuta bash → devuelve
resultado como mensaje tool → repite hasta respuesta final sin tool_call.

Uso:
  ./scripts/qwen-tool-loop.py "<prompt>" [--max-steps 8] [--model qwen3.8-27b-mlx]
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:1234/v1/chat/completions"
TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*<function=(\w+)>(.*?)</function>\s*</tool_call>",
    re.DOTALL,
)
PARAM_RE = re.compile(r"<parameter=([^>]+)>(.*?)</parameter>", re.DOTALL)


def call_model(messages, model, max_tokens=4000):
    body = json.dumps({
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "stream": False,
    }).encode()
    req = urllib.request.Request(BASE, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read())
    return d["choices"][0]["message"]


def parse_tool_call(text):
    m = TOOL_CALL_RE.search(text)
    if not m:
        return None
    fn = m.group(1)
    params = {}
    for pm in PARAM_RE.finditer(m.group(2)):
        params[pm.group(1).strip()] = pm.group(2).strip()
    return {"function": fn, "params": params}


def execute(fn, params):
    """Ejecuta la tool. Solo bash/read permitidos. Whitelist estricta."""
    if fn == "bash":
        cmd = params.get("command", "")
        if not cmd:
            return {"ok": False, "error": "comando vacío"}
        try:
            p = subprocess.run(
                ["/bin/zsh", "-c", cmd],
                capture_output=True, text=True, timeout=300,
                cwd="/Users/felipe_gonzalez/Developer/examen_grado",
            )
            return {"ok": True, "exit": p.returncode, "stdout": p.stdout[-8000:], "stderr": p.stderr[-4000:]}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout 300s"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif fn == "read":
        path = params.get("file_path", "")
        try:
            with open(path) as f:
                return {"ok": True, "content": f.read()[:8000]}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    else:
        return {"ok": False, "error": f"tool no permitida: {fn}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prompt")
    ap.add_argument("--max-steps", type=int, default=8)
    ap.add_argument("--model", default="qwen3.8-27b-mlx")
    ap.add_argument("--system", default=(
        "Eres Qwen, ejecutor de tareas git en el workspace de Felipe. "
        "Cuando necesites ejecutar un comando, emite EXACTAMENTE este formato:\n"
        "<tool_call>\n<function=bash>\n<parameter=command>\n<comando>\n</parameter>\n</function>\n</tool_call>\n"
        "Sin texto alrededor del tool_call. Espera el resultado y continúa hasta completar la tarea. "
        "Al terminar, responde con un JSON final {\"status\": \"PASS\"|\"FAIL\", ...}."
    ))
    args = ap.parse_args()

    messages = [{"role": "system", "content": args.system}, {"role": "user", "content": args.prompt}]

    for step in range(1, args.max_steps + 1):
        t0 = time.time()
        msg = call_model(messages, args.model)
        text = msg.get("content") or ""
        print(f"── step {step} ({time.time()-t0:.1f}s) ──", file=sys.stderr)
        print(text, file=sys.stderr)

        tc = parse_tool_call(text)
        if not tc:
            # Respuesta final sin tool call
            print(json.dumps({"final": text}))
            return 0
        result = execute(tc["function"], tc["params"])
        print(f"→ tool {tc['function']} exit={result.get('exit')} ok={result.get('ok')}", file=sys.stderr)
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "tool", "tool_call_id": f"call_{step}", "name": tc["function"],
                         "content": json.dumps(result)[:8000]})

    print(json.dumps({"final": "MAX_STEPS", "error": "límite de pasos alcanzado"}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
