---
title: "Bases Teóricas: Principios de Zechner y Musk"
topic: "hardening-loop"
doc_type: reference
tags: [referencia, fundamentos, musk-zechner, ingenieria]
sources:
  - "Algorithmic Code Hardening Loop v0.3 Paper"
created: 2026-08-21
updated: 2026-08-21
status: active
review_state: validated
owner: Felipe
ai_generated: none
caveats: false
---

# Bases Teóricas: Principios de Zechner y Musk

El **Algorithmic Code Hardening Loop** nace de la convergencia de dos principios fundamentales de ingeniería aplicados al desarrollo de software asistido por IA:

## 1. El Algoritmo de 5 Pasos (Musk)
1. **Hacer que los requerimientos sean menos tontos (Question Context):** Cuestionar el requerimiento sin importar quién lo formuló.
2. **Eliminar la parte o el proceso (Delete Harness):** Si no terminás reincorporando al menos el 10% de lo que borraste, no estás borrando suficiente.
3. **Simplificar u optimizar (Simplify Interfaces):** El error más común es optimizar algo que no debería existir.
4. **Acelerar el ciclo (Verify Faster):** Acortar el tiempo de feedback entre cambio y evidencia.
5. **Automatizar (Codify Learning):** Solo automatizar después de haber ejecutado los 4 pasos anteriores.

## 2. El Principio de Endurecimiento de Zechner
> "El modelo de lenguaje es un generador estocástico; el entorno debe ser un validador determinista."

En lugar de intentar que el modelo de IA sea "más inteligente" agregándole capas de prompts, se rodea al modelo con un entorno que acumula aprendizaje en forma de invariantes y contratos ejecutables.

---

## Relaciones

- [[loop-5-fases|trata]] — 💊 Implementación operacional del algoritmo.
- [[anti-ferrari-anti-slop|usa]] — 🧠 Aplicación de austeridad técnica.
