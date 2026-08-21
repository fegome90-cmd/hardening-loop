VENV ?= .venv
PYTHON ?= $(VENV)/bin/python3
PYTEST ?= $(VENV)/bin/pytest
RUFF ?= $(VENV)/bin/ruff
MYPY ?= $(VENV)/bin/mypy

.PHONY: help install test lint format typecheck check clean audit-qwen

help:
	@echo "Hardening Loop — Comandos de Desarrollo"
	@echo "  make install    Instala paquete y dependencias dev en .venv"
	@echo "  make lint       Ejecuta ruff linter sobre src/ y tests/"
	@echo "  make format     Ejecuta formateo con ruff sobre src/ y tests/"
	@echo "  make typecheck  Ejecuta chequeo de tipos estático con mypy"
	@echo "  make test       Ejecuta suite de tests con pytest"
	@echo "  make check      Gate unificado: lint + typecheck + test"
	@echo "  make audit-qwen Ejecuta ciclo completo sobre target fixture"
	@echo "  make clean      Limpia artefactos compilados y caches"

install:
	uv pip install -e ".[dev]"

lint:
	$(RUFF) check src/ tests/

format:
	$(RUFF) format src/ tests/
	$(RUFF) check --fix src/ tests/

typecheck:
	$(MYPY) src/ tests/

test:
	$(PYTEST) tests/ -v

check: lint typecheck test
	@echo "✅ [GATE PASS] Todos los checks de calidad (lint, types, tests) pasaron exitosamente."

audit-qwen:
	$(PYTHON) -m hardening_loop.cli run --target fixtures/qwen-tool-loop.py --phase all --output evidence/run-001

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
