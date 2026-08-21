.PHONY: test lint audit clean install

install:
	pip install -e .

test:
	python3 -m pytest tests/ -v

audit-qwen:
	python3 -m hardening_loop.cli run --target /Users/felipe_gonzalez/Developer/examen_grado/scripts/qwen-tool-loop.py --phase all --output evidence/run-001

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache/ src/hardening_loop/__pycache__ tests/__pycache__
