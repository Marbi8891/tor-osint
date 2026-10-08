.DEFAULT_GOAL := help
PY ?= python3

.PHONY: help install test lint format check web up down clean

help: ## Muestra esta ayuda
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Instala el paquete con dependencias de desarrollo
	$(PY) -m pip install -e ".[dev]"

test: ## Ejecuta los tests (sin red)
	pytest

lint: ## Comprueba estilo y formato
	ruff check .
	ruff format --check .

format: ## Corrige estilo y formato
	ruff check --fix .
	ruff format .

check: lint test ## Lint + tests (lo mismo que el CI)

web: ## Arranca la interfaz web local
	tor-osint web --open

up: ## Levanta Tor + interfaz web con Docker Compose
	docker compose up -d --build

down: ## Para los contenedores
	docker compose down

clean: ## Borra cachés y artefactos de build
	rm -rf build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
