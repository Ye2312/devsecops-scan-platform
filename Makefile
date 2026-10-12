.PHONY: install lint test up down logs db-up db-down db-reset migrate migration api worker clean

# Postgres published on localhost for running the API, worker and tests from .venv.
DEV_COMPOSE = docker compose -f docker-compose.yml -f docker-compose.dev.yml

install:
	python3 -m venv .venv
	.venv/bin/pip install -U pip
	.venv/bin/pip install -e ./shared
	.venv/bin/pip install -e ./app-api -e ./scanner-worker
	.venv/bin/pip install -r requirements-dev.txt

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
	.venv/bin/mypy shared app-api scanner-worker

test:
	.venv/bin/pytest -v

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f api worker

db-up:
	$(DEV_COMPOSE) up -d db

db-down:
	docker compose down

db-reset:
	docker compose down -v
	$(DEV_COMPOSE) up -d db

migrate:
	.venv/bin/alembic upgrade head

migration:
	.venv/bin/alembic revision --autogenerate -m "$(m)"
	.venv/bin/ruff check --fix shared/migrations/versions
	.venv/bin/ruff format shared/migrations/versions

api:
	.venv/bin/uvicorn app.main:app --reload --port 8000

worker:
	.venv/bin/python -m worker.main

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache
