.PHONY: dev test lint fmt types audit tools check serve worker

dev:
	uv sync
	uv run pwatch init

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff check --fix .
	uv run ruff format .

types:
	uv run mypy src

audit:
	uv run pip-audit

tools:
	uv run pwatch tools install --all

check: lint types test

serve:
	uv run pwatch serve

worker:
	uv run pwatch worker
