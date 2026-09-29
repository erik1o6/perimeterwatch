.PHONY: dev test lint fmt types audit tools check serve worker

dev:
	uv sync
	uv run parapet init

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
	uv run parapet tools install --all

check: lint types test

serve:
	uv run parapet serve

worker:
	uv run parapet worker
