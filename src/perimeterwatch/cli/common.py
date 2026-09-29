"""Shared pieces for the command line."""

from __future__ import annotations

import asyncio
import getpass
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console

from perimeterwatch.config import Settings, load_settings
from perimeterwatch.core.errors import PerimeterwatchError, ValidationError
from perimeterwatch.safety.domains import validate_domain
from perimeterwatch.storage.db import Database, open_database
from perimeterwatch.storage.repo import TenantRepo
from perimeterwatch.storage.tables import TargetRow

out = Console()
err = Console(stderr=True)

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


@dataclass
class App:
    settings: Settings
    database: Database


def open_app() -> App:
    settings = load_settings()
    return App(settings=settings, database=open_database(settings))


def actor() -> str:
    return f"cli:{getpass.getuser()}"


def domain_arg(raw: str) -> str:
    return validate_domain(raw)


def require_target(repo: TenantRepo, domain: str) -> TargetRow:
    row = repo.get_target(domain)
    if row is None:
        raise ValidationError(
            f"{domain} is not a known target. Add it with 'pwatch target add {domain}', "
            f"or scan it once with 'pwatch scan {domain}'."
        )
    return row


def run_async[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def fail(exc: PerimeterwatchError) -> typer.Exit:
    err.print(f"[red]Error:[/red] {exc}", highlight=False)
    return typer.Exit(exc.exit_code)
