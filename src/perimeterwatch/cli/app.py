"""The `perimeterwatch` command."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import typer

from perimeterwatch import __version__
from perimeterwatch import logging as pwlog
from perimeterwatch.cli import db, doctor, report, scan, serve, targets, tools, verify
from perimeterwatch.cli.common import err, out
from perimeterwatch.core.errors import PerimeterwatchError

app = typer.Typer(
    name="pwatch",
    help="See what is publicly visible about your own organisation's systems.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,  # locals can hold secrets
)


def _version(value: bool) -> None:
    if value:
        out.print(f"pwatch {__version__}")
        raise typer.Exit


@app.callback()
def root(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug logging."),
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    pwlog.configure(verbose=verbose)


def guarded(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Show expected errors as one line and exit with the right code."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except PerimeterwatchError as exc:
            err.print(f"[red]Error:[/red] {exc}", highlight=False, markup=True)
            raise typer.Exit(exc.exit_code) from None

    return wrapper


def _register(group: typer.Typer, name: str, fn: Callable[..., Any], **kwargs: Any) -> None:
    group.command(name, **kwargs)(guarded(fn))


_register(app, "scan", scan.scan)
_register(app, "report", report.report)
_register(app, "diff", report.diff)
_register(app, "authorise", verify.authorise)
_register(app, "doctor", doctor.doctor)
_register(app, "init", db.init)
_register(app, "serve", serve.serve)
_register(app, "worker", serve.worker)

target_app = typer.Typer(help="Manage the domains you monitor.", no_args_is_help=True)
_register(target_app, "add", targets.add)
_register(target_app, "list", targets.list_)
_register(target_app, "show", targets.show)
_register(target_app, "remove", targets.remove)
app.add_typer(target_app, name="target")

verify_app = typer.Typer(help="Prove you control a domain.", no_args_is_help=True)
_register(verify_app, "init", verify.init)
_register(verify_app, "check", verify.check)
app.add_typer(verify_app, name="verify")

modules_app = typer.Typer(help="See which checks exist.", no_args_is_help=True)
_register(modules_app, "list", doctor.modules_list)
app.add_typer(modules_app, name="modules")

tools_app = typer.Typer(help="Install and check the external tools.", no_args_is_help=True)
_register(tools_app, "list", tools.list_)
_register(tools_app, "install", tools.install)
_register(tools_app, "verify", tools.verify)
_register(tools_app, "bump", tools.bump)
app.add_typer(tools_app, name="tools")

db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
_register(db_app, "migrate", db.migrate)
_register(db_app, "purge", db.purge)
_register(db_app, "new-key", db.new_key)
app.add_typer(db_app, name="db")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
