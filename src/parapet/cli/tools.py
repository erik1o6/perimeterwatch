from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from parapet.cli.common import err, out
from parapet.config import load_settings
from parapet.core.errors import ToolError, ValidationError
from parapet.tools import bump as bumper
from parapet.tools.installer import Installer
from parapet.tools.locate import manifest


def _installer() -> Installer:
    settings = load_settings()
    settings.ensure_data_dir()
    return Installer(settings.resolved_tools_dir)


def _names(requested: list[str] | None, all_: bool) -> list[str]:
    pins = manifest()
    if all_:
        return sorted(pins)
    if not requested:
        raise ValidationError("Name the tools to install, or use --all. See 'parapet tools list'.")
    unknown = [n for n in requested if n not in pins]
    if unknown:
        raise ValidationError(f"Not a pinned tool: {', '.join(unknown)}.")
    return requested


def list_() -> None:
    """Show the pinned tools and whether each is installed."""
    installer = _installer()
    table = Table(box=None, pad_edge=False)
    for column in ("Tool", "Version", "Licence", "State"):
        table.add_column(column)
    for name, pin in sorted(manifest().items()):
        state = installer.verify(name)
        label = (
            "[green]installed[/green]"
            if state.verified
            else "[red]altered[/red]"
            if state.installed
            else "[dim]not installed[/dim]"
        )
        table.add_row(name, pin.version, pin.license, label)
    out.print(table)
    out.print(f"[dim]Tools directory: {installer.tools_dir}[/dim]", highlight=False)


def install(
    names: Annotated[list[str] | None, typer.Argument(help="Tools to install.")] = None,
    all_: Annotated[bool, typer.Option("--all", help="Install every pinned tool.")] = False,
    force: Annotated[bool, typer.Option("--force", help="Download again even if present.")] = False,
) -> None:
    """Download pinned tools and verify each against its recorded checksum."""
    installer = _installer()
    failures = 0
    for name in _names(names, all_):
        try:
            state = installer.install(name, force=force)
        except ToolError as exc:
            failures += 1
            err.print(f"[red]failed[/red]    {name}: {exc}", highlight=False)
            continue
        out.print(
            f"[green]ok[/green]        {name} {state.version}  {state.detail}", highlight=False
        )
    if failures:
        raise typer.Exit(1)


def verify() -> None:
    """Check that installed tools are unchanged since they were installed."""
    installer = _installer()
    problems = 0
    for name in sorted(manifest()):
        state = installer.verify(name)
        if not state.installed:
            out.print(f"[dim]absent[/dim]    {name}", highlight=False)
        elif state.verified:
            out.print(
                f"[green]ok[/green]        {name} {state.version}  {state.detail}", highlight=False
            )
        else:
            problems += 1
            out.print(f"[red]altered[/red]   {name}: {state.detail}", highlight=False)
    if problems:
        err.print(
            f"{problems} tool(s) failed verification and will not be trusted. "
            "Reinstall with 'parapet tools install NAME --force'."
        )
        raise typer.Exit(1)


def bump(
    name: Annotated[str, typer.Argument(help="Tool to pin.")],
    version: Annotated[str, typer.Argument(help="Version number, or 'latest'.")] = "latest",
) -> None:
    """For maintainers: pin a tool release in the manifest, for review."""
    if version == "latest":
        version = bumper.latest_version(name)
    entry = bumper.resolve(name, version)
    path = bumper.write_entry(name, entry)
    out.print(f"Pinned {name} {entry['version']} for {', '.join(sorted(entry['assets']))}.")
    out.print(f"Review the change to {path} before committing it.", highlight=False)
    out.print("[dim]Then re-record the test fixtures for this tool: output formats change.[/dim]")
