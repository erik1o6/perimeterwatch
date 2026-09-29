from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.table import Table

from parapet.cli.common import out, run_async
from parapet.clients.dns import DnsClient
from parapet.config import KNOWN_SECRETS, config_files, load_settings, secret
from parapet.core.module import all_modules
from parapet.storage.db import open_database
from parapet.tools.locate import ToolLocator, manifest

OK = "[green]ok[/green]"
MISSING = "[yellow]missing[/yellow]"
BAD = "[red]problem[/red]"

SECRET_PURPOSE = {
    "GITHUB_TOKEN": "GitHub organisation checks and secret scanning",
    "HIBP_API_KEY": "breach lookups",
    "VIRUSTOTAL_API_KEY": "more subdomain sources",
    "SECURITYTRAILS_API_KEY": "more subdomain sources",
    "CERTSPOTTER_API_KEY": "more subdomain sources",
    "CHAOS_API_KEY": "more subdomain sources",
    "PARAPET_RPC_ETH_MAINNET": "Safe multisig checks",
    "PARAPET_DATA_KEYS": "data encryption (generated locally if unset)",
}


def doctor() -> None:
    """Check that everything needed is in place. Never prints secret values."""
    problems = 0
    settings = load_settings()
    table = Table(box=None, pad_edge=False, show_header=False)
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(overflow="fold")

    version = ".".join(str(p) for p in sys.version_info[:3])
    table.add_row("Python", OK, version)

    files = config_files()
    table.add_row(
        "Settings", OK, ", ".join(str(f) for f in files) or "defaults (run 'parapet init')"
    )

    try:
        database = open_database(settings)
    except Exception as exc:
        problems += 1
        table.add_row("Database", BAD, f"{type(exc).__name__}: {exc}")
    else:
        table.add_row("Database", OK, database.url.split("@")[-1].removeprefix("sqlite:///"))

    async def dns_works() -> bool:
        return (await DnsClient(timeout_s=4).query("iana.org", "NS")).ok

    if run_async(dns_works()):
        table.add_row("DNS lookups", OK, "public resolvers answer")
    else:
        problems += 1
        table.add_row("DNS lookups", BAD, "public resolvers did not answer. Check the network.")

    env_file = Path(".env")
    if env_file.is_file() and env_file.stat().st_mode & 0o077:
        problems += 1
        table.add_row(".env file", BAD, "readable by other users. Run: chmod 600 .env")

    locator = ToolLocator(settings.resolved_tools_dir, allow_path=settings.allow_path_tools)
    pins = manifest()
    wanted = sorted(
        {
            b
            for cls in all_modules().values()
            for b in (
                *cls.spec.requires_binaries,
                *cls.spec.any_of_binaries,
                *cls.spec.optional_binaries,
            )
        }
    )
    for name in wanted:
        if locator.available(name):
            table.add_row(f"Tool: {name}", OK, pins[name].version if name in pins else "on PATH")
        else:
            table.add_row(f"Tool: {name}", MISSING, f"parapet tools install {name}")

    for name in KNOWN_SECRETS:
        state = "[green]set[/green]" if secret(name) else MISSING
        table.add_row(f"Key: {name}", state, SECRET_PURPOSE.get(name, ""))

    out.print(table)
    if problems:
        out.print(f"\n{problems} problem(s) need fixing.")
        raise typer.Exit(1)
    out.print("\nReady. Missing tools and keys only switch off the checks that need them.")


def modules_list() -> None:
    """List every check, how deep it goes, and what it needs."""
    table = Table(box=None, pad_edge=False)
    for column in ("Check", "Depth", "Needs", "What it does"):
        table.add_column(column, overflow="fold")
    for name, cls in sorted(all_modules().items(), key=lambda kv: (kv[1].spec.mode.rank, kv[0])):
        spec = cls.spec
        needs = [*spec.requires_binaries, *spec.requires_keys]
        if spec.any_of_binaries:
            needs.append(" or ".join(spec.any_of_binaries))
        if spec.requires_verification:
            needs.append("verified domain")
        needs.extend(a.replace("_", " ") for a in spec.requires_target)
        table.add_row(name, spec.mode.value, ", ".join(needs) or "nothing", spec.description)
    out.print(table)
