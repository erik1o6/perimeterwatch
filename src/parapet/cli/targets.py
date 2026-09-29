from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from parapet.cli.common import actor, domain_arg, open_app, out, require_target
from parapet.core.errors import ValidationError
from parapet.core.models import ContractRef, JobBoardRef, SafeRef, Target
from parapet.safety.domains import (
    validate_email,
    validate_eth_address,
    validate_github_org,
    validate_slug,
)
from parapet.storage.repo import TenantRepo

MAX_STAFF_CSV_BYTES = 1_000_000
CHAINS = {"eth"}


def parse_safe(raw: str) -> SafeRef:
    chain, sep, address = raw.partition(":")
    if not sep:
        chain, address = "eth", raw
    chain = chain.strip().lower()
    if chain not in CHAINS:
        raise ValidationError(f"Unknown chain {chain!r}. Supported: {', '.join(sorted(CHAINS))}.")
    return SafeRef(chain=chain, address=validate_eth_address(address))


_NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,100}$")
_PYPI_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,100}[A-Za-z0-9])?$")
_ENS_NAME = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+eth$")


def parse_contract(raw: str) -> ContractRef:
    """A contract as chain:address, optionally followed by =label."""
    location, _, label = raw.partition("=")
    safe = parse_safe(location)
    clean = " ".join(label.split())[:60]
    if clean and not re.fullmatch(r"[A-Za-z0-9 ._-]+", clean):
        raise ValidationError(f"{label!r} is not a usable label. Use letters, digits and spaces.")
    return ContractRef(chain=safe.chain, address=safe.address, label=clean)


def parse_names(values: list[str], pattern: re.Pattern[str], what: str) -> list[str]:
    names = []
    for raw in values:
        name = raw.strip()
        if what != "PyPI package":
            name = name.lower()
        if not pattern.fullmatch(name) or ".." in name:
            raise ValidationError(f"{raw!r} is not a valid {what} name.")
        names.append(name)
    return sorted(set(names))


def read_staff_csv(path: Path, root_domain: str) -> list[str]:
    """Work addresses from a CSV. Addresses at other domains are rejected."""
    if not path.is_file():
        raise ValidationError(f"{path} does not exist.")
    if path.stat().st_size > MAX_STAFF_CSV_BYTES:
        raise ValidationError(f"{path} is larger than 1 MB.")
    emails: list[str] = []
    rejected = 0
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.reader(fh):
            for cell in row:
                cell = cell.strip()
                if "@" not in cell:
                    continue
                try:
                    emails.append(validate_email(cell, root_domain=root_domain))
                except ValidationError:
                    rejected += 1
    if rejected:
        out.print(
            f"[yellow]{rejected} address(es) were ignored:[/yellow] "
            f"not valid, or not at {root_domain}."
        )
    return sorted(set(emails))


def add(
    domain: Annotated[str, typer.Argument(help="The domain to monitor, such as myproject.xyz.")],
    github_org: Annotated[
        str | None, typer.Option("--github-org", help="GitHub organisation name.")
    ] = None,
    safe: Annotated[
        list[str] | None,
        typer.Option("--safe", help="Safe multisig address, as eth:0x... Repeat for several."),
    ] = None,
    greenhouse: Annotated[
        str | None, typer.Option("--greenhouse", help="Greenhouse job board name.")
    ] = None,
    lever: Annotated[str | None, typer.Option("--lever", help="Lever job board name.")] = None,
    staff_csv: Annotated[
        Path | None,
        typer.Option("--staff-csv", help="CSV of work email addresses, supplied by you."),
    ] = None,
    npm: Annotated[
        list[str] | None,
        typer.Option(
            "--npm", help="npm package you publish, such as @acme/sdk. Repeat for several."
        ),
    ] = None,
    pypi: Annotated[
        list[str] | None,
        typer.Option("--pypi", help="PyPI package you publish. Repeat for several."),
    ] = None,
    contract: Annotated[
        list[str] | None,
        typer.Option(
            "--contract",
            help="Contract to watch for changes of control, as eth:0x...=label. Repeat for several.",
        ),
    ] = None,
    ens: Annotated[
        list[str] | None,
        typer.Option("--ens", help="ENS name you hold, such as acme.eth. Repeat for several."),
    ] = None,
) -> None:
    """Add a domain, or update the details of one already added."""
    root = domain_arg(domain)
    if greenhouse and lever:
        raise ValidationError("Give either --greenhouse or --lever, not both.")

    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        existing = repo.get_target(root)
        target = repo.target_model(existing) if existing else Target(root_domain=root)

        if github_org is not None:
            target.github_org = validate_github_org(github_org)
        if safe:
            target.safes = [parse_safe(s) for s in safe]
        if greenhouse:
            target.job_board = JobBoardRef(
                kind="greenhouse", value=validate_slug(greenhouse, "job board name")
            )
        if lever:
            target.job_board = JobBoardRef(
                kind="lever", value=validate_slug(lever, "job board name")
            )
        if staff_csv is not None:
            target.staff_emails = read_staff_csv(staff_csv, root)
        if npm:
            target.npm_packages = parse_names(npm, _NPM_NAME, "npm package")
        if pypi:
            target.pypi_packages = parse_names(pypi, _PYPI_NAME, "PyPI package")
        if contract:
            target.contracts = [parse_contract(c) for c in contract]
        if ens:
            target.ens_names = parse_names(ens, _ENS_NAME, "ENS")

        row = repo.upsert_target(target)
        repo.audit(
            "target.updated" if existing else "target.added",
            actor=actor(),
            object_type="target",
            object_id=str(row.id),
            meta={"staff_addresses": len(target.staff_emails)},
        )
    out.print(f"{'Updated' if existing else 'Added'} [bold]{root}[/bold].")
    out.print(f"Next: [bold]parapet scan {root}[/bold]")


def list_() -> None:
    """List the domains you monitor."""
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        rows = repo.list_targets()
        if not rows:
            out.print("No domains yet. Add one with 'parapet target add DOMAIN'.")
            return
        table = Table(box=None, pad_edge=False)
        for column in ("Domain", "Scans", "Last scan", "Verified"):
            table.add_column(column)
        for row in rows:
            scans = repo.list_scans(row.id, status="done")
            verification = repo.get_verification(row.id)
            last = (
                scans[0].finished_at.strftime("%Y-%m-%d %H:%M")
                if scans and scans[0].finished_at
                else "never"
            )
            verified = "yes" if verification and verification.verified_at else "no"
            table.add_row(row.root_domain, str(len(scans)), last, verified)
        out.print(table)


def show(domain: Annotated[str, typer.Argument()]) -> None:
    """Show what is configured for a domain."""
    root = domain_arg(domain)
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        row = require_target(repo, root)
        target = repo.target_model(row)
        out.print(f"[bold]{root}[/bold]")
        out.print(f"  GitHub organisation  {target.github_org or 'not set'}")
        safes = ", ".join(f"{s.chain}:{s.address}" for s in target.safes) or "not set"
        out.print(f"  Safe multisigs       {safes}")
        board = (
            f"{target.job_board.kind}: {target.job_board.value}" if target.job_board else "not set"
        )
        out.print(f"  Job board            {board}")
        out.print(f"  npm packages         {', '.join(target.npm_packages) or 'not set'}")
        out.print(f"  PyPI packages        {', '.join(target.pypi_packages) or 'not set'}")
        contracts = ", ".join(c.label or c.address for c in target.contracts) or "not set"
        out.print(f"  Contracts            {contracts}")
        out.print(f"  ENS names            {', '.join(target.ens_names) or 'not set'}")
        # Count only. Addresses are personal data and are not echoed back.
        out.print(f"  Staff addresses      {len(target.staff_emails)} on file")
        scans = repo.list_scans(row.id, limit=10)
        if scans:
            out.print("  Recent scans")
            for scan in scans:
                when = scan.created_at.strftime("%Y-%m-%d %H:%M")
                out.print(f"    {str(scan.id)[:8]}  {when}  {scan.mode:<8} {scan.status}")


def remove(
    domain: Annotated[str, typer.Argument()],
    yes: Annotated[bool, typer.Option("--yes", help="Do not ask for confirmation.")] = False,
) -> None:
    """Remove a domain and delete everything stored about it."""
    root = domain_arg(domain)
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        row = require_target(repo, root)
        scans = len(repo.list_scans(row.id, limit=10_000))
        if not yes:
            typer.confirm(
                f"Delete {root} and its {scans} stored scan(s)? This cannot be undone.", abort=True
            )
        repo.remove_target(root)
        repo.audit("target.removed", actor=actor(), object_type="target", meta={"domain": root})
    out.print(f"Removed {root} and {scans} scan(s).")
