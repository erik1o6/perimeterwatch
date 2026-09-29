from __future__ import annotations

from typing import Annotated

import typer

from perimeterwatch.cli.common import actor, domain_arg, open_app, out, run_async
from perimeterwatch.core.errors import AuthorisationError, ValidationError
from perimeterwatch.core.models import Target, utcnow
from perimeterwatch.safety.authorisation import (
    ACK_VALID_FOR,
    check_dns,
    make_ack,
    new_token,
    record_name,
    record_value,
    statement_for,
)
from perimeterwatch.storage.repo import TenantRepo


def _show_record(domain: str, token: str) -> None:
    out.print("Create this DNS record where the domain's DNS is managed:\n")
    out.print("  Type   TXT")
    out.print(f"  Name   {record_name(domain)}", highlight=False)
    out.print(f"  Value  {record_value(token)}", highlight=False)
    out.print(f"\nThen run: [bold]pwatch verify check {domain}[/bold]")
    out.print(
        "[dim]Keep the record in place. It is checked again before every active scan, and "
        "removing it withdraws authorisation.[/dim]"
    )


def init(
    domain: Annotated[str, typer.Argument()],
    rotate: Annotated[
        bool, typer.Option("--rotate", help="Replace the existing token with a new one.")
    ] = False,
) -> None:
    """Get the DNS record that proves you control a domain."""
    root = domain_arg(domain)
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        row = repo.get_target(root) or repo.upsert_target(Target(root_domain=root))
        verification = repo.get_verification(row.id)
        if verification is None or rotate:
            verification = repo.create_verification(row.id, new_token())
            repo.audit(
                "verification.started", actor=actor(), object_type="target", object_id=str(row.id)
            )
        token = verification.token
    _show_record(root, token)


def check(domain: Annotated[str, typer.Argument()]) -> None:
    """Check that the DNS record is in place."""
    root = domain_arg(domain)
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        row = repo.get_target(root)
        verification = repo.get_verification(row.id) if row else None
        if row is None or verification is None:
            raise ValidationError(f"Start with 'pwatch verify init {root}'.")
        result = run_async(check_dns(root, verification.token))
        now = utcnow()
        verification.last_checked_at = now
        verification.last_result = result.detail[:200]
        if result.verified:
            verification.verified_at = now
            verification.consecutive_failures = 0
        else:
            verification.consecutive_failures += 1
        repo.audit(
            "verification.checked",
            actor=actor(),
            object_type="target",
            object_id=str(row.id),
            meta={"verified": result.verified, "source": result.source},
        )
    if not result.verified:
        raise AuthorisationError(f"Not verified. {result.detail}")
    out.print(f"[green]Verified[/green] ({result.source}). {result.detail}", highlight=False)
    out.print(f"Active checks are now available: [bold]pwatch scan {root} --active[/bold]")


def authorise(domain: Annotated[str, typer.Argument()]) -> None:
    """Record a statement that you are authorised to test a domain.

    This is for when you cannot add a DNS record. It allows active checks, but
    never shows details about individual people.
    """
    root = domain_arg(domain)
    out.print(
        f"You are about to state that you may run active security checks against "
        f"[bold]{root}[/bold] and the hosts under it.\n"
        "Scanning systems without permission is unlawful in most places. This statement is "
        "stored and printed at the top of every report it enables.\n"
    )
    full_name = typer.prompt("Your full name").strip()
    organisation = typer.prompt("Organisation").strip()
    role = typer.prompt("Your role there").strip()
    typed_domain = typer.prompt("Type the domain again").strip().lower()
    if typed_domain != root:
        raise AuthorisationError("The domain you typed does not match. Nothing was recorded.")
    expected = statement_for(root)
    typed = typer.prompt(f'Type exactly: "{expected}"').strip()
    if typed != expected:
        raise AuthorisationError("The statement does not match. Nothing was recorded.")
    if not (full_name and organisation and role):
        raise AuthorisationError("Name, organisation and role are all required.")

    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        row = repo.get_target(root) or repo.upsert_target(Target(root_domain=root))
        ack = repo.add_ack(
            make_ack(
                row,
                full_name=full_name,
                organisation=organisation,
                role=role,
                keys=app.database.keys,
            )
        )
        repo.audit(
            "authorisation.acknowledged",
            actor=actor(),
            object_type="target",
            object_id=str(row.id),
            meta={"ack_id": str(ack.id)},
        )
    out.print(f"Recorded. Valid for {ACK_VALID_FOR.days} days.")
