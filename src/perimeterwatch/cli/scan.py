from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from perimeterwatch.branding import user_agent
from perimeterwatch.cli.common import (
    SEVERITY_STYLE,
    App,
    actor,
    domain_arg,
    err,
    open_app,
    out,
    run_async,
)
from perimeterwatch.core.diff import ScanDiff
from perimeterwatch.core.engine import check_mode_allowed, run_scan, select_modules
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    Authorisation,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    ScanSnapshot,
    Target,
)
from perimeterwatch.report.build import ReportData, build_report
from perimeterwatch.report.render_html import render_html
from perimeterwatch.report.render_json import render_json, render_jsonl
from perimeterwatch.safety.authorisation import resolve_authorisation
from perimeterwatch.storage.repo import TenantRepo

FORMATS = {"html": "report.html", "json": "report.json", "jsonl": "findings.jsonl"}
STATUS_STYLE = {"ok": "green", "partial": "yellow", "skipped": "dim", "failed": "red"}


def parse_names(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    return {part.strip() for part in raw.split(",") if part.strip()}


def parse_formats(raw: str) -> list[str]:
    formats = [f.strip().lower() for f in raw.split(",") if f.strip()]
    unknown = [f for f in formats if f not in FORMATS]
    if unknown or not formats:
        raise ValidationError(
            f"Unknown format: {', '.join(unknown) or raw!r}. Choose from {', '.join(FORMATS)}."
        )
    return formats


def make_report(
    app: App, snapshot: ScanSnapshot, diff: ScanDiff, *, redact_personal: bool = False
) -> ReportData:
    s = app.settings
    return build_report(
        snapshot,
        diff,
        user_agent=user_agent(s.contact_url, s.abuse_email),
        contact_url=s.contact_url,
        abuse_email=s.abuse_email,
        retention_days=s.retention_days,
        redact_personal=redact_personal,
    )


def render(report: ReportData, fmt: str) -> str:
    return {"html": render_html, "json": render_json, "jsonl": render_jsonl}[fmt](report)


def write_reports(
    report: ReportData, formats: list[str], out_dir: Path | None, domain: str
) -> list[Path]:
    """Write report files readable only by the owner. Returns the paths written."""
    if out_dir is None:
        stamp = report.scan["started_at"][:19].replace(":", "").replace("-", "")
        out_dir = Path("pw-reports") / domain / f"{stamp}-{report.scan['id'][:8]}"
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    written = []
    for fmt in formats:
        path = out_dir / FORMATS[fmt]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(render(report, fmt))
        written.append(path)
    return written


def print_summary(report: ReportData, snapshot: ScanSnapshot) -> None:
    counts = report.summary["by_severity"]
    line = "  ".join(f"[{SEVERITY_STYLE[name]}]{n} {name}[/]" for name, n in counts.items() if n)
    out.print()
    out.print(f"[bold]{snapshot.target.root_domain}[/bold]: {line or 'no findings'}")

    diff = report.diff
    if diff.baseline:
        out.print("First scan of this domain. It sets the baseline for later comparisons.")
    elif diff.has_changes:
        out.print(
            f"Since the last scan: {len(diff.new)} new, {len(diff.resolved)} resolved, "
            f"{len(diff.changed)} changed."
        )
    else:
        out.print("No changes since the last scan.")

    top = [f for f in report.findings if f.severity >= 2][:8]
    if top:
        table = Table(box=None, pad_edge=False, show_header=False)
        table.add_column(no_wrap=True)
        table.add_column(overflow="fold")
        for finding in top:
            style = SEVERITY_STYLE[finding.severity.label]
            table.add_row(f"[{style}]{finding.severity.label}[/]", finding.title)
        out.print(table)


def scan(
    domain: Annotated[str, typer.Argument(help="A domain you are responsible for.")],
    probe: Annotated[
        bool,
        typer.Option("--probe", help="Also make one web request and TLS handshake per host."),
    ] = False,
    active: Annotated[
        bool,
        typer.Option(
            "--active", help="Also run port and misconfiguration checks. Needs authorisation."
        ),
    ] = False,
    only: Annotated[
        str | None, typer.Option("--only", help="Run only these checks, comma separated.")
    ] = None,
    skip: Annotated[
        str | None, typer.Option("--skip", help="Leave out these checks, comma separated.")
    ] = None,
    formats: Annotated[
        str, typer.Option("--format", help="Report formats: html, json, jsonl.")
    ] = "html,json",
    out_dir: Annotated[
        Path | None, typer.Option("--out", help="Directory to write reports to.")
    ] = None,
    no_report: Annotated[
        bool, typer.Option("--no-report", help="Store results without writing report files.")
    ] = False,
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit with code 3 if any check was skipped or failed.")
    ] = False,
    redact_personal: Annotated[
        bool, typer.Option("--redact-personal", help="Mask personal details in the report.")
    ] = False,
) -> None:
    """Scan a domain and write a report.

    By default only public records are consulted and no connection is made to your hosts.
    """
    root = domain_arg(domain)
    wanted_formats = parse_formats(formats)
    only_set, skip_set = parse_names(only), parse_names(skip)
    select_modules(only_set, skip_set)  # validate names before doing any work
    mode = ScanMode.ACTIVE if active else ScanMode.PROBE if probe else ScanMode.PASSIVE

    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        row = repo.get_target(root) or repo.upsert_target(Target(root_domain=root))
        target = repo.target_model(row)
        authorisation: Authorisation = run_async(
            resolve_authorisation(repo, row, app.database.keys, app.settings.never_contact)
        )

    check_mode_allowed(mode, authorisation, root)

    err.print(f"Scanning [bold]{root}[/bold] ({mode.value}).", highlight=False)
    err.print(f"[dim]{authorisation.basis}[/dim]", highlight=False)
    if mode is ScanMode.PROBE:
        err.print(
            "[dim]Probe mode sends one ordinary web request and TLS handshake to each "
            "host found under this domain.[/dim]"
        )

    def progress(name: str, result: ModuleResult | None) -> None:
        if result is None:
            return
        style = STATUS_STYLE[result.status.value]
        detail = result.skip_reason or f"{len(result.findings)} findings"
        err.print(f"  [{style}]{result.status.value:<8}[/] {name:<16} {detail}", highlight=False)

    snapshot, diff = run_async(
        run_scan(
            target,
            settings=app.settings,
            database=app.database,
            tenant_id=row.tenant_id,
            mode=mode,
            authorisation=authorisation,
            only=only_set,
            skip=skip_set,
            requested_by=actor(),
            progress=progress,
        )
    )

    report = make_report(app, snapshot, diff, redact_personal=redact_personal)
    if str(out_dir) == "-":
        sys.stdout.write(render(report, wanted_formats[0]))
    else:
        print_summary(report, snapshot)
        if not no_report:
            for path in write_reports(report, wanted_formats, out_dir, root):
                out.print(f"Report: [bold]{path}[/bold]", highlight=False)

    degraded = [
        m for m in snapshot.modules if m.status in (ModuleStatus.SKIPPED, ModuleStatus.FAILED)
    ]
    hints = sorted({m.hint for m in degraded if m.hint})
    if hints and str(out_dir) != "-":
        err.print(f"[dim]{len(degraded)} check(s) did not run. To enable them:[/dim]")
        for hint in hints:
            err.print(f"[dim]  {hint}[/dim]", highlight=False)
    if strict and degraded:
        raise typer.Exit(3)
