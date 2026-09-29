from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from perimeterwatch.cli.common import actor, domain_arg, open_app, out, require_target
from perimeterwatch.cli.scan import (
    make_report,
    parse_formats,
    print_summary,
    render,
    write_reports,
)
from perimeterwatch.core.diff import ScanDiff, compute_diff
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import ScanSnapshot
from perimeterwatch.storage.repo import TenantRepo
from perimeterwatch.storage.tables import Scan


def _find(repo: TenantRepo, target_id: object, ref: str, domain: str) -> Scan:
    scan = repo.find_scan(target_id, ref)  # type: ignore[arg-type]
    if scan is None:
        raise ValidationError(
            f"No finished scan of {domain} matches {ref!r}. See 'pwatch target show {domain}'."
        )
    return scan


def _load(
    repo: TenantRepo, domain: str, scan_ref: str, against_ref: str
) -> tuple[ScanSnapshot, ScanDiff]:
    row = require_target(repo, domain)
    scan = _find(repo, row.id, scan_ref, domain)
    snapshot = repo.load_snapshot(scan)
    if against_ref == "previous":
        previous = repo.previous_scan(scan)
    else:
        previous = _find(repo, row.id, against_ref, domain)
    previous_snapshot = repo.load_snapshot(previous) if previous else None
    return snapshot, compute_diff(previous_snapshot, snapshot)


def report(
    domain: Annotated[str, typer.Argument()],
    scan: Annotated[str, typer.Option("--scan", help="Scan reference, or 'latest'.")] = "latest",
    diff_against: Annotated[
        str, typer.Option("--diff-against", help="Scan to compare with, or 'previous'.")
    ] = "previous",
    formats: Annotated[str, typer.Option("--format", help="html, json, jsonl.")] = "html,json",
    out_dir: Annotated[
        Path | None, typer.Option("--out", help="Directory, or - for stdout.")
    ] = None,
    redact_personal: Annotated[
        bool, typer.Option("--redact-personal", help="Mask personal details, for sharing.")
    ] = False,
) -> None:
    """Write the report for a stored scan again, without rescanning."""
    root = domain_arg(domain)
    wanted = parse_formats(formats)
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        snapshot, diff = _load(repo, root, scan, diff_against)
        repo.audit(
            "report.generated",
            actor=actor(),
            object_type="scan",
            object_id=str(snapshot.scan_id),
            meta={"formats": wanted, "personal_redacted": redact_personal},
        )
    data = make_report(app, snapshot, diff, redact_personal=redact_personal)
    if str(out_dir) == "-":
        sys.stdout.write(render(data, wanted[0]))
        return
    print_summary(data, snapshot)
    for path in write_reports(data, wanted, out_dir, root):
        out.print(f"Report: [bold]{path}[/bold]", highlight=False)


def diff(
    domain: Annotated[str, typer.Argument()],
    from_: Annotated[str, typer.Option("--from", help="Earlier scan, or 'previous'.")] = "previous",
    to: Annotated[str, typer.Option("--to", help="Later scan, or 'latest'.")] = "latest",
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    """Show what changed between two scans."""
    root = domain_arg(domain)
    app = open_app()
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        _, result = _load(repo, root, to, from_)

    if as_json:
        sys.stdout.write(json.dumps(result.model_dump(mode="json"), indent=2) + "\n")
        return
    if result.baseline:
        out.print("Only one scan exists, so there is nothing to compare with yet.")
        return
    out.print(
        f"{len(result.new)} new, {len(result.resolved)} resolved, "
        f"{len(result.changed)} changed, {result.unchanged} unchanged, {len(result.stale)} not re-checked."
    )
    for label, style, items in (
        ("new", "red", result.new),
        ("resolved", "green", result.resolved),
        ("changed", "yellow", [c.after for c in result.changed]),
    ):
        for finding in items:
            out.print(
                f"  [{style}]{label:<9}[/] {finding.severity.label:<9} {finding.title}",
                highlight=False,
            )
    for label, assets in (
        ("appeared", result.assets_new),
        ("gone", result.assets_removed),
        ("changed", [c.after for c in result.assets_changed]),
    ):
        for asset in assets:
            out.print(f"  [dim]{label:<9}[/] {asset.type.value:<9} {asset.key}", highlight=False)
