from __future__ import annotations

import re
from datetime import timedelta
from typing import Annotated

import typer

from parapet.cli.common import actor, open_app, out
from parapet.config import USER_CONFIG, load_settings
from parapet.core.errors import ValidationError
from parapet.core.models import utcnow
from parapet.storage import crypto
from parapet.storage.db import migrate as run_migrations
from parapet.storage.repo import Cache, TenantRepo

CONFIG_TEMPLATE = """\
# Parapet settings. Secrets do not belong here: put them in the
# environment or in a .env file.

# Where people can read about this scanner and ask questions.
# contact_url = "https://example.org/about-our-scanner"
# abuse_email = "abuse@example.org"

# Days to keep stored scans.
# retention_days = 90

# Extra DKIM selector names to look for, if your mail provider uses unusual ones.
# dkim_selectors_extra = ["myselector"]
"""


def parse_age(raw: str) -> timedelta:
    match = re.fullmatch(r"(\d{1,5})\s*([dwh])", raw.strip().lower())
    if not match:
        raise ValidationError(f"{raw!r} is not an age. Use a form like 90d, 12w or 48h.")
    number, unit = int(match.group(1)), match.group(2)
    return {
        "d": timedelta(days=number),
        "w": timedelta(weeks=number),
        "h": timedelta(hours=number),
    }[unit]


def init() -> None:
    """Create the settings file and the local database."""
    if USER_CONFIG.exists():
        out.print(f"Settings already exist: {USER_CONFIG}", highlight=False)
    else:
        USER_CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        USER_CONFIG.write_text(CONFIG_TEMPLATE)
        USER_CONFIG.chmod(0o600)
        out.print(f"Wrote settings: {USER_CONFIG}", highlight=False)
    app = open_app()
    out.print(f"Database ready: {app.database.url.removeprefix('sqlite:///')}", highlight=False)
    out.print("Next: [bold]parapet doctor[/bold], then [bold]parapet scan YOUR-DOMAIN[/bold]")


def migrate() -> None:
    """Bring the database schema up to date."""
    settings = load_settings()
    settings.ensure_data_dir()
    run_migrations(settings.resolved_database_url)
    out.print("Database is up to date.")


def purge(
    older_than: Annotated[
        str | None,
        typer.Option("--older-than", help="Age such as 90d. Defaults to the retention setting."),
    ] = None,
) -> None:
    """Delete stored scans past their retention period.

    The most recent scan of each domain is always kept, so comparisons still work.
    """
    app = open_app()
    age = parse_age(older_than) if older_than else timedelta(days=app.settings.retention_days)
    with app.database.session() as session:
        repo = TenantRepo.local(session)
        removed = repo.purge_scans_before(utcnow() - age)
        Cache(session).purge_expired()
        repo.audit("retention.purged", actor=actor(), object_type="scan", meta={"removed": removed})
    out.print(f"Deleted {removed} scan(s) older than {age.days or 0} day(s).")


def new_key() -> None:
    """Print a new data encryption key for PARAPET_DATA_KEYS."""
    out.print(crypto.new_key(), highlight=False)
