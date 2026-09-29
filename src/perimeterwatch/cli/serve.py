from __future__ import annotations

import asyncio
from typing import Annotated

import typer

from perimeterwatch.cli.common import err, open_app
from perimeterwatch.core.errors import ConfigError


def _check_hosted_settings() -> None:
    app = open_app()
    s = app.settings
    if s.env == "dev":
        return
    problems = []
    if not s.base_url.startswith("https://"):
        problems.append("PW_BASE_URL must be an https:// address")
    if not s.smtp_host:
        problems.append("PW_SMTP_HOST must be set, or nobody can sign in")
    if not s.abuse_email:
        problems.append("PW_ABUSE_EMAIL must be set, so scanned hosts can reach someone")
    if problems:
        raise ConfigError("Not ready to run outside development:\n  " + "\n  ".join(problems))


def serve(
    host: Annotated[str, typer.Option("--host", help="Address to listen on.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8000,
) -> None:
    """Run the web service. Put it behind a TLS-terminating proxy in production."""
    import uvicorn

    from perimeterwatch.web.app import create_app

    _check_hosted_settings()
    app = open_app()
    if app.settings.env == "dev":
        err.print("[dim]Development mode: sign-in links are printed here instead of emailed.[/dim]")
    uvicorn.run(
        create_app(app.settings, app.database),
        host=host,
        port=port,
        log_level="warning",
        server_header=False,
        proxy_headers=app.settings.trust_proxy_headers,
        forwarded_allow_ips="*" if app.settings.trust_proxy_headers else None,
    )


def worker(
    once: Annotated[bool, typer.Option("--once", help="Do one round of work and exit.")] = False,
) -> None:
    """Run queued and scheduled scans, and send alerts."""
    from perimeterwatch.worker.runner import Worker

    _check_hosted_settings()
    app = open_app()
    runner = Worker(app.settings, app.database)
    asyncio.run(runner.tick() if once else runner.run_forever())
