"""Shared outbound HTTP client: one User-Agent, sane timeouts, no surprise redirects."""

from __future__ import annotations

import httpx

from perimeterwatch.branding import user_agent
from perimeterwatch.config import Settings


def make_client(settings: Settings) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={
            "User-Agent": user_agent(settings.contact_url, settings.abuse_email),
            "Accept": "application/json, text/plain;q=0.8, */*;q=0.5",
        },
        timeout=httpx.Timeout(settings.http_timeout_s, connect=10.0),
        follow_redirects=False,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        # Environment proxies could silently reroute scan traffic.
        trust_env=False,
    )
