"""Certificate transparency lookups through crt.sh.

crt.sh is a free community service that is often slow or overloaded. Requests
are spaced out, retried with backoff, and cached for a day.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

HOST = "crt.sh"
CACHE_TTL = timedelta(hours=24)
MAX_BYTES = 40_000_000


class CrtShUnavailable(Exception):
    pass


@dataclass(frozen=True)
class CertEntry:
    names: tuple[str, ...]
    issuer: str
    not_before: str
    not_after: str
    serial: str


def _parse(payload: str) -> list[CertEntry]:
    try:
        rows: list[dict[str, Any]] = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CrtShUnavailable("crt.sh returned a response that is not JSON") from exc
    if not isinstance(rows, list):
        raise CrtShUnavailable("crt.sh returned an unexpected response")
    entries: dict[str, CertEntry] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_names = f"{row.get('name_value', '')}\n{row.get('common_name', '') or ''}"
        names = tuple(
            sorted({n.strip().lower().rstrip(".") for n in raw_names.splitlines() if n.strip()})
        )
        serial = str(row.get("serial_number", ""))
        key = serial or "|".join(names)
        entries.setdefault(
            key,
            CertEntry(
                names=names,
                issuer=str(row.get("issuer_name", ""))[:300],
                not_before=str(row.get("not_before", "")),
                not_after=str(row.get("not_after", "")),
                serial=serial,
            ),
        )
    return list(entries.values())


async def _fetch(ctx: ScanContext, params: dict[str, str]) -> str:
    async def attempt() -> str:
        await ctx.limiter.acquire(HOST)
        response = await ctx.http.get(
            f"https://{HOST}/", params=params, timeout=httpx.Timeout(90.0, connect=15.0)
        )
        if response.status_code in (429, 500, 502, 503, 504):
            raise CrtShUnavailable(f"crt.sh answered HTTP {response.status_code}")
        if response.status_code != 200:
            raise httpx.HTTPStatusError(
                f"HTTP {response.status_code}", request=response.request, response=response
            )
        if len(response.content) > MAX_BYTES:
            raise CrtShUnavailable("crt.sh response is too large")
        return response.text

    try:
        async for retry in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential_jitter(initial=5, max=45),
            retry=retry_if_exception_type((CrtShUnavailable, httpx.TransportError)),
            reraise=False,
        ):
            with retry:
                return await attempt()
    except RetryError as exc:
        raise CrtShUnavailable("crt.sh did not answer after 3 attempts") from exc
    except httpx.HTTPStatusError as exc:
        raise CrtShUnavailable(str(exc)) from exc
    raise CrtShUnavailable("crt.sh did not answer")


async def search(
    ctx: ScanContext, query: str, *, namespace: str, exclude_expired: bool = False
) -> list[CertEntry]:
    """Certificates whose names match `query`. `%` is the wildcard."""
    cache_ns = f"crtsh:{namespace}:{'current' if exclude_expired else 'all'}"
    cached = ctx.cache_get(cache_ns, query)
    if cached is not None:
        return _parse(cached)
    params = {"q": query, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    payload = await _fetch(ctx, params)
    entries = _parse(payload)  # validate before caching
    ctx.cache_set(cache_ns, query, payload, CACHE_TTL)
    return entries
