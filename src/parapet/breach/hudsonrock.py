"""Hudson Rock's free lookup: how many devices infected with credential-stealing
malware held logins for this domain. Counts only, no addresses.

Off by default. Hudson Rock publishes no terms for this endpoint, so a hosted
service should not use it without their written permission.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from parapet.breach.base import DomainSummary, ProviderError, ProviderResult

if TYPE_CHECKING:
    from parapet.core.context import ScanContext

HOST = "cavalier.hudsonrock.com"
URL = f"https://{HOST}/api/json/v2/osint-tools/search-by-domain"
ATTRIBUTION = "Malware log counts from Hudson Rock (hudsonrock.com)."


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class HudsonRock:
    name = "hudsonrock"
    per_person = False

    def configured(self, ctx: ScanContext) -> str | None:
        if not ctx.settings.hudsonrock_enabled:
            return "switched off (set PARAPET_HUDSONROCK_ENABLED=true to use it)"
        return None

    async def lookup(self, domain: str, ctx: ScanContext) -> ProviderResult:
        await ctx.limiter.acquire(HOST)
        try:
            response = await ctx.http.get(URL, params={"domain": domain})
        except httpx.TransportError as exc:
            raise ProviderError(
                f"Hudson Rock could not be reached ({type(exc).__name__})."
            ) from exc
        if response.status_code != 200:
            raise ProviderError(f"Hudson Rock answered HTTP {response.status_code}.")
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError("Hudson Rock did not answer with JSON.") from exc
        if not isinstance(data, dict):
            raise ProviderError("Hudson Rock gave an unexpected answer.")
        # Only the counts are read. Anything else in the response is ignored.
        return ProviderResult(
            summary=DomainSummary(
                source=self.name,
                employees=_count(data.get("employees")),
                users=_count(data.get("users")),
                detail={"third_parties": _count(data.get("third_parties"))},
            ),
            attribution=ATTRIBUTION,
        )
