"""Have I Been Pwned.

HIBP answers a domain search only for a domain that was verified in the HIBP
account the API key belongs to, so the key holder is the domain's owner. Its
terms forbid building a general breach search, which is why this provider runs
only for a domain verified here as well, and shows results to nobody else.

HIBP never returns passwords. Breach data is licensed CC BY 4.0 and must be
attributed wherever it is shown.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx

from perimeterwatch.breach.base import (
    BreachRecord,
    ProviderError,
    ProviderResult,
    ProviderUnavailable,
    StealerRecord,
)
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.safety.domains import validate_email, validate_hostname

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

HOST = "haveibeenpwned.com"
API = f"https://{HOST}/api/v3"
ATTRIBUTION = "Breach data from Have I Been Pwned (haveibeenpwned.com), licensed CC BY 4.0."
CATALOGUE_TTL = timedelta(hours=24)
MAX_RETRIES = 3


class Hibp:
    name = "hibp"
    per_person = True

    def configured(self, ctx: ScanContext) -> str | None:
        return None if ctx.secret("HIBP_API_KEY") else "missing key: HIBP_API_KEY"

    async def _get(self, ctx: ScanContext, path: str, *, keyed: bool = True) -> Any:
        headers = {}
        if keyed:
            headers["hibp-api-key"] = ctx.secret("HIBP_API_KEY") or ""
        for _attempt in range(MAX_RETRIES):
            await ctx.limiter.acquire(HOST)
            try:
                response = await ctx.http.get(f"{API}{path}", headers=headers)
            except httpx.TransportError as exc:
                raise ProviderError(
                    f"Have I Been Pwned could not be reached ({type(exc).__name__})."
                ) from exc
            if response.status_code == 429:
                try:
                    wait = min(30.0, float(response.headers.get("retry-after", "2")))
                except ValueError:
                    wait = 2.0
                await asyncio.sleep(wait)
                continue
            if response.status_code == 404:
                return None  # nothing found: the good outcome
            if response.status_code == 401:
                raise ProviderUnavailable("Have I Been Pwned rejected the key in HIBP_API_KEY.")
            if response.status_code == 403:
                raise ProviderUnavailable(
                    "Have I Been Pwned refused the request. The domain must be verified in the "
                    "HIBP account that owns the key, and the plan must cover it."
                )
            if response.status_code != 200:
                raise ProviderError(f"Have I Been Pwned answered HTTP {response.status_code}.")
            return response.json()
        raise ProviderError("Have I Been Pwned is limiting requests. Try again later.")

    async def _catalogue(self, ctx: ScanContext) -> dict[str, dict[str, Any]]:
        """Public details of every breach, by name. Needs no key."""
        cached = ctx.cache_get("hibp", "breaches")
        if cached is None:
            data = await self._get(ctx, "/breaches", keyed=False)
            rows = [
                {
                    "Name": str(b.get("Name", "")),
                    "Title": str(b.get("Title", "")),
                    "BreachDate": str(b.get("BreachDate", "")),
                    "DataClasses": [str(c) for c in b.get("DataClasses") or []],
                }
                for b in data or []
                if isinstance(b, dict)
            ]
            cached = json.dumps(rows)
            ctx.cache_set("hibp", "breaches", cached, CATALOGUE_TTL)
        return {b["Name"]: b for b in json.loads(cached)}

    async def lookup(self, domain: str, ctx: ScanContext) -> ProviderResult:
        result = ProviderResult(attribution=ATTRIBUTION)
        found = await self._get(ctx, f"/breacheddomain/{domain}")
        catalogue = await self._catalogue(ctx) if found else {}

        for alias, names in sorted((found or {}).items()):
            try:
                email = validate_email(f"{alias}@{domain}", root_domain=domain)
            except ValidationError:
                continue
            for name in names or []:
                info = catalogue.get(str(name), {})
                result.breaches.append(
                    BreachRecord(
                        email=email,
                        breach=str(info.get("Title") or name)[:120],
                        breach_date=str(info.get("BreachDate", ""))[:10],
                        data_classes=tuple(str(c)[:60] for c in info.get("DataClasses", [])[:20]),
                        source=self.name,
                    )
                )

        try:
            logs = await self._get(ctx, f"/stealerlogsbyemaildomain/{domain}")
        except ProviderUnavailable:
            result.notes.append(
                "Malware log results need a Have I Been Pwned Pro subscription, so they were "
                "not checked."
            )
        else:
            for alias, sites in sorted((logs or {}).items()):
                try:
                    email = validate_email(f"{alias}@{domain}", root_domain=domain)
                except ValidationError:
                    continue
                clean = []
                for site in sites or []:
                    try:
                        clean.append(validate_hostname(str(site), allow_reserved=True))
                    except ValidationError:
                        continue
                result.stealer_logs.append(
                    StealerRecord(
                        email=email, sites=tuple(sorted(set(clean))[:50]), source=self.name
                    )
                )
        return result
