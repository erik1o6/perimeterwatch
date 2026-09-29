"""Lookalike domains that are on a public phishing blocklist.

The list is downloaded from its publisher and compared here. No lookalike
domain is ever contacted, and the organisation's name is never sent anywhere.

Source: MetaMask eth-phishing-detect, https://github.com/MetaMask/eth-phishing-detect
Licence: "Don't Be A Dick" Public License (DBAD) version 1.2, copyright 2018 kumavis.
The licence allows any use provided the work is not passed off as one's own, so
every finding names the list as its source. The list is read, never redistributed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register, skipped
from perimeterwatch.modules.lookalikes import display_name
from perimeterwatch.safety.domains import registrable_domain, validate_hostname

LIST_NAME = "MetaMask eth-phishing-detect"
LIST_HOST = "raw.githubusercontent.com"
LIST_URL = f"https://{LIST_HOST}/MetaMask/eth-phishing-detect/main/src/config.json"
ATTRIBUTION = f"{LIST_NAME} (github.com/MetaMask/eth-phishing-detect), DBAD licence 1.2"

CACHE_NAMESPACE = "phishing_lists"
CACHE_KEY = "metamask"
CACHE_TTL = timedelta(hours=6)

MAX_BYTES = 30_000_000
MAX_ENTRIES = 1_000_000
MAX_NAME_LENGTH = 253
MAX_BRAND_FINDINGS = 50
MAX_LISTED_NAMES = 5
MIN_BRAND_LENGTH = 6
TIMEOUT = httpx.Timeout(60.0, connect=10.0)


class ListUnavailable(Exception):
    """The blocklist could not be read. The message is shown to the user."""


@dataclass(frozen=True)
class Blocklist:
    blocked: tuple[str, ...]
    allowed: frozenset[str]
    truncated: bool = False


def _names(raw: Any, field: str) -> tuple[list[str], bool]:
    if not isinstance(raw, list):
        raise ListUnavailable(f"the blocklist has no usable '{field}' section")
    names = [
        entry.strip().lower().rstrip(".")
        for entry in raw[:MAX_ENTRIES]
        if isinstance(entry, str) and 3 < len(entry) <= MAX_NAME_LENGTH
    ]
    return names, len(raw) > MAX_ENTRIES


def parse_list(payload: str) -> Blocklist:
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise ListUnavailable("the blocklist is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ListUnavailable("the blocklist has an unexpected shape")
    blocked, truncated = _names(data.get("blacklist"), "blacklist")
    allowed, _ = _names(data.get("whitelist", []), "whitelist")
    return Blocklist(tuple(blocked), frozenset(allowed), truncated or bool(data.get("truncated")))


async def load_list(ctx: ScanContext) -> Blocklist:
    cached = ctx.cache_get(CACHE_NAMESPACE, CACHE_KEY)
    if cached is not None:
        try:
            return parse_list(cached)
        except ListUnavailable:
            pass  # A damaged cache entry: fetch a fresh copy.
    await ctx.limiter.acquire(LIST_HOST)
    try:
        async with ctx.http.stream("GET", LIST_URL, timeout=TIMEOUT) as response:
            if response.status_code != 200:
                raise ListUnavailable(
                    f"the blocklist could not be downloaded (HTTP {response.status_code})"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise ListUnavailable(
                        "the blocklist is larger than expected, so it was not read"
                    )
    except httpx.HTTPError as exc:
        raise ListUnavailable(
            f"the blocklist could not be downloaded ({type(exc).__name__})"
        ) from exc
    parsed = parse_list(body.decode("utf-8", "replace"))  # validate before caching
    # Only the two sections that are used are kept.
    compact = json.dumps(
        {
            "blacklist": list(parsed.blocked),
            "whitelist": sorted(parsed.allowed),
            "truncated": parsed.truncated,
        },
        separators=(",", ":"),
    )
    ctx.cache_set(CACHE_NAMESPACE, CACHE_KEY, compact, CACHE_TTL)
    return parsed


def _parents(name: str) -> list[str]:
    """The name itself and every name above it, down to two labels."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _valid(name: str) -> str | None:
    try:
        return validate_hostname(name, allow_reserved=True)
    except ValidationError:
        return None


def brand_label(domain: str) -> str | None:
    label = domain.split(".")[0]
    return label if len(label) >= MIN_BRAND_LENGTH else None


def uses_brand(name: str, brand: str) -> bool:
    """True when the brand is part of what was registered, or a label of its own."""
    try:
        owner = registrable_domain(name)
    except ValidationError:
        return False
    return brand in owner.split(".")[0] or brand in name.split(".")


@register
class PhishingLists(ScanModule):
    spec = ModuleSpec(
        name="phishing_lists",
        title="Lookalike domains reported for phishing",
        category=Category.LOOKALIKE,
        mode=ScanMode.PASSIVE,
        description="Lookalike domains, and domains using your name, that are on a public "
        "phishing blocklist.",
        depends_on=("lookalikes",),
        contacts=(
            "raw.githubusercontent.com (MetaMask eth-phishing-detect blocklist, DBAD licence 1.2)",
        ),
        default_timeout_s=180,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        try:
            domain = registrable_domain(target.root_domain)
        except ValidationError:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason="the domain is not under a recognised public ending",
            )
        notes: list[str] = []
        incomplete = False

        lookalikes: set[str] = set()
        earlier = ctx.assets.get("lookalikes")
        if earlier is None or not ctx.assets.completed("lookalikes"):
            incomplete = True
            notes.append(
                "The lookalike search did not finish, so only domains on the blocklist "
                "that contain your name were looked for."
            )
        else:
            for asset in earlier.assets:
                if asset.type is not AssetType.LOOKALIKE_DOMAIN:
                    continue
                name = _valid(str(asset.key))
                if name is not None and not self._own(name, domain, ctx):
                    lookalikes.add(name)
            if earlier.status is not ModuleStatus.OK:
                incomplete = True
                notes.append(
                    "The lookalike search was incomplete, so some lookalike domains were "
                    "not compared with the blocklist."
                )

        brand = brand_label(domain)
        if brand is None:
            notes.append(
                f"The blocklist was not searched for the name '{domain.split('.')[0]}': it is "
                "too short to search for without a flood of unrelated matches."
            )
        if brand is None and not lookalikes:
            return skipped(
                self.spec,
                "there are no lookalike domains to compare, and the name is too short to "
                "search the blocklist for",
            )

        try:
            blocklist = await load_list(ctx)
        except ListUnavailable as exc:
            return self.result(ModuleStatus.FAILED, skip_reason=str(exc), notes=notes)
        if blocklist.truncated:
            incomplete = True
            notes.append(
                f"The blocklist holds more than {MAX_ENTRIES} names. Only the first "
                f"{MAX_ENTRIES} were compared."
            )

        by_lookalike: dict[str, set[str]] = {}
        by_brand: set[str] = set()
        for entry in blocklist.blocked:
            parents = _parents(entry)
            if any(parent in blocklist.allowed for parent in parents):
                continue
            hit = next((parent for parent in parents if parent in lookalikes), None)
            if hit is None and (brand is None or brand not in entry):
                continue
            name = _valid(entry)
            if name is None or name != entry or self._own(name, domain, ctx):
                continue
            if hit is not None:
                by_lookalike.setdefault(hit, set()).add(name)
            elif brand is not None and uses_brand(name, brand):
                by_brand.add(name)

        findings = [
            self._finding(name, sorted(listed), variation=True)
            for name, listed in sorted(by_lookalike.items())
        ]
        brand_hits = sorted(by_brand)
        findings.extend(
            self._finding(name, [name], variation=False) for name in brand_hits[:MAX_BRAND_FINDINGS]
        )
        if len(brand_hits) > MAX_BRAND_FINDINGS:
            notes.append(
                f"{len(brand_hits)} domains on the blocklist contain your name. "
                f"{MAX_BRAND_FINDINGS} are listed."
            )
        return self.result(
            ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={
                "blocklist_names": len(blocklist.blocked),
                "lookalikes_compared": len(lookalikes),
                "lookalikes_listed": len(by_lookalike),
                "name_matches": len(brand_hits),
            },
        )

    @staticmethod
    def _own(name: str, domain: str, ctx: ScanContext) -> bool:
        return ctx.in_scope(name) or name == domain or name.endswith("." + domain)

    def _finding(self, name: str, listed: list[str], *, variation: bool) -> Finding:
        return self.finding(
            "lookalike.reported_phishing",
            AssetType.LOOKALIKE_DOMAIN,
            name,
            f"{display_name(name)} is on a public phishing blocklist",
            state={"lists": [LIST_NAME]},
            evidence={
                "domain": name,
                "shown_as": display_name(name),
                "listed_names": listed[:MAX_LISTED_NAMES],
                "blocklist": LIST_NAME,
                "also_a_registered_variation": variation,
                "why_it_is_shown": "It is a registered variation of your domain."
                if variation
                else "Its name contains your name.",
            },
            confidence=Confidence.LIKELY if variation else Confidence.CANDIDATE,
            attribution=ATTRIBUTION,
        )
