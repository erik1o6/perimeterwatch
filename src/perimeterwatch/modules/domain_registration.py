"""The domain's registration record: expiry, transfer lock, registrar and nameservers.

Reads the public registration record (RDAP) kept by the registry of the
domain's ending. The right server is found in the list IANA publishes. Only
IANA and servers named in that list are ever contacted.

Registration records can hold contact details of the person who registered
the domain. Those parts of the answer are never read, stored or shown: only
the registrar's company name, the nameservers, the status list and the
registration and expiry dates are taken.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

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
    utcnow,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register, skipped
from perimeterwatch.safety.domains import registrable_domain, validate_hostname

BOOTSTRAP_HOST = "data.iana.org"
BOOTSTRAP_URL = f"https://{BOOTSTRAP_HOST}/rdap/dns.json"
BOOTSTRAP_TTL = timedelta(hours=24)
CACHE_NAMESPACE = "rdap"
CACHE_KEY = "bootstrap"

MAX_BOOTSTRAP_BYTES = 2_000_000
MAX_RECORD_BYTES = 1_000_000
MAX_SERVICES = 5000
MAX_REDIRECTS = 3
MAX_ATTEMPTS = 2
MAX_NAMESERVERS = 20
MAX_STATUSES = 30
MAX_ENTITIES = 20
MAX_EVENTS = 50
MAX_REGISTRAR_LENGTH = 100
TIMEOUT = httpx.Timeout(20.0, connect=10.0)

# Longest first: the first limit the remaining time fits under is the bucket.
BUCKETS = ((7, "7d"), (14, "14d"), (30, "30d"), (60, "60d"))
URGENT_BUCKETS = ("7d", "14d")

# Any of these in the status list means the domain cannot simply be moved away.
LOCK_STATUSES = frozenset(
    {
        "client transfer prohibited",
        "server transfer prohibited",
        "transfer prohibited",
        "locked",
    }
)

_STATUS_RE = re.compile(r"^[a-z][a-z ]{0,39}$")
_TLD_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_REGISTRAR_ID_RE = re.compile(r"^[0-9]{1,8}$")
_REGISTRAR_EXTRA_CHARS = frozenset(" .,&-()/+")


class RdapError(Exception):
    """The registration record could not be read. The message is shown to the user."""


@dataclass(frozen=True)
class Bootstrap:
    """Which server holds the records for which ending, and every host IANA lists."""

    servers: dict[str, tuple[str, ...]]
    hosts: frozenset[str]

    def servers_for(self, domain: str) -> tuple[str, ...]:
        """Servers for the longest ending of `domain` that IANA lists."""
        labels = domain.split(".")
        for start in range(1, len(labels)):
            found = self.servers.get(".".join(labels[start:]))
            if found:
                return found
        return ()


@dataclass(frozen=True)
class Registration:
    registrar: str | None
    registrar_id: str | None
    nameservers: tuple[str, ...]
    statuses: tuple[str, ...]
    registered: datetime | None
    expires: datetime | None


def expiry_bucket(expires: datetime, now: datetime) -> str | None:
    days = (expires - now).total_seconds() / 86400
    if days < 0:
        return "expired"
    for limit, label in BUCKETS:
        if days <= limit:
            return label
    return None


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def clean_registrar(value: Any) -> str | None:
    """A registrar's company name, reduced to letters, digits and plain punctuation."""
    if not isinstance(value, str):
        return None
    kept = "".join(ch for ch in value[:400] if ch.isalnum() or ch in _REGISTRAR_EXTRA_CHARS)
    name = " ".join(kept.split())[:MAX_REGISTRAR_LENGTH].strip()
    return name or None


def _server_url(raw: Any) -> tuple[str, str] | None:
    """(base address ending in '/', host) for a usable server, or None.

    Servers offered only over an unencrypted connection are not usable: the
    answer could be altered on the way.
    """
    if not isinstance(raw, str) or len(raw) > 200:
        return None
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username or parts.password or parts.query:
        return None
    if parts.fragment or port not in (None, 443) or not parts.hostname:
        return None
    try:
        host = validate_hostname(parts.hostname)
    except ValidationError:
        return None
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    if not re.fullmatch(r"/[A-Za-z0-9._~/-]{0,100}", path) or ".." in path:
        return None
    return f"https://{host}{path}", host


def parse_bootstrap(payload: str) -> Bootstrap:
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise RdapError("the list of registration servers from IANA is not valid JSON") from exc
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, list):
        raise RdapError("the list of registration servers from IANA has an unexpected shape")

    servers: dict[str, tuple[str, ...]] = {}
    hosts: set[str] = set()
    for service in services[:MAX_SERVICES]:
        if not isinstance(service, list) or len(service) < 2:
            continue
        endings, urls = service[0], service[1]
        if not isinstance(endings, list) or not isinstance(urls, list):
            continue
        usable = [u for u in (_server_url(raw) for raw in urls[:10]) if u is not None]
        hosts.update(host for _, host in usable)
        for ending in endings[:2000]:
            if not isinstance(ending, str):
                continue
            key = ending.strip().lower().strip(".")
            if len(key) <= 253 and _TLD_RE.match(key):
                # Listed endings with no usable server are kept, with no servers,
                # so the skip reason can say why.
                servers.setdefault(key, tuple(url for url, _ in usable))
    if not servers:
        raise RdapError("the list of registration servers from IANA is empty")
    return Bootstrap(servers, frozenset(hosts))


def _registrar(entities: Any) -> tuple[str | None, str | None]:
    """Name and IANA number of the registrar. Every other entity is left unread."""
    if not isinstance(entities, list):
        return None, None
    for entity in entities[:MAX_ENTITIES]:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrar" not in roles:
            # Registrant, administrative and technical contacts are personal data.
            continue
        name: str | None = None
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            for field in vcard[1][:40]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    name = clean_registrar(field[3])
                    break
        number: str | None = None
        public_ids = entity.get("publicIds")
        if isinstance(public_ids, list):
            for item in public_ids[:10]:
                if not isinstance(item, dict) or item.get("type") != "IANA Registrar ID":
                    continue
                identifier = str(item.get("identifier", ""))
                if _REGISTRAR_ID_RE.match(identifier):
                    number = identifier
                break
        return name, number
    return None, None


def parse_record(payload: str, domain: str) -> Registration:
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise RdapError("the registry did not answer with JSON") from exc
    if not isinstance(data, dict) or data.get("objectClassName") != "domain":
        raise RdapError("the registry's answer is not a domain record")
    try:
        named = validate_hostname(str(data.get("ldhName", "")), allow_reserved=True)
    except ValidationError:
        named = ""
    if named != domain:
        raise RdapError("the registry answered about a different domain, so the answer was discarded")  # fmt: skip

    statuses: set[str] = set()
    raw_statuses = data.get("status")
    if isinstance(raw_statuses, list):
        for raw in raw_statuses[:MAX_STATUSES]:
            if isinstance(raw, str):
                status = " ".join(raw.lower().split())
                if _STATUS_RE.match(status):
                    statuses.add(status)

    nameservers: set[str] = set()
    raw_servers = data.get("nameservers")
    if isinstance(raw_servers, list):
        for raw in raw_servers[:MAX_NAMESERVERS]:
            if not isinstance(raw, dict):
                continue
            try:
                nameservers.add(validate_hostname(str(raw.get("ldhName", "")), allow_reserved=True))
            except ValidationError:
                continue

    dates: dict[str, datetime] = {}
    raw_events = data.get("events")
    if isinstance(raw_events, list):
        for raw in raw_events[:MAX_EVENTS]:
            if not isinstance(raw, dict):
                continue
            action = raw.get("eventAction")
            if action in ("registration", "expiration") and action not in dates:
                moment = parse_time(raw.get("eventDate"))
                if moment is not None:
                    dates[action] = moment

    registrar, registrar_id = _registrar(data.get("entities"))
    return Registration(
        registrar=registrar,
        registrar_id=registrar_id,
        nameservers=tuple(sorted(nameservers)),
        statuses=tuple(sorted(statuses)),
        registered=dates.get("registration"),
        expires=dates.get("expiration"),
    )


async def _get(ctx: ScanContext, url: str, host: str, limit: int) -> tuple[int, str, str | None]:
    """(status, body, redirect target). Stops reading once the body passes `limit`."""
    await ctx.limiter.acquire(host)
    headers = {"Accept": "application/rdap+json, application/json"}
    async with ctx.http.stream("GET", url, headers=headers, timeout=TIMEOUT) as response:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > limit:
                raise RdapError("the answer was larger than expected, so it was not read")
        return (
            response.status_code,
            body.decode("utf-8", "replace"),
            response.headers.get("location"),
        )


async def load_bootstrap(ctx: ScanContext) -> Bootstrap:
    cached = ctx.cache_get(CACHE_NAMESPACE, CACHE_KEY)
    if cached is not None:
        try:
            return parse_bootstrap(cached)
        except RdapError:
            pass  # A damaged cache entry: fetch a fresh copy.
    try:
        status, body, _ = await _get(ctx, BOOTSTRAP_URL, BOOTSTRAP_HOST, MAX_BOOTSTRAP_BYTES)
    except httpx.HTTPError as exc:
        raise RdapError(
            f"the list of registration servers could not be fetched from IANA ({type(exc).__name__})"
        ) from exc
    if status != 200:
        raise RdapError(f"IANA answered HTTP {status} for the list of registration servers")
    bootstrap = parse_bootstrap(body)  # validate before caching
    ctx.cache_set(CACHE_NAMESPACE, CACHE_KEY, body, BOOTSTRAP_TTL)
    return bootstrap


async def fetch_record(ctx: ScanContext, base: str, domain: str, bootstrap: Bootstrap) -> str:
    url = f"{base}domain/{domain}"
    for _ in range(MAX_REDIRECTS + 1):
        host = urlsplit(url).hostname or ""
        status, body, location = await _fetch_with_retry(ctx, url, host)
        if status in (301, 302, 303, 307, 308):
            url = _redirect_target(url, location, bootstrap)
            continue
        if status == 404:
            raise RdapError(f"the registry has no registration record for {domain}")
        if status == 429:
            raise RdapError("the registry is limiting requests at the moment. Try again later")
        if status != 200:
            raise RdapError(f"the registry answered HTTP {status}")
        return body
    raise RdapError("the registry redirected too many times")


async def _fetch_with_retry(ctx: ScanContext, url: str, host: str) -> tuple[int, str, str | None]:
    last: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        if attempt:
            await asyncio.sleep(2.0 * attempt)
        try:
            status, body, location = await _get(ctx, url, host, MAX_RECORD_BYTES)
        except httpx.HTTPError as exc:
            last = exc
            continue
        if status in (500, 502, 503, 504) and attempt + 1 < MAX_ATTEMPTS:
            continue
        return status, body, location
    raise RdapError(f"the registry could not be reached ({type(last).__name__})") from last


def _redirect_target(current: str, location: str | None, bootstrap: Bootstrap) -> str:
    """Where a redirect leads, if that is a server IANA lists. Otherwise an error."""
    refused = RdapError(
        "the registry redirected to a server that IANA does not list, so it was not followed"
    )
    if not location or len(location) > 500:
        raise refused
    try:
        target = httpx.URL(current).join(location)
    except (httpx.InvalidURL, ValueError) as exc:
        raise refused from exc
    if target.scheme != "https" or target.userinfo or target.port not in (None, 443):
        raise refused
    if target.host.lower() not in bootstrap.hosts:
        raise refused
    return str(target.copy_with(fragment=None))


@register
class DomainRegistration(ScanModule):
    spec = ModuleSpec(
        name="domain_registration",
        title="Domain registration",
        category=Category.SURFACE,
        mode=ScanMode.PASSIVE,
        description="When your domain expires, whether it is locked against transfer, "
        "and who its registrar and nameservers are.",
        contacts=(
            "data.iana.org (the list of registration record servers)",
            "the registry's public registration record server (RDAP)",
        ),
        default_timeout_s=120,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        try:
            domain = validate_hostname(registrable_domain(target.root_domain), allow_reserved=True)
        except ValidationError:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason="the domain is not under a recognised public ending",
            )
        try:
            bootstrap = await load_bootstrap(ctx)
        except RdapError as exc:
            return self.result(ModuleStatus.FAILED, skip_reason=str(exc))

        ending = domain.split(".", 1)[1]
        servers = bootstrap.servers_for(domain)
        if not servers:
            return skipped(
                self.spec,
                f"the registry for .{ending} does not offer registration records in a form "
                "that can be read securely (RDAP over HTTPS), so expiry and lock status "
                "could not be checked",
                hint="Check the expiry date and transfer lock in your registrar's control panel.",
            )

        try:
            payload = await fetch_record(ctx, servers[0], domain, bootstrap)
            record = parse_record(payload, domain)
        except RdapError as exc:
            return self.result(ModuleStatus.FAILED, skip_reason=str(exc))

        notes: list[str] = []
        findings = [self._details(domain, record)]
        findings.extend(self._expiry(domain, record, utcnow(), notes))
        if not record.statuses:
            notes.append(
                "The registry does not publish the status of this domain, so the transfer "
                "lock could not be checked."
            )
        elif not LOCK_STATUSES.intersection(record.statuses):
            findings.append(
                self.finding(
                    "domain.registration.unlocked",
                    AssetType.DOMAIN,
                    domain,
                    f"{domain} is not locked against being transferred away",
                    evidence={
                        "status": list(record.statuses),
                        "missing": "client transfer prohibited",
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        return self.result(
            findings=findings,
            notes=notes,
            stats={"nameservers": len(record.nameservers), "findings": len(findings)},
        )

    def _details(self, domain: str, record: Registration) -> Finding:
        state = {
            "registrar": record.registrar,
            "nameservers": list(record.nameservers),
            "status": list(record.statuses),
        }
        registrar = record.registrar or "an unnamed registrar"
        return self.finding(
            "domain.registration.details",
            AssetType.DOMAIN,
            domain,
            f"{domain} is registered through {registrar}",
            state=state,
            evidence={
                **state,
                "registrar_iana_id": record.registrar_id,
                "registered_on": record.registered.date().isoformat()
                if record.registered
                else None,
                "expires_on": record.expires.date().isoformat() if record.expires else None,
            },
            confidence=Confidence.CONFIRMED,
        )

    def _expiry(
        self, domain: str, record: Registration, now: datetime, notes: list[str]
    ) -> list[Finding]:
        if record.expires is None:
            notes.append(
                "The registry does not publish an expiry date for this domain, so expiry "
                "could not be checked."
            )
            return []
        bucket = expiry_bucket(record.expires, now)
        day = record.expires.date().isoformat()
        if bucket == "expired":
            return [
                self.finding(
                    "domain.registration.expired",
                    AssetType.DOMAIN,
                    domain,
                    f"The registration of {domain} has run out",
                    evidence={"expired_on": day, "registrar": record.registrar},
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if bucket is None:
            return []
        urgent = bucket in URGENT_BUCKETS
        return [
            self.finding(
                "domain.registration.expiring",
                AssetType.DOMAIN,
                domain,
                f"The registration of {domain} runs out within {bucket[:-1]} days",
                state={"bucket": bucket},
                evidence={"expires_on": day, "registrar": record.registrar},
                confidence=Confidence.CONFIRMED,
                severity_steps=1 if urgent else 0,
                severity_note="Two weeks or less remain before the domain lapses."
                if urgent
                else None,
            )
        ]
