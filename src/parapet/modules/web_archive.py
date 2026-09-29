"""Addresses on your domain that web archives remember and that look sensitive.

Asks the Internet Archive's Wayback Machine which addresses it has recorded
under the domain, and looks at the paths only. None of the addresses is ever
fetched, from the archive or from your own servers. Query strings are thrown
away before anything is stored or shown, because they can hold tokens and
personal data.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

import httpx

from parapet.core.context import ScanContext
from parapet.core.errors import ValidationError
from parapet.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from parapet.core.module import ModuleSpec, ScanModule, register
from parapet.safety.domains import validate_hostname

ARCHIVE_HOST = "web.archive.org"
ARCHIVE_URL = f"https://{ARCHIVE_HOST}/cdx/search/cdx"
CACHE_NAMESPACE = "web_archive"
CACHE_TTL = timedelta(hours=12)

ROW_LIMIT = 5000
MAX_BYTES = 20_000_000
MAX_ADDRESS_LENGTH = 2000
MAX_SHOWN_PATH = 200
MAX_SEGMENT = 32
MAX_MATCHES = 5000
MAX_FINDINGS = 100
MAX_EXAMPLES = 5
MAX_ATTEMPTS = 2
TIMEOUT = httpx.Timeout(90.0, connect=15.0)

_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~%/+-]*$")
_REMOVED = "(removed)"


class ArchiveUnavailable(Exception):
    """The archive could not be read. The message is shown to the user."""


@dataclass(frozen=True)
class Group:
    id: str
    label: str
    raise_severity: bool
    patterns: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class Listing:
    rows: int
    matches: tuple[tuple[str, str, str], ...]  # host, group id, path as shown
    capped: bool


@lru_cache(maxsize=1)
def groups() -> tuple[Group, ...]:
    raw = resources.files("parapet.data").joinpath("archive_patterns.json").read_text()
    return tuple(
        Group(
            id=str(entry["id"]),
            label=str(entry["label"]),
            raise_severity=bool(entry.get("raise", False)),
            patterns=tuple(re.compile(p) for p in entry["patterns"]),
        )
        for entry in json.loads(raw)["groups"]
    )


def group_for(path: str) -> Group | None:
    lowered = path.lower()
    for group in groups():
        if any(p.search(lowered) for p in group.patterns):
            return group
    return None


def split_address(raw: Any) -> tuple[str, str] | None:
    """(host, path) of a recorded address. The query string and fragment are dropped."""
    if not isinstance(raw, str) or not raw or len(raw) > MAX_ADDRESS_LENGTH:
        return None
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in raw):
        return None
    try:
        parts = urlsplit(raw)
        hostname = parts.hostname
        _ = parts.port  # raises for a port that is not a number in range
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not hostname:
        return None
    try:
        host = validate_hostname(hostname, allow_reserved=True)
    except ValidationError:
        return None
    # ";jsessionid=..." and the like are parameters too.
    path = parts.path.split(";", 1)[0] or "/"
    if not _SAFE_PATH_RE.match(path):
        return None
    segments = path.lower().replace("%2e", ".").split("/")
    if ".." in segments:
        return None
    return host, path


def shown_path(path: str) -> str:
    """The path as it may be displayed: long opaque parts and addresses of people removed."""
    out = []
    for segment in path.split("/"):
        stem = segment.rsplit(".", 1)[0] if "." in segment else segment
        if "%40" in segment:
            out.append(_REMOVED)
        elif len(stem) >= MAX_SEGMENT:
            ending = segment.rsplit(".", 1)[1] if "." in segment else ""
            keep = f".{ending}" if 0 < len(ending) <= 8 and "%" not in ending else ""
            out.append(_REMOVED + keep)
        else:
            out.append(segment)
    return "/".join(out)[:MAX_SHOWN_PATH]


def parse_listing(payload: str, ctx: ScanContext) -> Listing:
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise ArchiveUnavailable("the web archive did not answer with JSON") from exc
    if not isinstance(data, list):
        raise ArchiveUnavailable("the web archive gave an answer of an unexpected shape")
    rows = data[: ROW_LIMIT + 1]
    # The first row names the columns.
    if rows and rows[0] == ["original"]:
        rows = rows[1:]
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, list) or len(row) != 1:
            continue
        address = split_address(row[0])
        if address is None:
            continue
        host, path = address
        if not ctx.in_scope(host):
            continue
        group = group_for(path)
        if group is None:
            continue
        seen.add((host, group.id, shown_path(path)))
        if len(seen) >= MAX_MATCHES:
            break
    return Listing(len(rows), tuple(sorted(seen)), len(rows) >= ROW_LIMIT)


def _from_cache(cached: str, ctx: ScanContext) -> Listing | None:
    try:
        data = json.loads(cached)
        matches = tuple(
            (str(host), str(group), str(path))
            for host, group, path in data["matches"][:MAX_MATCHES]
            if ctx.in_scope(str(host))
        )
        return Listing(int(data["rows"]), matches, bool(data["capped"]))
    except (ValueError, KeyError, TypeError):
        return None


async def _fetch(ctx: ScanContext, domain: str) -> str:
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(ROW_LIMIT),
    }
    problem = "the web archive did not answer"
    for attempt in range(MAX_ATTEMPTS):
        if attempt:
            await asyncio.sleep(5.0 * attempt)
        await ctx.limiter.acquire(ARCHIVE_HOST)
        try:
            async with ctx.http.stream(
                "GET", ARCHIVE_URL, params=params, timeout=TIMEOUT
            ) as response:
                status = response.status_code
                if status in (429, 500, 502, 503, 504):
                    problem = (
                        f"the web archive is busy or unavailable at the moment (HTTP {status})"
                    )
                    continue
                if status != 200:
                    raise ArchiveUnavailable(f"the web archive answered HTTP {status}")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        raise ArchiveUnavailable(
                            "the web archive's answer was larger than expected, so it was not read"
                        )
                return body.decode("utf-8", "replace")
        except httpx.HTTPError as exc:
            problem = f"the web archive could not be reached ({type(exc).__name__})"
    raise ArchiveUnavailable(problem)


async def load_listing(ctx: ScanContext, domain: str) -> Listing:
    cached = ctx.cache_get(CACHE_NAMESPACE, domain)
    if cached is not None:
        listing = _from_cache(cached, ctx)
        if listing is not None:
            return listing
    listing = parse_listing(await _fetch(ctx, domain), ctx)
    # Only matched paths are kept, already stripped of query strings.
    ctx.cache_set(
        CACHE_NAMESPACE,
        domain,
        json.dumps(
            {"rows": listing.rows, "capped": listing.capped, "matches": listing.matches},
            separators=(",", ":"),
        ),
        CACHE_TTL,
    )
    return listing


@register
class WebArchive(ScanModule):
    spec = ModuleSpec(
        name="web_archive",
        title="Sensitive addresses in web archives",
        category=Category.SURFACE,
        mode=ScanMode.PASSIVE,
        description="Addresses on your domain, recorded by web archives, whose names suggest "
        "backups, keys, configuration or administration pages.",
        contacts=("web.archive.org (Internet Archive Wayback Machine index)",),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        try:
            domain = validate_hostname(target.root_domain, allow_reserved=True)
        except ValidationError:
            return self.result(ModuleStatus.FAILED, skip_reason="the domain name is not valid")
        try:
            listing = await load_listing(ctx, domain)
        except ArchiveUnavailable as exc:
            return self.result(ModuleStatus.FAILED, skip_reason=str(exc))

        by_group = {group.id: (rank, group) for rank, group in enumerate(groups())}
        found: dict[tuple[int, str], list[str]] = {}
        for host, group_id, path in listing.matches:
            if group_id in by_group:
                found.setdefault((by_group[group_id][0], host), []).append(path)

        notes: list[str] = []
        findings: list[Finding] = []
        for (rank, host), paths in sorted(found.items())[:MAX_FINDINGS]:
            findings.append(self._finding(host, domain, groups()[rank], sorted(set(paths))))
        if len(found) > MAX_FINDINGS:
            notes.append(
                f"{len(found)} groups of sensitive-looking addresses were found. "
                f"The first {MAX_FINDINGS} are listed."
            )
        if listing.capped:
            notes.append(
                f"The web archive holds at least {ROW_LIMIT} addresses for this domain. "
                f"Only the first {ROW_LIMIT} were looked at."
            )
        if findings:
            notes.append(
                "None of these addresses was visited. They are listed because of their names "
                "alone, so some may be harmless or long gone."
            )
        return self.result(
            ModuleStatus.PARTIAL if listing.capped else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={
                "addresses_read": listing.rows,
                "sensitive_addresses": len(listing.matches),
                "groups": len(found),
            },
        )

    def _finding(self, host: str, domain: str, group: Group, paths: list[str]) -> Finding:
        return self.finding(
            "surface.archive.sensitive_url",
            AssetType.DOMAIN if host == domain else AssetType.SUBDOMAIN,
            host,
            f"Web archives list {group.label} on {host}",
            identity={"group": group.id},
            evidence={
                "kind_of_address": group.label,
                "example_paths": paths[:MAX_EXAMPLES],
                "addresses_matched": len(paths),
                "source": "Internet Archive Wayback Machine",
                "visited": False,
            },
            confidence=Confidence.CANDIDATE,
            severity_steps=1 if group.raise_severity else 0,
            severity_note="Files of this kind often hold passwords, keys or copies of data."
            if group.raise_severity
            else None,
        )
