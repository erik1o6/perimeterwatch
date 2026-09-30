"""Domains on public phishing blocklists: lookalikes, and the organisation's own names.

Each list is downloaded whole from its publisher and compared here. No lookalike
domain is ever contacted, and the organisation's name is never sent anywhere.

Sources, each read from the address its publisher documents:

MetaMask eth-phishing-detect, https://github.com/MetaMask/eth-phishing-detect
    Address: https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json
    Licence: "Don't Be A Dick" Public License (DBAD) version 1.2, copyright 2018 kumavis.
    The licence allows any use provided the work is not passed off as one's own.

polkadot-js/phishing, https://github.com/polkadot-js/phishing
    Address: https://polkadot.js.org/phishing/all.json (named in the project's README)
    Licence: Apache License 2.0
    (https://github.com/polkadot-js/phishing/blob/master/LICENSE).
    Its "allow" section names shared hosting services that must never be listed
    themselves. Names below them can still be listed, so it is matched exactly.

Phishing.Database, https://github.com/Phishing-Database/Phishing.Database
    (formerly github.com/mitchellkrogza/Phishing.Database, which now redirects there)
    Address: https://phish.co.za/latest/phishing-domains-ACTIVE.txt (the "official
    source" for the list of active phishing domains in the project's README)
    Licence: MIT, copyright 2018-2025 Mitchell Krog, Nissar Chababy and contributors
    (https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE).
    The list is about 11 MB and 400,000 lines, so it is read line by line as it
    arrives and only the lines that match are kept. It has no allow-list.

Every finding names the lists it came from, and their licences, as its source.
The lists are read, never redistributed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
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
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.modules.lookalikes import display_name
from perimeterwatch.safety.domains import registrable_domain, validate_hostname


@dataclass(frozen=True)
class Source:
    key: str  # also the cache key
    name: str
    project: str
    licence: str
    host: str
    path: str
    shape: str  # metamask | polkadot | lines

    @property
    def url(self) -> str:
        return f"https://{self.host}{self.path}"

    @property
    def attribution(self) -> str:
        return f"{self.name} ({self.project}), {self.licence}"


METAMASK = Source(
    key="metamask",
    name="MetaMask eth-phishing-detect",
    project="github.com/MetaMask/eth-phishing-detect",
    licence="DBAD licence 1.2",
    host="raw.githubusercontent.com",
    path="/MetaMask/eth-phishing-detect/main/src/config.json",
    shape="metamask",
)
POLKADOT = Source(
    key="polkadot",
    name="polkadot-js/phishing",
    project="github.com/polkadot-js/phishing",
    licence="Apache licence 2.0",
    host="polkadot.js.org",
    path="/phishing/all.json",
    shape="polkadot",
)
PHISHING_DATABASE = Source(
    key="phishing_database",
    name="Phishing.Database",
    project="github.com/Phishing-Database/Phishing.Database",
    licence="MIT licence",
    host="phish.co.za",
    path="/latest/phishing-domains-ACTIVE.txt",
    shape="lines",
)
SOURCES: tuple[Source, ...] = (METAMASK, POLKADOT, PHISHING_DATABASE)

# Kept for callers that knew the module when it read one list.
LIST_NAME = METAMASK.name
LIST_HOST = METAMASK.host
LIST_URL = METAMASK.url
ATTRIBUTION = METAMASK.attribution

CACHE_NAMESPACE = "phishing_lists"
CACHE_TTL = timedelta(hours=6)

MAX_BYTES = 30_000_000  # a list that is read whole
MAX_STREAM_BYTES = 60_000_000  # a list that is read line by line
MAX_LINE_BYTES = 1_000
MAX_ENTRIES = 1_000_000
MAX_STREAM_MATCHES = 5_000
MAX_NAME_LENGTH = 253
MAX_CANDIDATES = 5_000
MAX_BRAND_FINDINGS = 50
MAX_OWN_FINDINGS = 50
MAX_LISTED_NAMES = 5
MIN_BRAND_LENGTH = 6
TIMEOUT = httpx.Timeout(60.0, connect=10.0)

_PLAUSIBLE_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")

AGREEMENT_NOTE = (
    "Two or more blocklists that are kept separately list this domain, so it is rated "
    "one step higher."
)
OWN_DOMAIN_NOTE = (
    "Wallets and browsers that use this blocklist warn their users away from the names "
    "on it, so your own users may be told that your site is dangerous."
)


class ListUnavailable(Exception):
    """A blocklist could not be read. The message is shown to the user."""


@dataclass(frozen=True)
class Blocklist:
    blocked: tuple[str, ...]
    allowed: frozenset[str] = frozenset()  # these names only
    allowed_trees: frozenset[str] = frozenset()  # these names and every name below them
    truncated: bool = False
    total: int = 0  # names the publisher's list held, which may be more than were kept

    def allows(self, parents: list[str]) -> bool:
        if not parents:
            return False
        return parents[0] in self.allowed or any(p in self.allowed_trees for p in parents)


@dataclass(frozen=True)
class Wanted:
    """What is looked for. A listed name matches when it is one of these names or lies
    below one. Parts of names are never compared."""

    names: frozenset[str]
    brand: str | None = None

    def relevant(self, entry: str) -> bool:
        if self.brand is not None and self.brand in entry:
            return True  # only a first sieve: uses_brand decides
        return any(parent in self.names for parent in _parents(entry))

    def digest(self) -> str:
        text = "\n".join([self.brand or "", *sorted(self.names)])
        return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


def _clean(raw: Any) -> str | None:
    """A listed name in lower case, or None when it cannot be a name."""
    if not isinstance(raw, str) or len(raw) > MAX_NAME_LENGTH + 2:
        return None
    entry = raw.strip().lower().rstrip(".")
    if not 3 < len(entry) <= MAX_NAME_LENGTH:
        return None
    if not entry.isascii():
        try:
            entry = entry.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
    return entry


def _names(raw: Any, section: str) -> tuple[list[str], bool, int]:
    if not isinstance(raw, list):
        raise ListUnavailable(f"the blocklist has no usable '{section}' section")
    names = [name for name in map(_clean, raw[:MAX_ENTRIES]) if name is not None]
    return names, len(raw) > MAX_ENTRIES, len(raw)


def _json(payload: str) -> dict[str, Any]:
    try:
        data = json.loads(payload)
    except (ValueError, RecursionError) as exc:
        raise ListUnavailable("the blocklist is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ListUnavailable("the blocklist has an unexpected shape")
    return data


def parse_metamask(payload: str) -> Blocklist:
    data = _json(payload)
    blocked, truncated, total = _names(data.get("blacklist"), "blacklist")
    allowed, _, _ = _names(data.get("whitelist", []), "whitelist")
    # MetaMask's allow-list covers a name and everything below it.
    return Blocklist(
        tuple(blocked), allowed_trees=frozenset(allowed), truncated=truncated, total=total
    )


def parse_polkadot(payload: str) -> Blocklist:
    data = _json(payload)
    blocked, truncated, total = _names(data.get("deny"), "deny")
    raw_allowed = data.get("allow", [])
    if not isinstance(raw_allowed, list):
        raise ListUnavailable("the blocklist has no usable 'allow' section")
    exact: set[str] = set()
    trees: set[str] = set()
    for item in raw_allowed[:MAX_ENTRIES]:
        if isinstance(item, str) and item.startswith("*."):
            name = _clean(item[2:])
            if name is not None:
                trees.add(name)
        else:
            name = _clean(item)
            if name is not None:
                exact.add(name)
    return Blocklist(tuple(blocked), frozenset(exact), frozenset(trees), truncated, total)


def parse_list(payload: str) -> Blocklist:
    """Read MetaMask's list. Kept under this name for callers that use it."""
    return parse_metamask(payload)


def _pack(parsed: Blocklist) -> str:
    return json.dumps(
        {
            "blocked": list(parsed.blocked),
            "allowed": sorted(parsed.allowed),
            "allowed_trees": sorted(parsed.allowed_trees),
            "truncated": parsed.truncated,
            "total": parsed.total,
        },
        separators=(",", ":"),
    )


def _unpack(cached: str) -> Blocklist | None:
    try:
        data = _json(cached)
        blocked, _, _ = _names(data.get("blocked"), "blocked")
        allowed, _, _ = _names(data.get("allowed"), "allowed")
        trees, _, _ = _names(data.get("allowed_trees"), "allowed_trees")
    except ListUnavailable:
        return None  # a damaged cache entry: fetch a fresh copy
    total = data.get("total")
    return Blocklist(
        tuple(blocked),
        frozenset(allowed),
        frozenset(trees),
        bool(data.get("truncated")),
        total if isinstance(total, int) and total >= 0 else len(blocked),
    )


def _refused(status: int) -> ListUnavailable:
    return ListUnavailable(f"the blocklist could not be downloaded (HTTP {status})")


def _unreachable(exc: Exception) -> ListUnavailable:
    return ListUnavailable(f"the blocklist could not be downloaded ({type(exc).__name__})")


def _too_large() -> ListUnavailable:
    return ListUnavailable("the blocklist is larger than expected, so it was not read")


async def _read_whole(ctx: ScanContext, source: Source) -> Blocklist:
    await ctx.limiter.acquire(source.host)
    body = bytearray()
    try:
        async with ctx.http.stream("GET", source.url, timeout=TIMEOUT) as response:
            if response.status_code != 200:
                raise _refused(response.status_code)
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise _too_large()
    except (httpx.HTTPError, httpx.StreamError) as exc:
        raise _unreachable(exc) from exc
    text = body.decode("utf-8", "replace")
    return parse_polkadot(text) if source.shape == "polkadot" else parse_metamask(text)


@dataclass
class _LineScan:
    wanted: Wanted
    matched: list[str] = field(default_factory=list)
    total: int = 0
    plausible: int = 0
    truncated: bool = False

    def line(self, raw: bytes) -> None:
        text = raw.strip()
        if not text or text.startswith(b"#"):
            return
        self.total += 1
        if self.total > MAX_ENTRIES:
            self.truncated = True
            return
        entry = _clean(text.decode("utf-8", "replace"))
        if entry is None or not _PLAUSIBLE_RE.match(entry):
            return
        self.plausible += 1
        if not self.wanted.relevant(entry):
            return
        if len(self.matched) < MAX_STREAM_MATCHES:
            self.matched.append(entry)
        else:
            self.truncated = True


async def _read_lines(ctx: ScanContext, source: Source, wanted: Wanted) -> Blocklist:
    """Match a large list as it arrives. Only the lines that match are held."""
    await ctx.limiter.acquire(source.host)
    scan = _LineScan(wanted)
    size = 0
    pending = b""
    in_long_line = False
    try:
        async with ctx.http.stream("GET", source.url, timeout=TIMEOUT) as response:
            if response.status_code != 200:
                raise _refused(response.status_code)
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_STREAM_BYTES:
                    raise _too_large()
                *lines, pending = (pending + chunk).split(b"\n")
                for raw in lines:
                    if in_long_line:
                        in_long_line = False  # this is the rest of the line being dropped
                        continue
                    scan.line(raw)
                if len(pending) > MAX_LINE_BYTES:
                    pending = b""
                    in_long_line = True
    except (httpx.HTTPError, httpx.StreamError) as exc:
        raise _unreachable(exc) from exc
    if not in_long_line:
        scan.line(pending)
    if scan.total == 0 or scan.plausible * 2 < min(scan.total, MAX_ENTRIES):
        raise ListUnavailable("the blocklist did not hold a list of domain names")
    return Blocklist(tuple(scan.matched), truncated=scan.truncated, total=scan.total)


async def load(ctx: ScanContext, source: Source, wanted: Wanted) -> Blocklist:
    """One download for each list, reused from the cache until it is six hours old.

    A list that is read whole is the same for every organisation and is cached once.
    For the list that is read line by line only the matches are cached, under a key
    made from a hash of what was looked for.
    """
    key = source.key if source.shape != "lines" else f"{source.key}:{wanted.digest()}"
    cached = ctx.cache_get(CACHE_NAMESPACE, key)
    if cached is not None:
        known = _unpack(cached)
        if known is not None:
            return known
    if source.shape == "lines":
        parsed = await _read_lines(ctx, source, wanted)
    else:
        parsed = await _read_whole(ctx, source)
    ctx.cache_set(CACHE_NAMESPACE, key, _pack(parsed), CACHE_TTL)
    return parsed


async def load_list(ctx: ScanContext) -> Blocklist:
    """MetaMask's list. Kept under this name for callers that use it."""
    return await load(ctx, METAMASK, Wanted(frozenset()))


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


def _ordered(found: set[str]) -> list[Source]:
    return [source for source in SOURCES if source.key in found]


@dataclass
class _Matches:
    own: dict[str, set[str]] = field(default_factory=dict)  # own name -> list keys
    lookalike_names: dict[str, set[str]] = field(default_factory=dict)
    lookalike_lists: dict[str, set[str]] = field(default_factory=dict)
    brand: dict[str, set[str]] = field(default_factory=dict)


@register
class PhishingLists(ScanModule):
    spec = ModuleSpec(
        name="phishing_lists",
        title="Lookalike domains reported for phishing",
        category=Category.LOOKALIKE,
        mode=ScanMode.PASSIVE,
        description="Lookalike domains, domains using your name, and your own domain, "
        "where they are on a public phishing blocklist.",
        depends_on=("lookalikes",),
        contacts=(
            "raw.githubusercontent.com (MetaMask eth-phishing-detect blocklist, DBAD licence 1.2)",
            "polkadot.js.org (polkadot-js/phishing blocklist, Apache licence 2.0)",
            "phish.co.za (Phishing.Database list of active phishing domains, MIT licence)",
        ),
        default_timeout_s=300,
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
                "The lookalike search did not finish, so only your own domain, and domains "
                "on the blocklists that contain your name, were looked for."
            )
        else:
            for asset in earlier.assets[:MAX_CANDIDATES]:
                if asset.type is not AssetType.LOOKALIKE_DOMAIN:
                    continue
                name = _valid(str(asset.key))
                if name is not None and not self._own(name, domain, ctx):
                    lookalikes.add(name)
            if earlier.status is not ModuleStatus.OK or len(earlier.assets) > MAX_CANDIDATES:
                incomplete = True
                notes.append(
                    "The lookalike search was incomplete, so some lookalike domains were "
                    "not compared with the blocklists."
                )

        own = self._own_names(ctx)
        brand = brand_label(domain)
        if brand is None:
            notes.append(
                f"The blocklists were not searched for the name '{domain.split('.')[0]}': it "
                "is too short to search for without a flood of unrelated matches."
            )
        wanted = Wanted(frozenset(lookalikes | own), brand)

        loaded = await asyncio.gather(*(self._load(ctx, source, wanted) for source in SOURCES))
        failures = [
            f"{source.name}: {answer}"
            for source, answer in zip(SOURCES, loaded, strict=True)
            if isinstance(answer, str)
        ]
        if len(failures) == len(SOURCES):
            return self.result(
                ModuleStatus.FAILED,
                skip_reason=f"no blocklist could be read ({'; '.join(failures)})",
                notes=notes,
            )
        found = _Matches()
        names_read = 0
        for source, answer in zip(SOURCES, loaded, strict=True):
            if isinstance(answer, str):
                incomplete = True
                notes.append(
                    f"{source.name} was not compared this time: {answer}. Domains reported "
                    "earlier from this list are kept as not re-checked."
                )
                continue
            names_read += answer.total
            if answer.truncated:
                incomplete = True
                notes.append(
                    f"{source.name} holds more names, or more matches, than are read in one "
                    "scan. Only the first part was compared."
                )
            self._match(ctx, source, answer, wanted, lookalikes, domain, found)

        findings = [
            self._own_finding(ctx, name, found.own[name], name in own)
            for name in sorted(found.own, key=lambda n: (n.count("."), n))[:MAX_OWN_FINDINGS]
        ]
        if len(found.own) > MAX_OWN_FINDINGS:
            notes.append(
                f"{len(found.own)} of your own names are on a blocklist. "
                f"{MAX_OWN_FINDINGS} are listed."
            )
        findings.extend(
            self._finding(
                name,
                sorted(found.lookalike_names[name]),
                found.lookalike_lists[name],
                variation=True,
            )
            for name in sorted(found.lookalike_names)
        )
        brand_hits = sorted(found.brand)
        findings.extend(
            self._finding(name, [name], found.brand[name], variation=False)
            for name in brand_hits[:MAX_BRAND_FINDINGS]
        )
        if len(brand_hits) > MAX_BRAND_FINDINGS:
            notes.append(
                f"{len(brand_hits)} domains on the blocklists contain your name. "
                f"{MAX_BRAND_FINDINGS} are listed."
            )
        return self.result(
            ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={
                "blocklists_read": len(SOURCES) - len(failures),
                "blocklists_failed": len(failures),
                "blocklist_names": names_read,
                "lookalikes_compared": len(lookalikes),
                "lookalikes_listed": len(found.lookalike_names),
                "name_matches": len(brand_hits),
                "own_names_listed": len(found.own),
            },
        )

    @staticmethod
    async def _load(ctx: ScanContext, source: Source, wanted: Wanted) -> Blocklist | str:
        try:
            return await load(ctx, source, wanted)
        except ListUnavailable as exc:
            return str(exc)

    @staticmethod
    def _own_names(ctx: ScanContext) -> set[str]:
        """The scanned domain and the hosts found under it."""
        own: set[str] = set()
        for raw in [ctx.root_domain, *ctx.assets.hostnames()[:MAX_CANDIDATES]]:
            name = _valid(str(raw))
            if name is not None and ctx.in_scope(name):
                own.add(name)
        return own

    @staticmethod
    def _own(name: str, domain: str, ctx: ScanContext) -> bool:
        return ctx.in_scope(name) or name == domain or name.endswith("." + domain)

    def _match(
        self,
        ctx: ScanContext,
        source: Source,
        blocklist: Blocklist,
        wanted: Wanted,
        lookalikes: set[str],
        domain: str,
        found: _Matches,
    ) -> None:
        brand = wanted.brand
        for entry in blocklist.blocked:
            if not wanted.relevant(entry):
                continue
            name = _valid(entry)
            if name is None:
                continue
            parents = _parents(name)
            if blocklist.allows(parents):
                continue
            if ctx.in_scope(name):
                found.own.setdefault(name, set()).add(source.key)
                continue
            if self._own(name, domain, ctx):
                continue
            hit = next((parent for parent in parents if parent in lookalikes), None)
            if hit is not None:
                found.lookalike_names.setdefault(hit, set()).add(name)
                found.lookalike_lists.setdefault(hit, set()).add(source.key)
            elif brand is not None and uses_brand(name, brand):
                found.brand.setdefault(name, set()).add(source.key)

    def _finding(
        self, name: str, listed: list[str], lists: set[str], *, variation: bool
    ) -> Finding:
        sources = _ordered(lists)
        agreed = len(sources) >= 2
        return self.finding(
            "lookalike.reported_phishing",
            AssetType.LOOKALIKE_DOMAIN,
            name,
            f"{display_name(name)} is on "
            + (
                f"{len(sources)} public phishing blocklists"
                if agreed
                else "a public phishing blocklist"
            ),
            state={"lists": [s.name for s in sources]},
            evidence={
                "domain": name,
                "shown_as": display_name(name),
                "listed_names": listed[:MAX_LISTED_NAMES],
                "lists": [s.name for s in sources],
                "licences": {s.name: s.licence for s in sources},
                "also_a_registered_variation": variation,
                "why_it_is_shown": "It is a registered variation of your domain."
                if variation
                else "Its name contains your name.",
            },
            confidence=Confidence.LIKELY if variation else Confidence.CANDIDATE,
            severity_steps=1 if agreed else 0,
            severity_note=AGREEMENT_NOTE if agreed else None,
            attribution="; ".join(s.attribution for s in sources),
        )

    def _own_finding(
        self, ctx: ScanContext, name: str, lists: set[str], discovered: bool
    ) -> Finding:
        sources = _ordered(lists)
        root = name == ctx.root_domain.lower()
        return self.finding(
            "brand.own_domain_blocklisted",
            AssetType.DOMAIN if root else AssetType.SUBDOMAIN,
            name,
            f"Your own {'domain' if root else 'host'} {display_name(name)} is on a public "
            "phishing blocklist",
            state={"lists": [s.name for s in sources]},
            evidence={
                "name": name,
                "shown_as": display_name(name),
                "lists": [s.name for s in sources],
                "licences": {s.name: s.licence for s in sources},
                "where_to_ask_for_removal": {s.name: f"https://{s.project}" for s in sources},
                "found_by_this_scan": discovered,
                "why_it_matters": OWN_DOMAIN_NOTE,
            },
            confidence=Confidence.CONFIRMED,
            attribution="; ".join(s.attribution for s in sources),
        )
