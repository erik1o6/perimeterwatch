"""The packages the organisation publishes on npm and PyPI: who can publish them, whether
the names are still registered, and whether packages with confusingly similar names exist.

Reads the registries' public records only. Nothing is downloaded or installed.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.utils import getaddresses
from itertools import zip_longest
from typing import Any

import httpx

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    Asset,
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

NPM_HOST = "registry.npmjs.org"
NPM_DOWNLOADS_HOST = "api.npmjs.org"
PYPI_HOST = "pypi.org"

MAX_PACKAGES = 10  # per registry
MAX_VARIANTS = 60  # per package
MAX_LOOKALIKE_FINDINGS = 15  # per package
MAX_DOCUMENT_BYTES = 10_000_000
MAX_SMALL_BYTES = 1_000_000
MAX_MAINTAINERS = 50
MAX_NAME_CHARS = 214  # npm's own limit
MAX_PYPI_NAME_CHARS = 100
REQUEST_TIMEOUT_S = 30.0
RECENT = timedelta(days=90)
ABSENT_TTL = timedelta(hours=12)
CACHE_NAMESPACE = "packages.absent"

_NPM_PART = r"[A-Za-z0-9~\-][A-Za-z0-9._~\-]*"
_NPM_RE = re.compile(rf"^(?:@({_NPM_PART})/)?({_NPM_PART})$")
_PYPI_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~\-]{0,59}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_\-]{0,59}$")
_SEPARATORS = "-_."

# Characters easily mistaken or mistyped for one another.
_SIMILAR = {
    "0": "o", "1": "li", "5": "s", "a": "es", "b": "dv", "c": "k", "d": "bs", "e": "a3",
    "g": "q", "i": "l1y", "k": "c", "l": "1i", "m": "n", "n": "m", "o": "0", "q": "g",
    "r": "t", "s": "z5", "t": "r", "u": "v", "v": "u", "w": "v", "y": "i", "z": "s",
}  # fmt: skip

PYPI_LIMITS_NOTE = (
    "PyPI lists the accounts that hold a role on a project, but not when each was added, "
    "whether it uses two-factor sign-in, or which automated publishers are trusted. Check "
    "those on the project's settings page."
)
PYPI_METADATA_NOTE = (
    "PyPI did not list the accounts that can publish {name}. The names shown come from "
    "the package's own description, which its publisher writes, so they do not prove who "
    "can publish."
)
LOOKALIKE_NOTE = (
    "Packages with similar names were looked for by trying up to {limit} close spellings "
    "of each name. Other spellings are possible, so an empty result is not proof that "
    "none exists. A name found to be unregistered is not asked about again for 12 hours."
)


class RegistryError(Exception):
    """The registry could not be read. The message is plain language."""


class TooLarge(RegistryError):
    pass


def valid_npm_name(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    name = raw.strip()
    if not name or len(name) > MAX_NAME_CHARS or not _NPM_RE.match(name):
        return None
    return name


def valid_pypi_name(raw: object) -> str | None:
    """The normalised form PyPI itself uses, or None if the name breaks PyPI's rules."""
    if not isinstance(raw, str):
        return None
    name = raw.strip()
    if not name or len(name) > MAX_PYPI_NAME_CHARS or not _PYPI_RE.match(name):
        return None
    return re.sub(r"[-_.]+", "-", name).lower()


def npm_url(name: str) -> str:
    return f"https://{NPM_HOST}/{name.replace('/', '%2f')}"


def pypi_url(name: str) -> str:
    return f"https://{PYPI_HOST}/pypi/{name}/json"


def _typos(text: str) -> list[list[str]]:
    """Close misspellings, grouped by how they are made."""
    dropped = [text[:i] + text[i + 1 :] for i in range(len(text))]
    swapped = [
        text[:i] + text[i + 1] + text[i] + text[i + 2 :]
        for i in range(len(text) - 1)
        if text[i] != text[i + 1]
    ]
    doubled = [text[:i] + text[i] + text[i:] for i in range(len(text)) if text[i].isalnum()]
    replaced = [
        text[:i] + other + text[i + 1 :]
        for i in range(len(text))
        for other in _SIMILAR.get(text[i], "")
    ]
    return [dropped, swapped, doubled, replaced]


def _separator_forms(text: str) -> list[str]:
    if not any(s in text for s in _SEPARATORS):
        return []
    pattern = re.compile(r"[-_.]")
    return [pattern.sub(s, text) for s in (*_SEPARATORS, "")]


def _interleave(groups: list[list[str]]) -> list[str]:
    return [item for row in zip_longest(*groups) for item in row if item is not None]


def variants(registry: str, name: str, own: set[str], limit: int = MAX_VARIANTS) -> list[str]:
    """Names close to `name`, in a fixed order, that are valid and not the organisation's."""
    lowered = name.lower()
    match = _NPM_RE.match(lowered) if registry == "npm" else None
    groups: list[list[str]] = []
    if match and match.group(1):
        # Inside a scope only the scope's owner can publish, so the risk is a similar
        # scope, or the same name outside any scope.
        scope, bare = match.group(1), match.group(2)
        joined = [f"{scope}{s}{bare}" for s in ("-", "", "_", ".")]
        # The bare name alone is left out: "@acme/sdk" would match the unrelated "sdk".
        groups.append(joined)
        groups.append([f"@{s}/{bare}" for s in _separator_forms(scope)])
        groups.extend([f"@{s}/{bare}" for s in group] for group in _typos(scope))
        groups.extend(_typos(f"{scope}-{bare}"))
    else:
        groups.append(_separator_forms(lowered))
        groups.extend(_typos(lowered))

    validate = valid_npm_name if registry == "npm" else valid_pypi_name
    taken = {o.lower() for o in own} | {lowered, validate(lowered) or lowered}
    out: list[str] = []
    for candidate in _interleave(groups):
        checked = validate(candidate)
        if checked is None or len(checked.lstrip("@")) < 2 or checked in taken:
            continue
        taken.add(checked)
        out.append(checked)
        if len(out) >= limit:
            break
    return out


def account_names(rows: object, key: str) -> list[str]:
    """Account names only. Anything that looks like an email address is dropped."""
    names = set()
    for row in rows if isinstance(rows, list) else []:
        value = row.get(key) if isinstance(row, dict) else None
        if isinstance(value, str) and _ACCOUNT_RE.match(value.strip()):
            names.add(value.strip())
    return sorted(names)[:MAX_MAINTAINERS]


def names_from_metadata(info: dict[str, Any]) -> list[str]:
    """Display names from a PyPI description, with every email address removed."""
    found = set()
    for key in ("author", "maintainer", "author_email", "maintainer_email"):
        value = info.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        for display, address in getaddresses([value[:2_000]]):
            name = " ".join((display or ("" if "@" in address else address)).split())
            if name and "@" not in name:
                found.add(name[:80])
    return sorted(found)[:MAX_MAINTAINERS]


def version_text(value: object) -> str:
    return value if isinstance(value, str) and _VERSION_RE.match(value) else ""


def parse_date(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=utcnow().tzinfo)


@dataclass
class Record:
    """What a registry says about one package."""

    maintainers: list[str] = field(default_factory=list)
    latest: str = ""
    created: datetime | None = None
    source: str = "accounts"  # accounts | description
    roles: dict[str, str] = field(default_factory=dict)


def read_npm(document: object) -> Record:
    if not isinstance(document, dict):
        raise RegistryError("npm answered with something other than a package record")
    tags = document.get("dist-tags")
    latest = tags.get("latest") if isinstance(tags, dict) else document.get("version")
    times = document.get("time")
    created = parse_date(times.get("created")) if isinstance(times, dict) else None
    return Record(
        maintainers=account_names(document.get("maintainers"), "name"),
        latest=version_text(latest),
        created=created,
    )


def read_pypi(document: object) -> Record:
    if not isinstance(document, dict) or not isinstance(document.get("info"), dict):
        raise RegistryError("PyPI answered with something other than a package record")
    info = document["info"]
    record = Record(latest=version_text(info.get("version")))
    ownership = document.get("ownership")
    roles = ownership.get("roles") if isinstance(ownership, dict) else None
    record.maintainers = account_names(roles, "user")
    if record.maintainers:
        for row in roles if isinstance(roles, list) else []:
            if isinstance(row, dict) and row.get("user") in record.maintainers:
                record.roles[row["user"]] = str(row.get("role") or "")[:40]
    else:
        record.source = "description"
        record.maintainers = names_from_metadata(info)
    uploads = []
    releases = document.get("releases")
    for files in releases.values() if isinstance(releases, dict) else []:
        for item in files if isinstance(files, list) else []:
            when = parse_date(item.get("upload_time_iso_8601")) if isinstance(item, dict) else None
            if when is not None:
                uploads.append(when)
    record.created = min(uploads) if uploads else None
    return record


async def request(
    ctx: ScanContext, method: str, url: str, host: str, *, limit: int = MAX_SMALL_BYTES
) -> tuple[int, bytes]:
    """One request to a fixed registry host, with the answer capped in size."""
    checked = httpx.URL(url)
    if checked.host != host or checked.scheme != "https" or ".." in checked.path:
        raise RegistryError("the address built for the registry was not safe to use")
    await ctx.limiter.acquire(host)
    body = bytearray()
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_S):
            async with ctx.http.stream(
                method, checked, headers={"Accept": "application/json"}
            ) as response:
                status = response.status_code
                if method == "GET" and status == 200:
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > limit:
                            raise TooLarge(f"{host} sent more than {limit // 1_000_000} MB")
    except TimeoutError as exc:
        raise RegistryError(f"{host} took too long to answer") from exc
    except httpx.HTTPError as exc:
        raise RegistryError(f"{host} could not be reached ({type(exc).__name__})") from exc
    return status, bytes(body)


def as_json(body: bytes, host: str) -> Any:
    try:
        return json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise RegistryError(f"{host} did not answer with valid JSON") from exc


async def lookup(ctx: ScanContext, registry: str, name: str) -> Record | None:
    """The package's record, or None when the registry says it does not exist."""
    if registry == "pypi":
        status, body = await request(
            ctx, "GET", pypi_url(name), PYPI_HOST, limit=MAX_DOCUMENT_BYTES
        )
        if status == 404:
            return None
        if status != 200:
            raise RegistryError(f"PyPI answered HTTP {status}")
        return read_pypi(as_json(body, PYPI_HOST))
    try:
        status, body = await request(ctx, "GET", npm_url(name), NPM_HOST, limit=MAX_DOCUMENT_BYTES)
    except TooLarge:
        # A long release history. The record of the latest release alone is small.
        status, body = await request(ctx, "GET", f"{npm_url(name)}/latest", NPM_HOST)
    if status == 404:
        return None
    if status != 200:
        raise RegistryError(f"npm answered HTTP {status}")
    return read_npm(as_json(body, NPM_HOST))


async def exists(ctx: ScanContext, registry: str, name: str) -> bool:
    key = f"{registry}:{name}"
    if ctx.cache_get(CACHE_NAMESPACE, key) is not None:
        return False
    if registry == "npm":
        status, _ = await request(ctx, "HEAD", npm_url(name), NPM_HOST)
    else:
        status, _ = await request(ctx, "HEAD", pypi_url(name), PYPI_HOST)
    if status == 404:
        ctx.cache_set(CACHE_NAMESPACE, key, "1", ABSENT_TTL)
        return False
    if status == 200:
        return True
    where = "npm" if registry == "npm" else "PyPI"
    raise RegistryError(f"{where} answered HTTP {status}")


async def weekly_downloads(ctx: ScanContext, names: list[str]) -> dict[str, int]:
    """npm's own download counts. Best effort: a failure only leaves the figure out."""
    out: dict[str, int] = {}
    base = f"https://{NPM_DOWNLOADS_HOST}/downloads/point/last-week/"
    plain = [n for n in names if not n.startswith("@")]
    scoped = [n for n in names if n.startswith("@")]
    batches = [[n] for n in scoped] + ([plain] if plain else [])
    for batch in batches:
        try:
            status, body = await request(ctx, "GET", base + ",".join(batch), NPM_DOWNLOADS_HOST)
            data = as_json(body, NPM_DOWNLOADS_HOST) if status == 200 else None
        except RegistryError:
            continue
        if not isinstance(data, dict):
            continue
        rows = [data] if len(batch) == 1 else [data.get(n) for n in batch]
        for row in rows:
            if not isinstance(row, dict):
                continue
            count, package = row.get("downloads"), row.get("package")
            if isinstance(count, int) and not isinstance(count, bool) and package in batch:
                out[str(package)] = max(0, count)
    return out


def page_url(registry: str, name: str) -> str:
    if registry == "npm":
        return f"https://www.npmjs.com/package/{name}"
    return f"https://pypi.org/project/{name}/"


@dataclass
class Outcome:
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    problems: int = 0
    read: int = 0
    variants_checked: int = 0


@register
class Packages(ScanModule):
    spec = ModuleSpec(
        name="packages",
        title="Published packages",
        category=Category.SUPPLY_CHAIN,
        mode=ScanMode.PASSIVE,
        description="Who can publish your npm and PyPI packages, and whether packages "
        "with confusingly similar names exist.",
        contacts=("npm registry", "npm download counts", "PyPI"),
        default_timeout_s=1500,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        if not target.npm_packages and not target.pypi_packages:
            return skipped(
                self.spec,
                "no npm or PyPI packages configured for this target",
                f"pwatch target add {ctx.root_domain} --help",
            )
        out = Outcome()
        wanted = 0
        for registry, raw_names in (("npm", target.npm_packages), ("pypi", target.pypi_packages)):
            label = "npm" if registry == "npm" else "PyPI"
            validate = valid_npm_name if registry == "npm" else valid_pypi_name
            names: list[str] = []
            for raw in raw_names:
                name = validate(raw)
                if name is None:
                    out.problems += 1
                    out.notes.append(
                        f"A configured {label} package name is not a valid {label} name "
                        "and was not looked up."
                    )
                elif name not in names:
                    names.append(name)
            if len(names) > MAX_PACKAGES:
                out.problems += 1
                out.notes.append(f"Only the first {MAX_PACKAGES} {label} packages were checked.")
                names = names[:MAX_PACKAGES]
            wanted += len(names)
            own = set(names)
            for name in names:
                await self._package(ctx, registry, name, own, out)

        if out.variants_checked:
            out.notes.append(LOOKALIKE_NOTE.format(limit=MAX_VARIANTS))
        stats = {
            "packages": wanted,
            "packages_read": out.read,
            "similar_names_checked": out.variants_checked,
        }
        if out.read == 0:
            reason = out.notes[0] if out.notes else "no package could be looked up"
            return self.result(
                ModuleStatus.FAILED, skip_reason=reason, notes=out.notes, stats=stats
            )
        return self.result(
            ModuleStatus.PARTIAL if out.problems else ModuleStatus.OK,
            assets=out.assets,
            findings=out.findings,
            notes=out.notes,
            stats=stats,
        )

    async def _package(
        self, ctx: ScanContext, registry: str, name: str, own: set[str], out: Outcome
    ) -> None:
        label = "npm" if registry == "npm" else "PyPI"
        key = f"{registry}:{name}"
        try:
            record = await lookup(ctx, registry, name)
        except RegistryError as exc:
            out.problems += 1
            out.notes.append(f"{label} package {name} was not read: {exc}.")
            return
        out.read += 1
        if record is None:
            out.findings.append(
                self.finding(
                    "package.missing",
                    AssetType.PACKAGE,
                    key,
                    f"{label} has no package named {name}",
                    identity={"registry": registry},
                    evidence={"registry": label, "name": name},
                    confidence=Confidence.CONFIRMED,
                )
            )
        else:
            out.assets.append(
                self.asset(
                    AssetType.PACKAGE,
                    key,
                    attributes={
                        "registry": label,
                        "latest_version": record.latest,
                        "first_published": record.created.date().isoformat()
                        if record.created
                        else "",
                    },
                )
            )
            evidence: dict[str, Any] = {
                "registry": label,
                "name": name,
                "page": page_url(registry, name),
                "first_published": record.created.date().isoformat() if record.created else "",
            }
            if record.roles:
                evidence["roles"] = record.roles
            if registry == "pypi":
                note = (
                    PYPI_LIMITS_NOTE
                    if record.source == "accounts"
                    else PYPI_METADATA_NOTE.format(name=name)
                )
                evidence["note"] = note
                if note not in out.notes:
                    out.notes.append(note)
            who = "accounts that can publish" if record.source == "accounts" else "named authors"
            out.findings.append(
                self.finding(
                    "package.maintainers",
                    AssetType.PACKAGE,
                    key,
                    f"{label} package {name} has {len(record.maintainers)} {who}",
                    identity={"registry": registry},
                    state={
                        "maintainers": record.maintainers,
                        "latest_version": record.latest,
                        "source": record.source,
                    },
                    evidence=evidence,
                    confidence=Confidence.CONFIRMED
                    if record.source == "accounts"
                    else Confidence.LIKELY,
                )
            )
        await self._lookalikes(ctx, registry, name, own, record, out)

    async def _lookalikes(
        self,
        ctx: ScanContext,
        registry: str,
        name: str,
        own: set[str],
        record: Record | None,
        out: Outcome,
    ) -> None:
        label = "npm" if registry == "npm" else "PyPI"
        found: list[str] = []
        for candidate in variants(registry, name, own):
            try:
                out.variants_checked += 1
                if await exists(ctx, registry, candidate):
                    found.append(candidate)
            except RegistryError as exc:
                out.problems += 1
                out.notes.append(
                    f"The search for names similar to {name} on {label} stopped early: {exc}."
                )
                break
        if len(found) > MAX_LOOKALIKE_FINDINGS:
            out.problems += 1
            out.notes.append(
                f"{len(found)} packages have names similar to {name}. Only the first "
                f"{MAX_LOOKALIKE_FINDINGS} are reported."
            )
            found = found[:MAX_LOOKALIKE_FINDINGS]
        if not found:
            return
        downloads = await weekly_downloads(ctx, found) if registry == "npm" else {}
        ours = set(record.maintainers) if record and record.source == "accounts" else set()
        now = utcnow()
        for candidate in found:
            try:
                other = await lookup(ctx, registry, candidate)
            except RegistryError as exc:
                out.problems += 1
                out.notes.append(f"{label} package {candidate} exists but was not read: {exc}.")
                other = Record(source="unread")
            if other is None:
                continue  # removed between the two requests
            recent = other.created is not None and now - other.created <= RECENT
            shared = sorted(ours & set(other.maintainers)) if other.source == "accounts" else []
            evidence: dict[str, Any] = {
                "registry": label,
                "name": candidate,
                "resembles": name,
                "page": page_url(registry, candidate),
                "first_published": other.created.date().isoformat() if other.created else "",
                "latest_version": other.latest,
            }
            if candidate in downloads:
                evidence["weekly_downloads"] = downloads[candidate]
            steps, why = 0, None
            if shared:
                steps, why = -1, "An account that publishes your package also publishes this one."
                evidence["shared_publishers"] = shared
            elif recent:
                steps, why = 1, "This package was first published within the last 90 days."
            out.findings.append(
                self.finding(
                    "package.lookalike",
                    AssetType.PACKAGE,
                    f"{registry}:{candidate}",
                    f"{label} package {candidate} has a name close to your package {name}",
                    identity={"registry": registry, "resembles": name},
                    state={
                        "published_in_last_90_days": recent,
                        "shares_a_publisher": bool(shared),
                    },
                    evidence=evidence,
                    confidence=Confidence.CANDIDATE,
                    severity_steps=steps,
                    severity_note=why,
                )
            )
