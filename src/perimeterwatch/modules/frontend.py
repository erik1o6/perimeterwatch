"""Which scripts the organisation's own web pages serve, and which protective headers they send.

One ordinary request for the front page of each web host, then one request for each
script file that the same host serves. Scripts hosted elsewhere are recorded by address
only and are never fetched, because that would contact a third party.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

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
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register, skipped
from perimeterwatch.safety.targets import contactable_hosts, reported_ip_is_safe

MAX_HOSTS = 50
MAX_PAGE_BYTES = 2_000_000
MAX_SCRIPT_BYTES = 3_000_000
MAX_SCRIPTS_FETCHED = 40
MAX_SCRIPT_TAGS = 200
MAX_INLINE_CHARS = 2_000_000
MAX_REDIRECTS = 3
MAX_PATH_CHARS = 1_000
MAX_QUERY_CHARS = 500
MAX_SHOWN_CHARS = 300
MAX_INTEGRITY_FINDINGS = 25
MAX_FILES_SHOWN = 20
REQUEST_TIMEOUT_S = 30.0
HOSTS_AT_ONCE = 4

_REDIRECTS = (301, 302, 303, 307, 308)
_GONE = (404, 410)
_DEFAULT_PORT = {"http": 80, "https": 443}
_PATH_SAFE = "/%:@!$&'()*+,;=~-._"
_QUERY_SAFE = "/?%:@!$&'()*+,;=~-._"
_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_HOST_RE = re.compile(r"^[a-z0-9._\-\[\]:]+$")
_INTEGRITY_RE = re.compile(r"(?:^|\s)sha(?:256|384|512)-[A-Za-z0-9+/=_\-]{20,}")
_STRIP = "".join(chr(c) for c in range(0x21))  # C0 controls and space, as browsers strip

# Values of <script type> that browsers run. Anything else is a data block.
_SCRIPT_TYPES = frozenset(
    {
        "",
        "module",
        "importmap",
        "application/ecmascript",
        "application/javascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
    }
)

HEADER_MEANING = {
    "Strict-Transport-Security": "tells browsers to use HTTPS only, so a visitor cannot be "
    "pushed back to an unprotected connection",
    "Content-Security-Policy": "limits where scripts may be loaded from, which limits what "
    "an injected script can do",
    "X-Content-Type-Options": "stops browsers guessing file types, which can turn an "
    "uploaded file into a script",
    "X-Frame-Options or frame-ancestors": "stops other sites showing this page inside a "
    "frame to trick visitors into clicking",
}

SCRIPTS_NOTE = (
    "Any script that is added, removed or altered is reported as a change. Many sites put "
    "a build code in file names (for example app.3f9a1c.js), so every release changes this "
    "list. That is expected: match each reported change to a release. A change that no "
    "release explains needs investigating at once. Text after a question mark in a script "
    "address is ignored, because it is often only there to refresh caches. Scripts written "
    "into the page itself are compared by content, so a page that writes a different value "
    "into a script on every visit will be reported as changed at every scan."
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shown(value: str, length: int = MAX_SHOWN_CHARS) -> str:
    return "".join(ch for ch in value if ch.isprintable())[:length]


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str

    @property
    def text(self) -> str:
        return f"{self.scheme}://{self.host}"


@dataclass(frozen=True)
class Resolved:
    """Where a script address points, judged against the page it appears on."""

    kind: str  # same | other | data | ignored
    address: str = ""  # without query string or fragment
    origin: str = ""
    host: str = ""
    path: str = "/"
    query: str = ""
    digest: str = ""


@dataclass
class ScriptTag:
    src: str
    integrity: str


class ScriptParser(HTMLParser):
    """Collects script tags, the first <base href> and any policy set in a <meta> tag."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.external: list[ScriptTag] = []
        self.inline: list[str] = []  # sha256 of each inline script
        self.meta_policies: list[str] = []
        self.truncated = False
        self._buffer: list[str] | None = None
        self._buffered = 0

    @property
    def _full(self) -> bool:
        return len(self.external) + len(self.inline) >= MAX_SCRIPT_TAGS

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in ("script", "base", "meta"):
            return
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name.lower(), value or "")  # browsers keep the first
        if tag == "base":
            if self.base is None and values.get("href", "").strip(_STRIP):
                self.base = values["href"]
            return
        if tag == "meta":
            if values.get("http-equiv", "").strip().lower() == "content-security-policy":
                self.meta_policies.append(values.get("content", "")[:20_000])
            return
        self._finish_inline()
        kind = values.get("type", "").split(";")[0].strip().lower()
        if kind not in _SCRIPT_TYPES:
            return
        if self._full:
            self.truncated = True
            return
        if "src" in values:
            if values["src"].strip(_STRIP):
                self.external.append(ScriptTag(values["src"], values.get("integrity", "")))
            return
        self._buffer = []
        self._buffered = 0

    def handle_data(self, data: str) -> None:
        if self._buffer is None:
            return
        room = MAX_INLINE_CHARS - self._buffered
        if room > 0:
            self._buffer.append(data[:room])
            self._buffered += min(len(data), room)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._finish_inline()

    def close(self) -> None:
        super().close()
        self._finish_inline()  # a script that was never closed still counts

    def _finish_inline(self) -> None:
        if self._buffer is None:
            return
        text = "".join(self._buffer)
        self._buffer = None
        if text.strip():
            self.inline.append(sha256_hex(text.encode("utf-8", "replace")))


def parse_page(text: str) -> ScriptParser:
    parser = ScriptParser()
    parser.feed(text)
    parser.close()
    return parser


def _tidy(raw: str) -> str:
    """The clean-up a browser applies before reading an address."""
    value = raw.strip(_STRIP)
    return value.replace("\t", "").replace("\n", "").replace("\r", "")


def _as_browser(value: str, scheme: str) -> str:
    """Rewrite the slash and scheme forms that browsers read differently from urllib."""
    value = value.replace("\\", "/")
    match = _SCHEME_RE.match(value)
    rest = value
    if match and match.group(1).lower() in ("http", "https"):
        rest = value[match.end() :]
        if match.group(1).lower() != scheme:
            return f"{match.group(1).lower()}://{rest.lstrip('/')}"
        if not rest.startswith("//"):
            return rest  # same scheme and no host: relative to the page
        return f"{scheme}://{rest.lstrip('/')}"
    if rest.startswith("//"):
        return "//" + rest.lstrip("/")
    return rest


def resolve(page: Origin, base: str | None, raw: str) -> Resolved:
    """Work out where a script address leads, the way a browser would."""
    value = _tidy(raw)
    scheme = _SCHEME_RE.match(value)
    if scheme and scheme.group(1).lower() not in ("http", "https"):
        if scheme.group(1).lower() == "data":
            return Resolved("data", digest=sha256_hex(value.encode("utf-8", "replace")))
        return Resolved("ignored")  # javascript:, blob:, file: and so on never load a script

    root = f"{page.text}/"
    root_scheme = page.scheme
    if base is not None:
        base_value = _tidy(base)
        base_scheme = _SCHEME_RE.match(base_value)
        if base_scheme is None or base_scheme.group(1).lower() in ("http", "https"):
            try:
                joined = urljoin(root, _as_browser(base_value, page.scheme))
                found = urlsplit(joined)
                if found.scheme in ("http", "https") and found.hostname:
                    root, root_scheme = joined, found.scheme
            except ValueError:
                pass
    try:
        parts = urlsplit(urljoin(root, _as_browser(value, root_scheme)))
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return Resolved("ignored")
    if parts.scheme not in ("http", "https") or not host:
        return Resolved("ignored")

    path = quote(parts.path or "/", safe=_PATH_SAFE)
    if not path.startswith("/"):
        path = "/" + path
    query = quote(parts.query, safe=_QUERY_SAFE)
    default_port = port is None or port == _DEFAULT_PORT[parts.scheme]
    if parts.scheme == page.scheme and host == page.host and default_port:
        return Resolved(
            "same",
            address=shown(f"{page.text}{path}"),
            origin=page.text,
            host=host,
            path=path,
            query=query,
        )
    if not _HOST_RE.match(host):
        host = quote(host, safe="")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    origin = f"{parts.scheme}://{host}" + ("" if default_port else f":{port}")
    return Resolved("other", address=shown(f"{origin}{path}"), origin=shown(origin), host=host)


def has_integrity(value: str) -> bool:
    return bool(_INTEGRITY_RE.search(value))


def missing_headers(headers: httpx.Headers, scheme: str, meta_policies: list[str]) -> list[str]:
    policies = [v for v in headers.get_list("content-security-policy") if v.strip()]
    missing = []
    if scheme == "https" and not headers.get("strict-transport-security", "").strip():
        missing.append("Strict-Transport-Security")
    if not policies and not any(p.strip() for p in meta_policies):
        missing.append("Content-Security-Policy")
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    # Browsers ignore frame-ancestors when the policy comes from a <meta> tag.
    framed = any("frame-ancestors" in p.lower() for p in policies)
    if not framed and not headers.get("x-frame-options", "").strip():
        missing.append("X-Frame-Options or frame-ancestors")
    return sorted(missing)


@dataclass
class Fetched:
    origin: Origin
    status: int = 0
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    body: bytes = b""
    truncated: bool = False
    error: str = ""  # plain-language reason the answer could not be used
    elsewhere: str = ""  # a redirect that leaves the host, which is never followed


def _peer_is_safe(response: httpx.Response) -> bool:
    """Check the address actually connected to. Unknown counts as safe: the host was vetted."""
    stream = response.extensions.get("network_stream")
    if stream is None:
        return True
    try:
        peer = stream.get_extra_info("server_addr")
    except Exception:
        return True
    if not isinstance(peer, tuple) or not peer:
        return True
    return reported_ip_is_safe(str(peer[0]))


async def fetch(
    ctx: ScanContext, origin: Origin, path: str, query: str, *, limit: int, accept: str
) -> Fetched:
    """GET from the vetted host only. Redirects are followed only if they stay on it."""
    for _ in range(MAX_REDIRECTS + 1):
        target = path + (f"?{query}" if query else "")
        try:
            url = httpx.URL(scheme=origin.scheme, host=origin.host, raw_path=target.encode("ascii"))
        except (httpx.InvalidURL, UnicodeError, ValueError):
            return Fetched(origin, error="its address could not be read")
        if url.host != origin.host or url.port is not None or url.userinfo:
            return Fetched(origin, error="its address could not be read")

        await ctx.limiter.acquire(origin.host)
        got = Fetched(origin)
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_S):
                async with ctx.http.stream("GET", url, headers={"Accept": accept}) as response:
                    if not _peer_is_safe(response):
                        return Fetched(origin, error="it answered from a non-public address")
                    got.status = response.status_code
                    got.headers = response.headers
                    if response.status_code == 200:
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk)
                            if len(chunks) > limit:
                                got.truncated = True
                                break
                        got.body = bytes(chunks[:limit])
        except TimeoutError:
            return Fetched(origin, error="it took too long to answer")
        except (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError) as exc:
            return Fetched(origin, error=f"it could not be reached ({type(exc).__name__})")

        if got.status not in _REDIRECTS:
            return got
        step = resolve(origin, None, got.headers.get("location", "")[:4_000])
        if step.kind in ("data", "ignored"):
            return Fetched(origin, error="it redirected to an address that could not be read")
        upgraded = Origin("https", origin.host)
        if step.kind == "same" and len(step.path) <= MAX_PATH_CHARS:
            path, query = step.path, step.query[:MAX_QUERY_CHARS]
            continue
        if origin.scheme == "http":
            retry = resolve(upgraded, None, got.headers.get("location", "")[:4_000])
            if retry.kind == "same" and len(retry.path) <= MAX_PATH_CHARS:
                origin, path, query = upgraded, retry.path, retry.query[:MAX_QUERY_CHARS]
                continue
        got.elsewhere = step.address or "an address that could not be read"
        return got
    return Fetched(origin, error="it redirected too many times")


def decode(body: bytes, headers: httpx.Headers) -> str:
    match = re.search(r"charset=\s*[\"']?([A-Za-z0-9_\-]{1,40})", headers.get("content-type", ""))
    if match:
        try:
            return body.decode(match.group(1), "replace")
        except LookupError:
            pass
    return body.decode("utf-8", "replace")


def sort_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {json.dumps(e, sort_keys=True): e for e in entries}
    return [unique[key] for key in sorted(unique)]


@dataclass
class HostOutcome:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    incomplete: bool = False
    read: bool = False
    scripts_fetched: int = 0


@register
class Frontend(ScanModule):
    spec = ModuleSpec(
        name="frontend",
        title="Website scripts and security headers",
        category=Category.SUPPLY_CHAIN,
        mode=ScanMode.PROBE,
        description="Which scripts your web pages serve, so that a changed or added script "
        "is noticed, and which protective headers are missing.",
        depends_on=("http_probe",),
        contacts=("each of your web hosts: the front page and the script files that host serves",),
        default_timeout_s=1200,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        probe = ctx.assets.get("http_probe")
        if probe is None or not ctx.assets.completed("http_probe"):
            return skipped(
                self.spec,
                "the check that finds your web servers did not complete",
                "run the scan with the http_probe module enabled",
            )
        targets = contactable_hosts(ctx)
        allowed = set(targets.names)
        notes: list[str] = []
        hosts: dict[str, Asset] = {}
        for asset in sorted(probe.assets, key=lambda a: (a.key.count("."), a.key)):
            if asset.state.get("web") is not True:
                continue
            if asset.type not in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                continue
            if asset.key not in allowed:
                why = targets.excluded.get(asset.key, "it did not qualify for contact")
                notes.append(f"{shown(asset.key, 100)} was not contacted: {why}.")
                continue
            hosts.setdefault(asset.key, asset)
        if not hosts:
            return self.result(notes=[*notes, "No web host qualified for contact."])

        chosen = list(hosts.values())[:MAX_HOSTS]
        truncated = len(hosts) > len(chosen)
        if truncated:
            notes.append(f"Only the first {MAX_HOSTS} web hosts were read.")

        gate = asyncio.Semaphore(HOSTS_AT_ONCE)

        async def one(asset: Asset) -> HostOutcome:
            async with gate:
                return await self._host(ctx, asset)

        outcomes = await asyncio.gather(*(one(a) for a in chosen))
        findings = [f for o in outcomes for f in o.findings]
        for outcome in outcomes:
            notes.extend(outcome.notes)
        if any(f.kind == "frontend.scripts" for f in findings):
            notes.append(SCRIPTS_NOTE)
        notes.append(
            "Only the front page of each host was read. Scripts loaded by other pages, or "
            "added by another script after the page loads, are not seen."
        )
        read = sum(1 for o in outcomes if o.read)
        incomplete = truncated or any(o.incomplete for o in outcomes)
        stats = {
            "hosts": len(chosen),
            "pages_read": read,
            "scripts_fetched": sum(o.scripts_fetched for o in outcomes),
        }
        if read == 0 and any(o.incomplete for o in outcomes):
            return self.result(
                ModuleStatus.FAILED,
                skip_reason="none of your web hosts gave a page that could be read",
                notes=notes,
                stats=stats,
            )
        return self.result(
            ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats=stats,
        )

    async def _host(self, ctx: ScanContext, asset: Asset) -> HostOutcome:
        host = asset.key
        out = HostOutcome()
        start = Origin("https" if asset.state.get("https") else "http", host)
        page = await fetch(
            ctx, start, "/", "", limit=MAX_PAGE_BYTES, accept="text/html,application/xhtml+xml"
        )
        if page.error:
            out.incomplete = True
            out.notes.append(f"The front page of {host} was not read: {page.error}.")
            return out
        if page.elsewhere:
            out.notes.append(
                f"{host} sends visitors on to {page.elsewhere}. Redirects to another host "
                "are not followed, so its page was not read."
            )
            return out
        if page.status in _GONE:
            out.notes.append(f"{host} has no front page (HTTP {page.status}).")
            return out
        if page.status != 200:
            out.incomplete = True
            out.notes.append(f"The front page of {host} was not read: HTTP {page.status}.")
            return out

        out.read = True
        origin = page.origin
        address = f"{origin.text}/"
        kind = page.headers.get("content-type", "").split(";")[0].strip().lower()
        is_html = kind in ("text/html", "application/xhtml+xml", "")
        parsed = ScriptParser()
        if is_html:
            try:
                parsed = await asyncio.to_thread(parse_page, decode(page.body, page.headers))
            except Exception as exc:  # html.parser should not raise, but the input is hostile
                out.incomplete = True
                is_html = False
                out.notes.append(
                    f"The front page of {host} could not be parsed ({type(exc).__name__})."
                )
        else:
            out.notes.append(f"The front page of {host} is not a web page ({shown(kind, 60)}).")

        missing = missing_headers(page.headers, origin.scheme, parsed.meta_policies)
        if missing:
            out.findings.append(
                self.finding(
                    "http.headers.missing",
                    asset.type,
                    host,
                    f"{host} does not send {len(missing)} recommended security "
                    f"header{'s' if len(missing) != 1 else ''}",
                    state={"missing": missing},
                    evidence={
                        "page": address,
                        "missing": {name: HEADER_MEANING[name] for name in missing},
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        if not is_html:
            return out
        if page.truncated or parsed.truncated:
            out.incomplete = True
            out.notes.append(
                f"The front page of {host} is very large or has very many scripts. Only "
                "the first part was read."
            )
        await self._scripts(ctx, asset, origin, parsed, out)
        return out

    async def _scripts(
        self, ctx: ScanContext, asset: Asset, origin: Origin, parsed: ScriptParser, out: HostOutcome
    ) -> None:
        host = asset.key
        same: dict[str, Resolved] = {}
        other: dict[str, str] = {}  # address -> integrity value
        entries: list[dict[str, Any]] = [{"inline": digest} for digest in parsed.inline]
        ignored = 0
        for tag in parsed.external:
            where = resolve(origin, parsed.base, tag.src)
            if where.kind == "same":
                same.setdefault(where.address, where)
            elif where.kind == "other":
                value = shown(tag.integrity.strip(), 300) if has_integrity(tag.integrity) else ""
                # One unprotected use is enough to make the address unprotected.
                other[where.address] = value if other.get(where.address, value) else ""
            elif where.kind == "data":
                entries.append({"inline": where.digest})
            else:
                ignored += 1

        unread: list[str] = []
        for number, address in enumerate(sorted(same)):
            where = same[address]
            if number >= MAX_SCRIPTS_FETCHED:
                entries.append({"src": address, "sha256": "", "status": "not read"})
                continue
            if len(where.path) > MAX_PATH_CHARS:
                entries.append({"src": address, "sha256": "", "status": "address too long"})
                continue
            got = await fetch(
                ctx,
                origin,
                where.path,
                where.query if len(where.query) <= MAX_QUERY_CHARS else "",
                limit=MAX_SCRIPT_BYTES,
                accept="*/*",
            )
            out.scripts_fetched += 1
            if got.error:
                unread.append(f"{address}: {got.error}")
            elif got.elsewhere:
                entries.append({"src": address, "sha256": "", "redirects_to": got.elsewhere})
            elif got.status in _GONE:
                entries.append({"src": address, "sha256": "", "status": "not found"})
            elif got.status != 200:
                unread.append(f"{address}: HTTP {got.status}")
            else:
                entry: dict[str, Any] = {"src": address, "sha256": sha256_hex(got.body)}
                if got.truncated:
                    entry["status"] = "first part only"
                entries.append(entry)
        if len(same) > MAX_SCRIPTS_FETCHED:
            out.incomplete = True
            out.notes.append(
                f"{host} serves {len(same)} script files of its own. Only the first "
                f"{MAX_SCRIPTS_FETCHED} were read."
            )
        for address, integrity in other.items():
            entries.append({"src": address, "integrity": integrity})

        if unread:
            # An incomplete list would look like removed scripts, so none is reported.
            out.incomplete = True
            out.notes.append(
                f"The scripts of {host} were not recorded this time, because "
                f"{len(unread)} could not be read (first: {unread[0]})."
            )
        else:
            out.findings.append(
                self.finding(
                    "frontend.scripts",
                    asset.type,
                    host,
                    f"{host} serves {len(entries)} script{'' if len(entries) == 1 else 's'}",
                    state={"scripts": sort_entries(entries)},
                    evidence={
                        "page": f"{origin.text}/",
                        "own_script_files": len(same),
                        "scripts_written_into_the_page": len(entries) - len(same) - len(other),
                        "scripts_from_other_sites": sorted(other)[:MAX_FILES_SHOWN],
                        "addresses_that_load_nothing": ignored,
                        "base_address_set_by_page": shown(parsed.base or "", 200),
                        "note": SCRIPTS_NOTE,
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        out.findings.extend(self._no_integrity(ctx, asset, origin, other))

    def _no_integrity(
        self, ctx: ScanContext, asset: Asset, origin: Origin, other: dict[str, str]
    ) -> list[Finding]:
        by_origin: dict[str, list[str]] = {}
        for address, integrity in other.items():
            if not integrity:
                parts = urlsplit(address)
                by_origin.setdefault(f"{parts.scheme}://{parts.netloc}", []).append(address)
        findings = []
        for source in sorted(by_origin)[:MAX_INTEGRITY_FINDINGS]:
            files = sorted(by_origin[source])
            own = ctx.in_scope(urlsplit(source).hostname or "")
            findings.append(
                self.finding(
                    "frontend.script.no_integrity",
                    asset.type,
                    asset.key,
                    f"{asset.key} loads scripts from {source} without an integrity check",
                    identity={"origin": source},
                    state={"own_domain": own},
                    evidence={
                        "page": f"{origin.text}/",
                        "scripts": files[:MAX_FILES_SHOWN],
                        "script_count": len(files),
                    },
                    confidence=Confidence.CONFIRMED,
                    severity_steps=-1 if own else 0,
                    severity_note="The scripts come from another host under your own domain."
                    if own
                    else None,
                )
            )
        return findings
