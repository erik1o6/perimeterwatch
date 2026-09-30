"""Whether the organisation says where security problems should be reported.

One ordinary request to the organisation's own domain for the file described in
RFC 9116, https://www.rfc-editor.org/rfc/rfc9116, at /.well-known/security.txt. The
older location /security.txt is asked for only when the first does not exist.

The request is made only if the domain qualified for contact. A redirect is followed
only while it stays on the domain, or goes from the bare domain to its own www host.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    Sensitivity,
    Target,
    utcnow,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register, skipped
from perimeterwatch.modules.frontend import Origin, resolve, shown
from perimeterwatch.safety.domains import validate_hostname
from perimeterwatch.safety.targets import contactable_hosts, reported_ip_is_safe

WELL_KNOWN = "/.well-known/security.txt"
LEGACY = "/security.txt"

MAX_BODY_BYTES = 32_768
MAX_LINES = 1_000
MAX_LINE_CHARS = 2_000
MAX_VALUE_CHARS = 500
MAX_CONTACTS = 20
MAX_ADDRESSES = 10
MAX_LANGUAGES = 10
MAX_REDIRECTS = 3
MAX_PATH_CHARS = 1_000
MAX_QUERY_CHARS = 500
REQUEST_TIMEOUT_S = 30.0

_REDIRECTS = (301, 302, 303, 307, 308)
_GONE = (404, 410)
_HTML_TYPES = ("text/html", "application/xhtml+xml")

_SIGNED_START = "-----BEGIN PGP SIGNED MESSAGE-----"
_SIGNATURE_START = "-----BEGIN PGP SIGNATURE-----"
SIGNED_NOTE = (
    "The file carries an OpenPGP signature. The signature was not verified, so it is "
    "not proof of who wrote the file."
)

_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]{0,39})[ \t]*:(.*)$")
_WEB_RE = re.compile(r"^https://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{1,490}$")
_TEL_RE = re.compile(r"^tel:\+?[0-9][0-9().\-]{2,30}$")
_KEY_RE = re.compile(r"^openpgp4fpr:[0-9A-Fa-f]{40}$")
_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$&'*+/=?^_`{|}~-]{1,64}$")
_LANGUAGE_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8}){0,3}$")
_DATE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[Tt](\d{2}:\d{2}:\d{2})(?:\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$"
)

# Names that belong to a team or a function, not to a person.
ROLE_WORDS = frozenset(
    {
        "security",
        "abuse",
        "psirt",
        "cert",
        "soc",
        "bugs",
        "bugbounty",
        "disclosure",
        "vuln",
        "infosec",
        "hello",
        "contact",
        "admin",
        "support",
    }
)
# Words that often accompany a role name and say nothing about a person.
_ROLE_COMPANIONS = frozenset(
    {
        "alert",
        "alerts",
        "bounty",
        "bug",
        "csirt",
        "desk",
        "incident",
        "incidents",
        "it",
        "mail",
        "ops",
        "report",
        "reports",
        "response",
        "team",
        "vulnerabilities",
        "vulnerability",
    }
)


def is_role_address(local: str) -> bool:
    """True when the part before the @ names a role and nothing else."""
    words = [w.rstrip("0123456789") for w in re.split(r"[._+\-]", local.lower())]
    words = [w for w in words if w]
    if not any(word in ROLE_WORDS for word in words):
        return False
    return all(word in ROLE_WORDS or word in _ROLE_COMPANIONS for word in words)


def _host_ok(host: str | None) -> bool:
    if not host:
        return False
    try:
        validate_hostname(host, allow_reserved=True)
    except ValidationError:
        return False
    return True


def web_address(value: str) -> str | None:
    """An https address that is safe to show, or None."""
    if not _WEB_RE.match(value):
        return None
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        return None
    if "@" in parts.netloc or not _host_ok(parts.hostname):
        return None
    return value


def mail_address(value: str) -> tuple[str, str] | None:
    """The mailto: address as published, and the part before its @."""
    if value[:7].lower() != "mailto:":
        return None
    address = value[7:].split("?", 1)[0]
    if address.count("@") != 1:
        return None
    local, _, host = address.partition("@")
    if not _LOCAL_RE.match(local) or local.startswith(".") or local.endswith("."):
        return None
    if not _host_ok(host):
        return None
    return f"mailto:{local}@{host.lower().rstrip('.')}", local


def parse_expiry(value: str) -> datetime | None:
    match = _DATE_RE.match(value)
    if match is None:
        return None
    day, time, zone = match.groups()
    try:
        when = datetime.fromisoformat(f"{day}T{time}{'+00:00' if zone in 'Zz' else zone}")
    except ValueError:
        return None
    return when.astimezone(UTC)


def strip_signature(text: str) -> tuple[str, bool]:
    """Take the message out of an OpenPGP cleartext signature. Nothing is verified."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == _SIGNED_START), None)
    if start is None:
        return text, False
    at = start + 1
    while at < len(lines) and lines[at].strip():
        at += 1  # armour headers such as "Hash: SHA256" end at the first empty line
    message: list[str] = []
    for line in lines[at + 1 :]:
        if line.strip() == _SIGNATURE_START:
            break
        message.append(line[2:] if line.startswith("- ") else line)
    return "\n".join(message), True


@dataclass
class SecurityFile:
    contacts: list[str] = field(default_factory=list)  # in the order published
    personal: bool = False
    expires: datetime | None = None
    expires_lines: int = 0
    policy: list[str] = field(default_factory=list)
    canonical: list[str] = field(default_factory=list)
    encryption: list[str] = field(default_factory=list)
    acknowledgments: list[str] = field(default_factory=list)
    hiring: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    signed: bool = False
    fields_seen: int = 0
    lines_ignored: int = 0
    values_ignored: int = 0

    @property
    def missing(self) -> list[str]:
        absent = []
        if not self.contacts:
            absent.append("Contact")
        if self.expires is None:
            absent.append("Expires")
        return absent


def _add(values: list[str], value: str | None, limit: int, parsed: SecurityFile) -> None:
    if value is None or len(values) >= limit:
        parsed.values_ignored += 1
    elif value not in values:
        values.append(value)


def parse_file(text: str) -> SecurityFile:
    text, signed = strip_signature(text.lstrip("\ufeff"))
    parsed = SecurityFile(signed=signed)
    lines = text.splitlines()
    parsed.lines_ignored += max(0, len(lines) - MAX_LINES)
    for raw in lines[:MAX_LINES]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _FIELD_RE.match(line) if len(line) <= MAX_LINE_CHARS else None
        if match is None:
            parsed.lines_ignored += 1
            continue
        name, value = match.group(1).lower(), match.group(2).strip()
        parsed.fields_seen += 1
        if name == "expires":
            parsed.expires_lines += 1
        if not value or len(value) > MAX_VALUE_CHARS or not value.isprintable():
            parsed.values_ignored += 1
            continue
        if name == "contact":
            mail = mail_address(value)
            if mail is not None:
                before = len(parsed.contacts)
                _add(parsed.contacts, mail[0], MAX_CONTACTS, parsed)
                if len(parsed.contacts) > before and not is_role_address(mail[1]):
                    parsed.personal = True
            elif _TEL_RE.match(value.lower()):
                _add(parsed.contacts, value.lower(), MAX_CONTACTS, parsed)
            else:
                _add(parsed.contacts, web_address(value), MAX_CONTACTS, parsed)
        elif name == "expires":
            if parsed.expires is None:
                parsed.expires = parse_expiry(value)
        elif name == "policy":
            _add(parsed.policy, web_address(value), MAX_ADDRESSES, parsed)
        elif name == "canonical":
            _add(parsed.canonical, web_address(value), MAX_ADDRESSES, parsed)
        elif name == "encryption":
            key = value if _KEY_RE.match(value) else web_address(value)
            _add(parsed.encryption, key, MAX_ADDRESSES, parsed)
        elif name == "acknowledgments":
            _add(parsed.acknowledgments, web_address(value), MAX_ADDRESSES, parsed)
        elif name == "hiring":
            _add(parsed.hiring, web_address(value), MAX_ADDRESSES, parsed)
        elif name == "preferred-languages":
            for tag in value.split(",")[: MAX_LANGUAGES * 2]:
                tag = tag.strip()
                _add(
                    parsed.languages,
                    tag.lower() if _LANGUAGE_RE.match(tag) else None,
                    MAX_LANGUAGES,
                    parsed,
                )
    return parsed


def looks_like_html(body: bytes, content_type: str) -> bool:
    start = body[:4_000].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if start.startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<?xml", b"<!--")):
        return True
    if b"<html" in start or b"<body" in start:
        return True
    return content_type in _HTML_TYPES and start.startswith(b"<")


@dataclass
class Fetched:
    host: str
    path: str
    status: int = 0
    content_type: str = ""
    body: bytes = b""
    truncated: bool = False
    error: str = ""  # plain-language reason the answer could not be used
    elsewhere: str = ""  # a redirect that leaves the domain, which is never followed

    @property
    def address(self) -> str:
        return f"https://{self.host}{self.path}"


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


async def fetch(ctx: ScanContext, root: str, path: str, allowed: set[str]) -> Fetched:
    """GET from the vetted domain only, following redirects only where the rules allow."""
    origin = Origin("https", root)
    www = f"www.{root}"
    query = ""
    for _ in range(MAX_REDIRECTS + 1):
        target = path + (f"?{query}" if query else "")
        try:
            url = httpx.URL(scheme="https", host=origin.host, raw_path=target.encode("ascii"))
        except (httpx.InvalidURL, UnicodeError, ValueError):
            return Fetched(origin.host, path, error="its address could not be read")
        if url.host != origin.host or url.port is not None or url.userinfo:
            return Fetched(origin.host, path, error="its address could not be read")

        await ctx.limiter.acquire(origin.host)
        got = Fetched(origin.host, path)
        location = ""
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_S):
                async with ctx.http.stream(
                    "GET", url, headers={"Accept": "text/plain, */*;q=0.1"}
                ) as response:
                    if not _peer_is_safe(response):
                        return Fetched(
                            origin.host, path, error="it answered from a non-public address"
                        )
                    got.status = response.status_code
                    header = response.headers.get("content-type", "")
                    got.content_type = header.split(";")[0].strip().lower()[:100]
                    location = response.headers.get("location", "")[:4_000]
                    if response.status_code == 200:
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk)
                            if len(chunks) > MAX_BODY_BYTES:
                                got.truncated = True
                                break
                        got.body = bytes(chunks[:MAX_BODY_BYTES])
        except TimeoutError:
            return Fetched(origin.host, path, error="it took too long to answer")
        except (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError) as exc:
            return Fetched(
                origin.host, path, error=f"it could not be reached ({type(exc).__name__})"
            )

        if got.status not in _REDIRECTS:
            return got
        step = resolve(origin, None, location)
        if step.kind in ("data", "ignored"):
            return Fetched(
                origin.host, path, error="it redirected to an address that could not be read"
            )
        if step.kind == "same" and len(step.path) <= MAX_PATH_CHARS:
            path, query = step.path, step.query[:MAX_QUERY_CHARS]
            continue
        if origin.host == root and step.origin == f"https://{www}" and www in allowed:
            onward = resolve(Origin("https", www), None, location)
            if onward.kind == "same" and len(onward.path) <= MAX_PATH_CHARS:
                origin = Origin("https", www)
                path, query = onward.path, onward.query[:MAX_QUERY_CHARS]
                continue
        got.elsewhere = step.address or "an address that could not be read"
        return got
    return Fetched(origin.host, path, error="it redirected too many times")


@register
class SecurityContact(ScanModule):
    spec = ModuleSpec(
        name="security_contact",
        title="Where to report security problems",
        category=Category.SURFACE,
        mode=ScanMode.PROBE,
        description="Whether your domain publishes a security.txt file that tells people "
        "who find a flaw where to report it, and whether the file is complete and in date.",
        depends_on=("dns_resolve",),
        contacts=("your own domain: one request for /.well-known/security.txt",),
        default_timeout_s=180,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        if not ctx.assets.completed("dns_resolve"):
            return skipped(
                self.spec,
                "the check that looks up your hosts did not complete",
                "run the scan with the dns_resolve module enabled",
            )
        try:
            root = validate_hostname(target.root_domain, allow_reserved=True)
        except ValidationError:
            return self.result(ModuleStatus.FAILED, skip_reason="the domain is not a valid name")
        targets = contactable_hosts(ctx)
        allowed = set(targets.names)
        if root not in allowed or not ctx.in_scope(root):
            why = targets.excluded.get(root, "it has no address that could be contacted")
            return self.result(
                notes=[
                    f"{root} was not asked for a security.txt file: {why}. Nothing is "
                    "reported, because a domain without a reachable web server is not "
                    "the same as a domain without the file."
                ],
                stats={"requests": 0},
            )

        tried: list[dict[str, Any]] = []
        got = await fetch(ctx, root, WELL_KNOWN, allowed)
        tried.append(self._tried(got, WELL_KNOWN))
        location = WELL_KNOWN
        if not got.error and not got.elsewhere and got.status in _GONE:
            got = await fetch(ctx, root, LEGACY, allowed)
            tried.append(self._tried(got, LEGACY))
            location = LEGACY
            if not got.error and not got.elsewhere and got.status in _GONE:
                return self.result(
                    findings=[self._missing(root, tried, "No file exists at either location.")],
                    stats={"requests": len(tried)},
                )

        stats = {"requests": len(tried)}
        unread = ""
        if got.error:
            unread = got.error
        elif got.elsewhere:
            unread = (
                f"it sends visitors on to {got.elsewhere}, and redirects to another host "
                "are not followed"
            )
        elif got.status != 200:
            unread = f"it answered HTTP {got.status}"
        if unread:
            return self.result(
                ModuleStatus.PARTIAL,
                notes=[
                    f"The security.txt file of {root} could not be checked at {location}: "
                    f"{unread}. Anything reported earlier is kept as not re-checked."
                ],
                stats=stats,
            )
        return self._assess(root, got, location, tried, stats)

    @staticmethod
    def _tried(got: Fetched, location: str) -> dict[str, Any]:
        if got.error:
            answer = got.error
        elif got.elsewhere:
            answer = "a redirect to another host"
        else:
            answer = f"HTTP {got.status}"
        return {"location": location, "answer": answer}

    def _assess(
        self,
        root: str,
        got: Fetched,
        location: str,
        tried: list[dict[str, Any]],
        stats: dict[str, int],
    ) -> ModuleResult:
        notes: list[str] = []
        parsed = parse_file(got.body.decode("utf-8", "replace"))
        html = looks_like_html(got.body, got.content_type)
        if html or (got.content_type in _HTML_TYPES and not parsed.contacts):
            finding = self._missing(
                root, tried, f"{got.address} answers with a web page, not with the file."
            )
            return self.result(findings=[finding], stats=stats)

        used = location if location == WELL_KNOWN else f"{LEGACY} (the older location)"
        common: dict[str, Any] = {"address": shown(got.address), "location_used": used}
        if location == LEGACY:
            notes.append(
                f"The security.txt file of {root} is at the older location {LEGACY}. "
                f"Moving it to {WELL_KNOWN} is recommended."
            )
        if parsed.signed:
            common["signed"] = SIGNED_NOTE
        if got.truncated:
            notes.append(
                f"The security.txt file of {root} is larger than {MAX_BODY_BYTES // 1024} KB. "
                "Only the first part was read."
            )
            common["read_in_part"] = True
        status = ModuleStatus.PARTIAL if got.truncated else ModuleStatus.OK

        if parsed.missing:
            if got.truncated:
                # The lines may be in the part that was not read, so nothing is claimed.
                return self.result(status, notes=notes, stats=stats)
            plain = b"\x00" not in got.body and "\ufffd" not in got.body.decode("utf-8", "replace")
            finding = self.finding(
                "security.contact.invalid",
                AssetType.DOMAIN,
                root,
                f"The security.txt file of {root} has no usable {' or '.join(parsed.missing)} line",
                state={"missing": parsed.missing},
                evidence={
                    **common,
                    "missing_or_unreadable": parsed.missing,
                    "contact_lines_read": len(parsed.contacts),
                    "expires_lines_found": parsed.expires_lines,
                    "lines_that_could_not_be_read": parsed.lines_ignored + parsed.values_ignored,
                    "is_plain_text": plain,
                },
                confidence=Confidence.CONFIRMED,
            )
            return self.result(status, findings=[finding], notes=notes, stats=stats)

        findings = [self._details(root, parsed, common)]
        expires = parsed.expires
        if expires is not None and expires < utcnow():
            findings.append(
                self.finding(
                    "security.contact.expired",
                    AssetType.DOMAIN,
                    root,
                    f"The security.txt file of {root} expired on {expires.date().isoformat()}",
                    evidence={**common, "expired_on": expires.date().isoformat()},
                    confidence=Confidence.CONFIRMED,
                )
            )
        if parsed.expires_lines > 1:
            notes.append(
                f"The security.txt file of {root} has {parsed.expires_lines} Expires lines. "
                "Only one is allowed. The first was used."
            )
        return self.result(status, findings=findings, notes=notes, stats=stats)

    def _missing(self, root: str, tried: list[dict[str, Any]], what: str) -> Finding:
        return self.finding(
            "security.contact.missing",
            AssetType.DOMAIN,
            root,
            f"{root} has no security.txt file",
            evidence={"what_was_found": shown(what), "locations_tried": tried},
            confidence=Confidence.CONFIRMED,
        )

    def _details(self, root: str, parsed: SecurityFile, common: dict[str, Any]) -> Finding:
        expires = parsed.expires
        return self.finding(
            "security.contact.details",
            AssetType.DOMAIN,
            root,
            f"{root} publishes where to report security problems",
            # A change to any of these changes where reports go, or what reporters are told.
            state={
                "contacts": sorted(parsed.contacts),
                "policy": sorted(parsed.policy),
                "canonical": sorted(parsed.canonical),
            },
            evidence={
                **common,
                "contacts_in_order_of_preference": parsed.contacts,
                "policy": sorted(parsed.policy),
                "canonical": sorted(parsed.canonical),
                "expires": expires.date().isoformat() if expires is not None else "",
                "encryption_key": parsed.encryption,
                "preferred_languages": parsed.languages,
                "acknowledgments": parsed.acknowledgments,
                "lines_that_could_not_be_read": parsed.lines_ignored + parsed.values_ignored,
            },
            confidence=Confidence.CONFIRMED,
            sensitivity=Sensitivity.PERSONAL if parsed.personal else Sensitivity.NORMAL,
        )
