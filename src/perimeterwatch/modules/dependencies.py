"""The outside services a domain relies on, kept as one list so changes stand out.

Every entry comes from something an earlier module already collected in this
scan: DNS aliases, nameservers, mail servers, the SPF record, the content
delivery network, scripts loaded from other sites and certificate issuers.
This module sends nothing to any host and makes no lookups of its own.

The list holds names only, never addresses, so a provider rotating its
addresses does not look like a change.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.modules.spf_chain import parse_terms
from perimeterwatch.safety.domains import registrable_domain, validate_hostname

ROLES = ("dns", "mail", "mail_sending", "cdn", "hosting", "scripts", "certificates", "other")

MAX_ITEMS_PER_SOURCE = 500
MAX_SERVICES = 150
MAX_REVEALED_BY = 5
MAX_SPF_CHARS = 4096
MAX_NAME_CHARS = 60
MAX_ADDRESS_CHARS = 2000

# What each source module contributes, in words for the notes.
SOURCES: dict[str, tuple[str, str]] = {
    "dns_resolve": ("DNS resolution", "services your hostnames are aliases for"),
    "domain_registration": ("the domain registration check", "your nameserver provider"),
    "email_posture": ("the email check", "your mail provider and the senders in your SPF record"),
    "http_probe": ("the web server check", "your content delivery network"),
    "tls_certs": ("the certificate check", "your certificate issuers"),
    "frontend": ("the website script check", "scripts loaded from other sites"),
}

# Names the web server check gives to delivery networks, and who they are.
_CDN_NAMES = {
    "cloudflare": "Cloudflare",
    "cloudfront": "Amazon CloudFront",
    "amazon": "Amazon CloudFront",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "incapsula": "Imperva",
    "imperva": "Imperva",
    "sucuri": "Sucuri",
    "bunny": "Bunny",
    "azure": "Microsoft Azure",
    "google": "Google Cloud",
    "vercel": "Vercel",
    "netlify": "Netlify",
}

# Issuer names change as authorities rotate their signing certificates, so each
# is reduced to the organisation behind it.
_ISSUERS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in (
        (r"let'?s encrypt|^(R|E|YR|YE)\d{1,2}$", "Let's Encrypt"),
        (r"^GTS\b|google trust services|^(WR|WE)\d{1,2}$", "Google Trust Services"),
        (r"^amazon\b", "Amazon Trust Services"),
        (r"cloudflare", "Cloudflare"),
        (r"digicert|geotrust|rapidssl|thawte", "DigiCert"),
        (r"sectigo|comodo|usertrust", "Sectigo"),
        (r"zerossl", "ZeroSSL"),
        (r"globalsign", "GlobalSign"),
        (r"go ?daddy|starfield", "GoDaddy"),
        (r"entrust", "Entrust"),
        (r"buypass", "Buypass"),
        (r"^microsoft\b", "Microsoft"),
        (r"ssl\.com", "SSL.com"),
    )
)

_NAME_RE = re.compile(r"[^A-Za-z0-9 .'_-]")
_IPV4_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_IPV6_RE = re.compile(r"[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,}", re.IGNORECASE)

EXPLANATION = (
    "Each service listed is an outside party your domain depends on. A service that "
    "appears or disappears between scans is reported as a change. Match each change to "
    "something your team did. One that nobody can explain needs looking into."
)


@dataclass(frozen=True)
class ServiceTable:
    domains: dict[str, tuple[str, str]]
    patterns: tuple[tuple[re.Pattern[str], str, str], ...]


@lru_cache(maxsize=1)
def service_table() -> ServiceTable:
    raw = resources.files("perimeterwatch.data").joinpath("service_names.json").read_text()
    data = json.loads(raw)
    domains = {
        str(e["domain"]).lower(): (str(e["service"]), str(e.get("usual_role", "other")))
        for e in data["services"]
    }
    patterns = tuple(
        (re.compile(str(e["pattern"])), str(e["service"]), str(e.get("usual_role", "other")))
        for e in data.get("patterns", [])
    )
    return ServiceTable(domains, patterns)


def service_for(domain: str) -> tuple[str, str | None]:
    """The service that operates a registrable domain, and what it is usually for.

    A domain that is not in the table is listed under its own name.
    """
    table = service_table()
    known = table.domains.get(domain)
    if known is not None:
        return known
    for pattern, service, role in table.patterns:
        if pattern.search(domain):
            return service, role
    return domain, None


def clean_label(raw: Any) -> str | None:
    """A short display name, or None when it is empty or looks like an address."""
    if not isinstance(raw, str):
        return None
    start = raw[:300]
    if _IPV4_RE.search(start) or _IPV6_RE.search(start):
        return None
    text = " ".join(_NAME_RE.sub("", start).split())[:MAX_NAME_CHARS].strip()
    return text or None


def issuer_name(raw: Any) -> str | None:
    label = clean_label(raw)
    if label is None:
        return None
    for pattern, name in _ISSUERS:
        if pattern.search(label):
            return name
    return label


@dataclass
class Found:
    """Services seen so far: (role, service) -> the records that revealed it."""

    entries: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    dropped: int = 0

    def add(self, role: str, service: str, revealed_by: str) -> None:
        if role not in ROLES:
            role = "other"
        key = (role, service)
        if key not in self.entries:
            if len(self.entries) >= MAX_SERVICES:
                self.dropped += 1
                return
            self.entries[key] = []
        shown = self.entries[key]
        if revealed_by not in shown and len(shown) < MAX_REVEALED_BY:
            shown.append(revealed_by)


@register
class Dependencies(ScanModule):
    spec = ModuleSpec(
        name="dependencies",
        title="Outside services you rely on",
        category=Category.SUPPLY_CHAIN,
        mode=ScanMode.PASSIVE,
        description="One list of the outside services your domain depends on, so that a "
        "service being added or removed is noticed. Nothing is sent to any host.",
        depends_on=tuple(SOURCES),
        contacts=(),
        default_timeout_s=60,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        root = target.root_domain
        try:
            own = registrable_domain(validate_hostname(root, allow_reserved=True))
        except ValidationError:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason="the domain is not under a recognised public ending",
            )

        notes: list[str] = []
        available: dict[str, ModuleResult] = {}
        missing: list[str] = []
        incomplete: list[str] = []
        for name, (title, provides) in SOURCES.items():
            result = ctx.assets.get(name)
            if result is None or not ctx.assets.completed(name):
                missing.append(name)
                notes.append(
                    f"{title[0].upper()}{title[1:]} did not run in this scan, so {provides} "
                    "could not be read. Nothing from it is listed, which does not mean "
                    "those services are gone."
                )
                continue
            available[name] = result
            if result.status is not ModuleStatus.OK:
                incomplete.append(name)
                notes.append(
                    f"{title[0].upper()}{title[1:]} was incomplete in this scan, so some of "
                    f"{provides} may be absent from the list."
                )
        if not available:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason="none of the checks this list is built from ran in this scan",
                notes=notes,
            )

        found = Found()
        readers = {
            "dns_resolve": self._aliases,
            "domain_registration": self._nameservers,
            "email_posture": self._mail,
            "http_probe": self._cdn,
            "tls_certs": self._issuers,
            "frontend": self._scripts,
        }
        for name, result in available.items():
            readers[name](result, own, ctx, found)
        if "dns_resolve" in available:
            self._nameservers_seen_in_dns(available["dns_resolve"], own, ctx, found)
        if found.dropped:
            notes.append(
                f"More than {MAX_SERVICES} services were found. The list was cut short, so "
                "it is not complete."
            )

        services = [
            {"service": service, "role": role}
            for role, service in sorted(found.entries, key=lambda k: (k[1].lower(), k[1], k[0]))
        ]
        evidence: dict[str, Any] = {}
        for role in ROLES:
            group = [
                {"service": service, "revealed_by": list(found.entries[(r, service)])}
                for r, service in sorted(found.entries, key=lambda k: (k[1].lower(), k[1]))
                if r == role
            ]
            if group:
                evidence[role] = group
        evidence["read_from"] = [SOURCES[name][0] for name in available]
        evidence["not_read_this_time"] = [SOURCES[name][0] for name in missing]
        evidence["note"] = EXPLANATION

        count = len({entry["service"] for entry in services})
        finding = self.finding(
            "supply_chain.dependencies",
            AssetType.DOMAIN,
            root,
            f"{root} relies on {count} outside service{'' if count == 1 else 's'}",
            # A list built from fewer checks is kept apart from the full list. Comparing
            # the two would report every service the missing check supplies as removed.
            identity={"built_from": ",".join(sorted(available))},
            state={"services": services},
            evidence=evidence,
            confidence=Confidence.CONFIRMED,
        )
        partial = bool(missing or incomplete or found.dropped)
        return self.result(
            ModuleStatus.PARTIAL if partial else ModuleStatus.OK,
            findings=[finding],
            notes=notes,
            stats={
                "services": count,
                "sources_read": len(available),
                "sources_missing": len(missing),
            },
        )

    # -- helpers ----------------------------------------------------------------

    @staticmethod
    def _outside(raw: Any, own: str, ctx: ScanContext) -> tuple[str, str] | None:
        """(hostname, registrable domain) when the name belongs to someone else."""
        if not isinstance(raw, str) or len(raw) > 260:
            return None
        try:
            host = validate_hostname(raw, allow_reserved=True)
            owner = registrable_domain(host)
        except ValidationError:
            return None
        if owner == own or ctx.in_scope(host):
            return None
        return host, owner

    @staticmethod
    def _own_host(raw: Any, ctx: ScanContext) -> str | None:
        if not isinstance(raw, str) or len(raw) > 260:
            return None
        try:
            host = validate_hostname(raw, allow_reserved=True)
        except ValidationError:
            return None
        return host if ctx.in_scope(host) else None

    # -- one reader per source --------------------------------------------------

    def _aliases(self, result: ModuleResult, own: str, ctx: ScanContext, found: Found) -> None:
        for asset in result.assets[:MAX_ITEMS_PER_SOURCE]:
            host = self._own_host(asset.key, ctx)
            target = self._outside(asset.state.get("cname"), own, ctx)
            if host is None or target is None:
                continue
            service, usual = service_for(target[1])
            found.add(usual or "other", service, f"{host} is an alias for {target[0]}")

    def _nameservers(self, result: ModuleResult, own: str, ctx: ScanContext, found: Found) -> None:
        for finding in result.findings:
            if finding.kind != "domain.registration.details":
                continue
            servers = finding.state.get("nameservers")
            if isinstance(servers, list):
                self._add_nameservers(servers, own, ctx, found, "in the registration record")

    def _nameservers_seen_in_dns(
        self, result: ModuleResult, own: str, ctx: ScanContext, found: Found
    ) -> None:
        for finding in result.findings:
            if finding.kind != "dns.nameserver.single_provider":
                continue
            servers = finding.evidence.get("nameservers")
            if isinstance(servers, list):
                self._add_nameservers(servers, own, ctx, found, "in your NS records")

    def _add_nameservers(
        self, servers: list[Any], own: str, ctx: ScanContext, found: Found, where: str
    ) -> None:
        for raw in servers[:MAX_ITEMS_PER_SOURCE]:
            target = self._outside(raw, own, ctx)
            if target is not None:
                service, _ = service_for(target[1])
                found.add("dns", service, f"nameserver {target[0]} {where}")

    def _mail(self, result: ModuleResult, own: str, ctx: ScanContext, found: Found) -> None:
        for asset in result.assets[:1]:
            servers = asset.attributes.get("mx")
            if isinstance(servers, list):
                for raw in servers[:MAX_ITEMS_PER_SOURCE]:
                    target = self._outside(raw, own, ctx)
                    if target is not None:
                        service, _ = service_for(target[1])
                        found.add("mail", service, f"mail server {target[0]} in your MX records")
            record = asset.attributes.get("spf_record")
            if not isinstance(record, str):
                continue
            for term in parse_terms(record[:MAX_SPF_CHARS]):
                if term.mechanism not in ("include", "redirect") or term.domain is None:
                    continue
                target = self._outside(term.domain, own, ctx)
                if target is not None:
                    service, _ = service_for(target[1])
                    sign = "=" if term.mechanism == "redirect" else ":"
                    found.add(
                        "mail_sending",
                        service,
                        f"{term.mechanism}{sign}{target[0]} in your SPF record",
                    )

    def _cdn(self, result: ModuleResult, own: str, ctx: ScanContext, found: Found) -> None:
        for asset in result.assets[:MAX_ITEMS_PER_SOURCE]:
            host = self._own_host(asset.key, ctx)
            label = clean_label(asset.attributes.get("cdn"))
            if host is None or label is None:
                continue
            service = _CDN_NAMES.get(label.lower(), label)
            found.add("cdn", service, f"{host} is served through it")

    def _issuers(self, result: ModuleResult, own: str, ctx: ScanContext, found: Found) -> None:
        for asset in result.assets[:MAX_ITEMS_PER_SOURCE]:
            host = self._own_host(asset.key, ctx)
            service = issuer_name(asset.attributes.get("cert_issuer"))
            if host is None or service is None:
                continue
            found.add("certificates", service, f"issued the certificate served by {host}")

    def _scripts(self, result: ModuleResult, own: str, ctx: ScanContext, found: Found) -> None:
        for finding in result.findings[:MAX_ITEMS_PER_SOURCE]:
            if finding.kind != "frontend.scripts":
                continue
            page = self._own_host(finding.asset_key, ctx)
            scripts = finding.state.get("scripts")
            if page is None or not isinstance(scripts, list):
                continue
            for entry in scripts[:MAX_ITEMS_PER_SOURCE]:
                if not isinstance(entry, dict):
                    continue
                address = entry.get("src")
                if not isinstance(address, str) or len(address) > MAX_ADDRESS_CHARS:
                    continue
                if "\\" in address or "@" in address:
                    # Browsers and parsers disagree about where such an address leads.
                    continue
                try:
                    parts = urlsplit(address)
                    name = parts.hostname
                except ValueError:
                    continue
                if parts.scheme not in ("http", "https") or not name:
                    continue
                target = self._outside(name, own, ctx)
                if target is not None:
                    service, _ = service_for(target[1])
                    found.add("scripts", service, f"{page} loads a script from {target[0]}")
