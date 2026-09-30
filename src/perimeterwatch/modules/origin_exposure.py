"""Can the server behind a content delivery network be found in your own records?

A site served through a content delivery network is protected only while the
server behind it stays hidden. That server's address often sits in plain view
in the organisation's own DNS: an old hostname, the SPF record, a mail server.

This module sends nothing to any host. It reads what earlier modules collected
in this scan, and asks public DNS resolvers for the addresses of the
organisation's own mail servers when those are not already known. It never
connects to a candidate address and never uses historical DNS data.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

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
from perimeterwatch.safety.domains import validate_hostname
from perimeterwatch.safety.netguard import is_public_ip

MAX_CANDIDATES = 10
MAX_EXPOSED = 25
MAX_HOSTS = 2000
MAX_IPS_PER_HOST = 16
MAX_CERT_NAMES = 100
MAX_SPF_CHARS = 4096
MAX_SPF_TERMS = 100
MAX_SPF_ENTRIES = 50
MAX_MAIL_SERVERS = 10
MAX_SHOWN = 10
MAX_NOTES = 20

# An SPF entry wider than this names a whole network, not a server.
_NARROWEST_PREFIX = {4: 24, 6: 64}

# Alias targets that belong to a content delivery network.
_CDN_ALIASES: tuple[tuple[str, str], ...] = (
    ("cdn.cloudflare.net", "Cloudflare"),
    ("cloudfront.net", "Amazon CloudFront"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("edgekey.net", "Akamai"),
    ("edgesuite.net", "Akamai"),
    ("akamaiedge.net", "Akamai"),
    ("akamai.net", "Akamai"),
    ("azureedge.net", "Azure CDN"),
    ("azurefd.net", "Azure Front Door"),
    ("b-cdn.net", "Bunny"),
    ("incapdns.net", "Imperva"),
)

# Address ranges the networks publish as their own.
_CDN_RANGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Cloudflare",
        (
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2405:b500::/32",
            "2405:8100::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32",
        ),
    ),
    ("Fastly", ("151.101.0.0/16", "199.232.0.0/16", "2a04:4e42::/32")),
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_NETWORKS: tuple[tuple[str, IPNetwork], ...] = tuple(
    (name, ipaddress.ip_network(block)) for name, blocks in _CDN_RANGES for block in blocks
)

# Names that classically point straight at the server behind the network.
_CLASSIC = frozenset(
    {
        "direct",
        "origin",
        "backend",
        "old",
        "dev",
        "staging",
        "mail",
        "ftp",
        "cpanel",
        "webmail",
        "stage",
        "legacy",
        "server",
    }
)
_LABEL_SPLIT = re.compile(r"[.\-_]")
_NAME_RE = re.compile(r"[^A-Za-z0-9 ._-]")

FALSE_ALARM = (
    "A separate server that shares a certificate with your site, most often a wildcard "
    "certificate covering every name under your domain, looks the same as the server "
    "behind the network. Check what this address serves before treating it as exposed."
)
NOTHING_SENT = (
    "Nothing was sent to this address. It was worked out only from your own DNS records "
    "and from what this scan had already collected."
)


@dataclass(frozen=True)
class HostRecord:
    host: str
    ips: tuple[str, ...]
    cname: str | None
    wildcard: bool


@dataclass(frozen=True)
class Fronted:
    host: str
    cdn: str
    seen_by: str


@dataclass
class Candidate:
    key: str
    asset_type: AssetType
    rank: int
    host: str | None = None
    addresses: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def reason(self, text: str) -> None:
        if text not in self.reasons and len(self.reasons) < MAX_SHOWN:
            self.reasons.append(text)


@dataclass(frozen=True)
class Match:
    exact: tuple[str, ...]
    wildcard: tuple[str, ...]
    certificate_of: tuple[str, ...]

    @property
    def sites(self) -> list[str]:
        return sorted({*self.exact, *self.wildcard})


def clean_host(raw: Any) -> str | None:
    """A hostname from an earlier result, or None when it is not plainly one."""
    if not isinstance(raw, str) or len(raw) > 260:
        return None
    try:
        return validate_hostname(raw, allow_reserved=True)
    except ValidationError:
        return None


def clean_ip(raw: Any) -> str | None:
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def clean_name(raw: Any, length: int = 40) -> str:
    """A short display name with anything unusual removed."""
    if not isinstance(raw, str):
        return ""
    return " ".join(_NAME_RE.sub("", raw[:200]).split())[:length]


def cdn_of_alias(cname: str | None) -> str | None:
    if not cname:
        return None
    for suffix, name in _CDN_ALIASES:
        if cname == suffix or cname.endswith("." + suffix):
            return name
    return None


def cdn_of_address(ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, network in _NETWORKS:
        if network.version == address.version and address in network:
            return name
    return None


def classic_label(host: str, root: str) -> str | None:
    """The part of a hostname that suggests a way round the network, if any."""
    prefix = host[: -len(root)].rstrip(".") if host != root and host.endswith(root) else ""
    for part in _LABEL_SPLIT.split(prefix):
        word = part.rstrip("0123456789")
        if word in _CLASSIC:
            return word
    return None


def spf_addresses(record: Any) -> list[tuple[str, IPNetwork]]:
    """The `ip4:` and `ip6:` entries of an SPF record, as written and as networks."""
    if not isinstance(record, str):
        return []
    found: dict[str, tuple[str, IPNetwork]] = {}
    for raw in record[:MAX_SPF_CHARS].split()[1 : MAX_SPF_TERMS + 1]:
        word = raw.lstrip("+-~?").lower()
        kind, sep, value = word.partition(":")
        if not sep or kind not in ("ip4", "ip6") or len(value) > 64:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version != int(kind[2]):
            continue
        found.setdefault(str(network), (f"{kind}:{value}", network))
        if len(found) >= MAX_SPF_ENTRIES:
            break
    return [found[key] for key in sorted(found)]


def _is_single(network: IPNetwork) -> bool:
    return network.num_addresses == 1


def _usable(network: IPNetwork) -> bool:
    """Public, narrow enough to mean a server, and not part of a delivery network."""
    if network.prefixlen < _NARROWEST_PREFIX[network.version]:
        return False
    if not is_public_ip(str(network.network_address)):
        return False
    if not is_public_ip(str(network.broadcast_address)):
        return False
    return not any(
        known.version == network.version and known.overlaps(network) for _, known in _NETWORKS
    )


def _contains(network: IPNetwork, ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.version == network.version and address in network


@register
class OriginExposure(ScanModule):
    spec = ModuleSpec(
        name="origin_exposure",
        title="Servers behind your content delivery network",
        category=Category.SURFACE,
        mode=ScanMode.PASSIVE,
        description="Whether your own DNS records give away the address of the server that "
        "your content delivery network is meant to hide. Nothing is sent to any host.",
        depends_on=("dns_resolve", "spf_chain", "email_posture", "http_probe", "tls_certs"),
        contacts=("public DNS resolvers",),
        default_timeout_s=180,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        resolved = ctx.assets.get("dns_resolve")
        if resolved is None or not ctx.assets.completed("dns_resolve"):
            return self.result(ModuleStatus.FAILED, skip_reason="DNS resolution did not complete")

        notes: list[str] = []
        incomplete = resolved.status is not ModuleStatus.OK
        if incomplete:
            notes.append("DNS resolution was incomplete, so some hostnames were not considered.")

        root = target.root_domain
        hosts = self._hosts(resolved, ctx)
        probed = ctx.assets.completed("http_probe")
        fronted = self._fronted(hosts, ctx)
        if not probed:
            incomplete = True
            notes.append(
                "The check that visits your web servers did not run, so hosts behind a "
                "content delivery network were recognised only from their DNS aliases and "
                "address ranges. The results are less certain."
            )
        if not fronted:
            notes.append(
                "No host was found to be served through a content delivery network, so "
                "there is no hidden server to look for."
            )
            return self.result(
                ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
                notes=notes,
                stats={"behind_cdn": 0, "candidates": 0, "exposed": 0},
            )

        network_addresses = {ip for f in fronted.values() for ip in hosts[f.host].ips}
        candidates = self._from_hostnames(hosts, fronted, network_addresses, root)

        mail = ctx.assets.get("email_posture")
        if mail is None or not ctx.assets.completed("email_posture"):
            incomplete = True
            notes.append(
                "The email check did not complete, so the SPF record and the mail servers "
                "were not searched for addresses."
            )
        else:
            if mail.status is not ModuleStatus.OK:
                incomplete = True
                notes.append("The email check was incomplete, so some records were not searched.")
            attributes = self._domain_attributes(mail, root)
            await self._from_mail_servers(
                attributes.get("mx"), hosts, fronted, network_addresses, candidates, ctx, notes
            )
            self._from_spf(attributes.get("spf_record"), hosts, fronted, candidates, notes)

        certificates: dict[str, set[str]] = {}
        tls = ctx.assets.get("tls_certs")
        if tls is None or not ctx.assets.completed("tls_certs"):
            incomplete = True
            notes.append(
                "The certificate check did not run, so no address could be confirmed. "
                "Every address below is a possibility only."
            )
        else:
            certificates = self._certificate_names(tls, ctx)
            if tls.status is not ModuleStatus.OK:
                incomplete = True
                notes.append("The certificate check was incomplete, so some were not compared.")

        exposed: list[Finding] = []
        possible: list[Finding] = []
        ordered = sorted(candidates.values(), key=lambda c: (c.rank, c.key))
        for candidate in ordered:
            match = self._match(candidate, certificates, fronted, hosts)
            if match.sites:
                exposed.append(self._exposed(candidate, match, fronted))
            else:
                possible.append(self._possible(candidate, fronted, tls))

        for kept, limit, what in (
            (exposed, MAX_EXPOSED, "confirmed addresses"),
            (possible, MAX_CANDIDATES, "unconfirmed addresses"),
        ):
            if len(kept) > limit:
                incomplete = True
                notes.append(f"{len(kept)} {what} were found. Only the first {limit} are reported.")
                del kept[limit:]

        if not candidates:
            notes.append(
                "Every host that could be checked is served through the content delivery "
                "network, and your own records name no address outside it."
            )
        return self.result(
            ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
            findings=[*exposed, *possible],
            notes=notes[:MAX_NOTES],
            stats={
                "behind_cdn": len(fronted),
                "candidates": len(possible),
                "exposed": len(exposed),
            },
        )

    # -- reading earlier results ------------------------------------------------

    def _hosts(self, resolved: ModuleResult, ctx: ScanContext) -> dict[str, HostRecord]:
        """In-scope hostnames and where they point. Everything else is dropped."""
        out: dict[str, HostRecord] = {}
        for asset in resolved.assets[:MAX_HOSTS]:
            if asset.type not in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                continue
            host = clean_host(asset.key)
            if host is None or not ctx.in_scope(host) or host in out:
                continue
            raw_ips = asset.attributes.get("ips")
            ips: list[str] = []
            if isinstance(raw_ips, list):
                for raw in raw_ips[:MAX_IPS_PER_HOST]:
                    ip = clean_ip(raw)
                    if ip is not None and ip not in ips:
                        ips.append(ip)
            out[host] = HostRecord(
                host=host,
                ips=tuple(ips),
                cname=clean_host(asset.state.get("cname")),
                wildcard=asset.attributes.get("wildcard_match") is True,
            )
        return out

    def _fronted(self, hosts: dict[str, HostRecord], ctx: ScanContext) -> dict[str, Fronted]:
        """Hosts served through a content delivery network, and how that is known."""
        out: dict[str, Fronted] = {}
        seen_on_web: set[str] = set()
        probe = ctx.assets.get("http_probe")
        if probe is not None and ctx.assets.completed("http_probe"):
            for asset in probe.assets[:MAX_HOSTS]:
                host = clean_host(asset.key)
                if host is None or host not in hosts:
                    continue
                seen_on_web.add(host)
                name = clean_name(asset.attributes.get("cdn"))
                if name:
                    out.setdefault(host, Fronted(host, name, "the web server check"))
        for host, record in hosts.items():
            if host in seen_on_web or record.wildcard or not record.ips:
                continue
            by_alias = cdn_of_alias(record.cname)
            if by_alias:
                out[host] = Fronted(host, by_alias, f"its DNS alias {record.cname}")
                continue
            owners = {cdn_of_address(ip) for ip in record.ips}
            if len(owners) == 1 and None not in owners:
                name = next(iter(owners)) or ""
                out[host] = Fronted(host, name, "its addresses, which belong to the network")
        return out

    @staticmethod
    def _domain_attributes(mail: ModuleResult, root: str) -> dict[str, Any]:
        for asset in mail.assets:
            if asset.type is AssetType.DOMAIN and asset.key == root:
                return dict(asset.attributes)
        return {}

    def _certificate_names(self, tls: ModuleResult, ctx: ScanContext) -> dict[str, set[str]]:
        """Names on the certificate each host served, as far as tls_certs kept them."""
        out: dict[str, set[str]] = {}

        def add(raw_host: Any, raw_names: Any) -> None:
            host = clean_host(raw_host)
            if host is None or not ctx.in_scope(host) or not isinstance(raw_names, list):
                return
            names = out.setdefault(host, set())
            for raw in raw_names[:MAX_CERT_NAMES]:
                if not isinstance(raw, str) or len(names) >= MAX_CERT_NAMES:
                    continue
                text = raw.strip().lower().rstrip(".")
                wildcard = text.startswith("*.")
                name = clean_host(text[2:] if wildcard else text)
                if name is not None:
                    names.add(f"*.{name}" if wildcard else name)

        for asset in tls.assets[:MAX_HOSTS]:
            add(asset.key, asset.attributes.get("cert_names"))
        for finding in tls.findings[:MAX_HOSTS]:
            if finding.kind == "tls.cert.hostname_mismatch":
                add(finding.asset_key, finding.evidence.get("certificate_names"))
        return {host: names for host, names in out.items() if names}

    # -- finding candidates -----------------------------------------------------

    @staticmethod
    def _outside(ips: tuple[str, ...], network_addresses: set[str]) -> list[str]:
        """Public addresses that do not belong to a content delivery network."""
        return sorted(
            ip
            for ip in ips
            if is_public_ip(ip) and ip not in network_addresses and cdn_of_address(ip) is None
        )

    def _from_hostnames(
        self,
        hosts: dict[str, HostRecord],
        fronted: dict[str, Fronted],
        network_addresses: set[str],
        root: str,
    ) -> dict[str, Candidate]:
        out: dict[str, Candidate] = {}
        networks = sorted({f.cdn for f in fronted.values()})
        named = " or ".join(networks[:3])
        for host, record in hosts.items():
            if host in fronted or record.wildcard or cdn_of_alias(record.cname):
                continue
            addresses = self._outside(record.ips, network_addresses)
            if not addresses:
                continue
            label = classic_label(host, root)
            rank = 0 if label else (2 if record.cname else 1)
            candidate = Candidate(host, AssetType.SUBDOMAIN, rank, host, addresses)
            if host == root:
                candidate.asset_type = AssetType.DOMAIN
            text = (
                f"{host} is one of your own hostnames. It points to an address that does "
                f"not belong to {named}."
            )
            if label:
                text += (
                    f" Names containing '{label}' often lead straight to the server behind "
                    "the network."
                )
            if record.cname:
                text += f" It is an alias for {record.cname}."
            candidate.reason(text)
            out[host] = candidate
        return out

    async def _from_mail_servers(
        self,
        raw: Any,
        hosts: dict[str, HostRecord],
        fronted: dict[str, Fronted],
        network_addresses: set[str],
        candidates: dict[str, Candidate],
        ctx: ScanContext,
        notes: list[str],
    ) -> None:
        if not isinstance(raw, list):
            return
        servers: list[str] = []
        for entry in raw[: MAX_MAIL_SERVERS * 3]:
            host = clean_host(entry)
            if host is not None and ctx.in_scope(host) and host not in servers:
                servers.append(host)
        for host in servers[:MAX_MAIL_SERVERS]:
            if host in fronted:
                continue
            reason = (
                f"{host} is a mail server listed in your MX records. Mail is not carried by "
                "the content delivery network, so a mail server on the same machine as the "
                "website gives its address away."
            )
            if host in candidates:
                candidates[host].reason(reason)
                continue
            known = hosts.get(host)
            if known is not None:
                if known.wildcard:
                    continue
                ips = known.ips
            else:
                looked_up, _ = await ctx.dns.addresses(host)
                ips = tuple(ip for ip in (clean_ip(i) for i in looked_up) if ip is not None)
                ips = ips[:MAX_IPS_PER_HOST]
            addresses = self._outside(ips, network_addresses)
            if not addresses:
                continue
            candidate = Candidate(host, AssetType.SUBDOMAIN, 0, host, addresses)
            candidate.reason(reason)
            candidates[host] = candidate

    def _from_spf(
        self,
        record: Any,
        hosts: dict[str, HostRecord],
        fronted: dict[str, Fronted],
        candidates: dict[str, Candidate],
        notes: list[str],
    ) -> None:
        skipped_wide = 0
        for written, network in spf_addresses(record):
            if not _usable(network):
                wide = network.prefixlen < _NARROWEST_PREFIX[network.version]
                skipped_wide += int(wide)
                continue
            single = _is_single(network)
            shown = str(network.network_address) if single else str(network)
            reason = (
                f"Your SPF record lists {written} as allowed to send your mail. A web "
                "server that also sends mail is often listed there."
            )
            matched = False
            for candidate in list(candidates.values()):
                if any(_contains(network, ip) for ip in candidate.addresses):
                    candidate.reason(reason)
                    matched = True
            if matched:
                continue
            if any(_contains(network, ip) for f in fronted.values() for ip in hosts[f.host].ips):
                continue
            candidate = Candidate(shown, AssetType.IP, 1, None, [shown])
            candidate.reason(reason)
            candidates[shown] = candidate
        if skipped_wide:
            notes.append(
                f"{skipped_wide} entries in your SPF record cover a whole network and not "
                "a single server. They were not treated as possible servers."
            )

    # -- confirming -------------------------------------------------------------

    def _match(
        self,
        candidate: Candidate,
        certificates: dict[str, set[str]],
        fronted: dict[str, Fronted],
        hosts: dict[str, HostRecord],
    ) -> Match:
        """Which sites behind the network are named on a certificate served here."""
        if candidate.host is not None:
            sources = [candidate.host]
        else:
            # An address from the SPF record: use the certificates of your own
            # hostnames that point to it.
            networks = [ipaddress.ip_network(a, strict=False) for a in candidate.addresses]
            sources = sorted(
                host
                for host, record in hosts.items()
                if host not in fronted
                and not record.wildcard
                and any(_contains(n, ip) for n in networks for ip in record.ips)
            )
        exact: set[str] = set()
        wildcard: set[str] = set()
        used: set[str] = set()
        for source in sources:
            names = certificates.get(source)
            if not names:
                continue
            for site in fronted:
                if site in names:
                    exact.add(site)
                    used.add(source)
                elif "." in site and f"*.{site.split('.', 1)[1]}" in names:
                    wildcard.add(site)
                    used.add(source)
        return Match(tuple(sorted(exact)), tuple(sorted(wildcard - exact)), tuple(sorted(used)))

    # -- findings ---------------------------------------------------------------

    @staticmethod
    def _where(candidate: Candidate) -> str:
        if candidate.host is None:
            return candidate.key
        shown = ", ".join(candidate.addresses[:2])
        return f"{candidate.host} ({shown})"

    def _exposed(self, candidate: Candidate, match: Match, fronted: dict[str, Fronted]) -> Finding:
        sites = match.sites
        networks = sorted({fronted[s].cdn for s in sites})
        served_by = ", ".join(match.certificate_of[:3])
        by_wildcard_only = not match.exact
        if by_wildcard_only:
            confirmed = (
                f"The certificate already collected from {served_by} is a wildcard "
                f"certificate that covers {', '.join(sites[:MAX_SHOWN])}. That suggests this "
                "is the server behind the network, but a wildcard certificate is often "
                "shared between separate servers."
            )
        else:
            confirmed = (
                f"The certificate already collected from {served_by} names "
                f"{', '.join(list(match.exact)[:MAX_SHOWN])}, which is served through "
                f"{' and '.join(networks)}. A server holding the certificate of the "
                "protected site is very likely the server behind it."
            )
        first = sites[0]
        more = f" and {len(sites) - 1} more" if len(sites) > 1 else ""
        return self.finding(
            "surface.origin.exposed",
            candidate.asset_type,
            candidate.key,
            f"The server behind {first}{more} can be reached directly at {self._where(candidate)}",
            state={"addresses": sorted(candidate.addresses), "sites": sites[:MAX_EXPOSED]},
            evidence={
                "addresses": sorted(candidate.addresses)[:MAX_SHOWN],
                "sites_behind_the_network": sites[:MAX_SHOWN],
                "content_delivery_network": networks,
                "how_it_was_found": list(candidate.reasons),
                "how_it_was_confirmed": confirmed,
                "matched_by_wildcard_only": by_wildcard_only,
                "what_was_sent": NOTHING_SENT,
                "possible_false_alarm": FALSE_ALARM,
            },
            confidence=Confidence.CANDIDATE if by_wildcard_only else Confidence.LIKELY,
            severity_steps=-1 if by_wildcard_only else 0,
            severity_note="Only a wildcard certificate links this address to the site, and "
            "such certificates are often shared between separate servers."
            if by_wildcard_only
            else None,
        )

    def _possible(
        self,
        candidate: Candidate,
        fronted: dict[str, Fronted],
        tls: ModuleResult | None,
    ) -> Finding:
        if tls is None or tls.status not in (ModuleStatus.OK, ModuleStatus.PARTIAL):
            why = (
                "Not confirmed. The certificate check did not run in this scan, so there "
                "was nothing to compare."
            )
        elif candidate.host is None:
            why = (
                "Not confirmed. None of your hostnames with a collected certificate points "
                "to this address, so there was nothing to compare."
            )
        else:
            why = (
                "Not confirmed. No certificate already collected from this host names a "
                "site that is served through the network."
            )
        sites = sorted(fronted)
        return self.finding(
            "surface.origin.candidate",
            candidate.asset_type,
            candidate.key,
            f"{self._where(candidate)} may be the server behind your content delivery network",
            state={"addresses": sorted(candidate.addresses)},
            evidence={
                "addresses": sorted(candidate.addresses)[:MAX_SHOWN],
                "sites_behind_the_network": sites[:MAX_SHOWN],
                "content_delivery_network": sorted({f.cdn for f in fronted.values()})[:MAX_SHOWN],
                "how_it_was_found": list(candidate.reasons),
                "how_it_was_confirmed": why,
                "what_was_sent": NOTHING_SENT,
                "possible_false_alarm": FALSE_ALARM,
            },
            confidence=Confidence.CANDIDATE,
        )
