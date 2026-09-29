"""Decide which hosts may be contacted.

A host qualifies only if it is under the scanned domain, it resolves, and every
address it resolves to is public. One private or reserved address disqualifies it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from perimeterwatch.safety.domains import validate_hostname
from perimeterwatch.safety.netguard import VettedHost, is_public_ip, vet

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

MAX_HOSTS = 500


@dataclass
class Contactable:
    hosts: list[VettedHost] = field(default_factory=list)
    excluded: dict[str, str] = field(default_factory=dict)  # host -> reason
    truncated: bool = False

    @property
    def names(self) -> list[str]:
        return [h.host for h in self.hosts]

    def owner_of(self, ip: str) -> list[str]:
        return [h.host for h in self.hosts if ip in h.public_ips]


def blocked_by(host: str, ips: list[str], never_contact: list[str]) -> bool:
    """Whether a host or any of its addresses is on the do-not-contact list."""
    for entry in never_contact:
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            if host == entry or host.endswith("." + entry):
                return True
            continue
        for ip in ips:
            try:
                if ipaddress.ip_address(ip) in network:
                    return True
            except ValueError:
                continue
    return False


def contactable_hosts(ctx: ScanContext, *, limit: int = MAX_HOSTS) -> Contactable:
    out = Contactable()
    resolved = ctx.assets.get("dns_resolve")
    if resolved is None:
        return out
    for asset in sorted(resolved.assets, key=lambda a: (a.key.count("."), a.key)):
        host = asset.key
        if not asset.state.get("resolves"):
            continue
        if not ctx.in_scope(host):
            out.excluded[host] = "outside the scanned domain"
            continue
        if asset.attributes.get("wildcard_match"):
            continue
        try:
            # Guards the subprocess input: a leading dash would read as an option.
            validate_hostname(host, allow_reserved=True)
        except Exception:
            out.excluded[host] = "not a valid hostname"
            continue
        ips = [str(i) for i in asset.attributes.get("ips", [])]
        if blocked_by(host, ips, ctx.settings.never_contact):
            out.excluded[host] = "on the do-not-contact list"
            continue
        vetted = vet(host, ips)
        if asset.attributes.get("private_ips") or not vetted.safe:
            out.excluded[host] = "resolves to a private or reserved address"
            continue
        if len(out.hosts) >= limit:
            out.truncated = True
            break
        out.hosts.append(vetted)
    return out


def reported_ip_is_safe(ip: object) -> bool:
    """Check the address a tool says it actually connected to."""
    return isinstance(ip, str) and is_public_ip(ip)
