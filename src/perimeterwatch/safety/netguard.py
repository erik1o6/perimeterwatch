"""Keep scans and fetches away from private, reserved and metadata addresses."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, cloud metadata
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS IPv6 metadata
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def is_public_ip(value: str | IPAddress) -> bool:
    try:
        ip = ipaddress.ip_address(value) if isinstance(value, str) else value
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)


@dataclass(frozen=True)
class VettedHost:
    host: str
    public_ips: tuple[str, ...]
    blocked_ips: tuple[str, ...]

    @property
    def safe(self) -> bool:
        """Safe to contact only when every address is public."""
        return bool(self.public_ips) and not self.blocked_ips


def vet(host: str, ips: list[str]) -> VettedHost:
    public = tuple(sorted(ip for ip in ips if is_public_ip(ip)))
    blocked = tuple(sorted(ip for ip in ips if not is_public_ip(ip)))
    return VettedHost(host=host, public_ips=public, blocked_ips=blocked)
