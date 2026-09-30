from __future__ import annotations

import pytest

from perimeterwatch.safety.netguard import is_public_ip, vet

BLOCKED = [
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.1",
    "127.0.0.1",
    "127.255.255.254",
    "0.0.0.0",
    "169.254.169.254",
    "169.254.0.1",
    "100.64.0.1",
    "100.127.255.254",
    "198.18.0.1",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "fd00:ec2::254",
    "64:ff9b::a00:1",
    "64:ff9b:1::1",
    "2001:20::1",
    "2002:a00:1::1",
    "2002:7f00:1::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "100::1",
    "fe80::1%eth0",
    "not-an-ip",
    "",
    "10.0.0.1/8",
    "1.2.3",
    "999.1.1.1",
]


@pytest.mark.parametrize("ip", BLOCKED)
def test_blocked(ip: str) -> None:
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "104.18.0.1", "2606:4700:4700::1111"])
def test_public(ip: str) -> None:
    assert is_public_ip(ip) is True


def test_one_private_address_makes_a_host_unsafe() -> None:
    assert vet("a.acme.xyz", ["1.1.1.1"]).safe
    mixed = vet("a.acme.xyz", ["1.1.1.1", "10.0.0.1"])
    assert not mixed.safe
    assert mixed.blocked_ips == ("10.0.0.1",)
    assert not vet("a.acme.xyz", []).safe
