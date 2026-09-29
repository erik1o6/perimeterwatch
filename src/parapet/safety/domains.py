"""Strict validation of everything a user can name as a target.

Validated values end up in DNS queries, URLs and subprocess input, so anything
that is not plainly a public domain name is rejected here.
"""

from __future__ import annotations

import ipaddress
import re

import tldextract

from parapet.core.errors import ValidationError

# Bundled public suffix snapshot only: validation must not depend on the network.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_STRICT_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_GITHUB_ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")

_RESERVED_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "arpa",
    "test",
    "invalid",
    "onion",
)
_RESERVED_REGISTRABLE = {"example.com", "example.net", "example.org"}


def _normalise(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValidationError("Domain must be text.")
    value = raw.strip().rstrip(".").lower()
    if not value:
        raise ValidationError("Domain is empty.")
    if len(raw) > 300:
        raise ValidationError("Domain is too long.")
    if any(ch.isspace() for ch in value) or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        raise ValidationError(f"Domain contains whitespace or control characters: {raw!r}")
    for bad in (
        "://",
        "/",
        "\\",
        "@",
        ":",
        "?",
        "#",
        "*",
        ";",
        "|",
        "&",
        "$",
        "`",
        "'",
        '"',
        "(",
        ")",
        "<",
        ">",
        "%",
        ",",
    ):
        if bad in value:
            raise ValidationError(
                f"{raw!r} is not a bare domain name. Give only the name, such as 'myproject.xyz'."
            )
    try:
        encoded = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"{raw!r} is not a valid domain name.") from exc
    return encoded.lower()


def validate_hostname(raw: str, *, allow_reserved: bool = False) -> str:
    """Return a canonical hostname, or raise ValidationError."""
    host = _normalise(raw)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValidationError(f"{raw!r} is an IP address. A domain name is required.")
    if len(host) > 253:
        raise ValidationError("Domain is longer than 253 characters.")
    labels = host.split(".")
    if len(labels) < 2:
        raise ValidationError(f"{raw!r} has no top-level domain.")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError(f"{raw!r} has an invalid label: {label!r}")
    if labels[-1].isdigit():
        raise ValidationError(f"{raw!r} has a numeric top-level domain.")
    if not allow_reserved:
        if labels[-1] in _RESERVED_SUFFIXES:
            raise ValidationError(f"{raw!r} uses a reserved or private suffix.")
        if registrable_domain(host, _checked=True) in _RESERVED_REGISTRABLE:
            raise ValidationError(f"{raw!r} is a reserved documentation domain.")
    return host


def registrable_domain(host: str, *, _checked: bool = False) -> str:
    """The part of a hostname someone can register, e.g. 'example.co.uk'."""
    parts = _extract(host)
    if not parts.suffix or not parts.domain:
        raise ValidationError(f"{host!r} is not under a recognised public suffix.")
    return f"{parts.domain}.{parts.suffix}"


def validate_domain(raw: str, *, allow_reserved: bool = False) -> str:
    """Validate a scan target. Stricter than a hostname: no underscores."""
    host = validate_hostname(raw, allow_reserved=allow_reserved)
    for label in host.split("."):
        if not _STRICT_LABEL_RE.match(label):
            raise ValidationError(f"{raw!r} has an invalid label: {label!r}")
    registrable_domain(host)
    return host


def in_scope(host: str, root_domain: str) -> bool:
    """True when host is the root domain or one of its subdomains."""
    host = host.strip().rstrip(".").lower()
    root = root_domain.lower()
    return host == root or host.endswith("." + root)


def validate_github_org(raw: str) -> str:
    value = raw.strip()
    if not _GITHUB_ORG_RE.match(value):
        raise ValidationError(f"{raw!r} is not a valid GitHub organisation name.")
    return value


def validate_slug(raw: str, what: str = "slug") -> str:
    value = raw.strip()
    if not _SLUG_RE.match(value):
        raise ValidationError(f"{raw!r} is not a valid {what}.")
    return value


def validate_email(raw: str, *, root_domain: str | None = None) -> str:
    value = raw.strip()
    if value.count("@") != 1:
        raise ValidationError(f"{raw!r} is not an email address.")
    local, _, domain = value.partition("@")
    if not _EMAIL_LOCAL_RE.match(local) or local.startswith(".") or local.endswith("."):
        raise ValidationError(f"{raw!r} is not an email address.")
    host = validate_hostname(domain)
    if root_domain is not None and not in_scope(host, root_domain):
        raise ValidationError(f"{raw!r} is not an address at {root_domain}.")
    return f"{local.lower()}@{host}"


def validate_eth_address(raw: str) -> str:
    """Return the EIP-55 checksummed form. Mixed-case input must already be valid."""
    from eth_utils.address import is_checksum_address, is_hex_address, to_checksum_address

    value = raw.strip()
    if not is_hex_address(value) or not value.startswith(("0x", "0X")):
        raise ValidationError(f"{raw!r} is not an Ethereum address.")
    body = value[2:]
    mixed = body != body.lower() and body != body.upper()
    if mixed and not is_checksum_address(value):
        raise ValidationError(f"{raw!r} fails its address checksum. Check for a typo.")
    return str(to_checksum_address(value))
