"""Proof that whoever asks for a scan is entitled to it.

Two levels exist. A DNS record proves control of the domain and unlocks
everything. A typed acknowledgement is a recorded statement of authority: it
unlocks active checks but never per-person data.
"""

from __future__ import annotations

import asyncio
import getpass
import secrets
import socket
import uuid
from dataclasses import dataclass
from datetime import timedelta

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rdatatype

from perimeterwatch.branding import VERIFY_LABEL, VERIFY_PREFIX
from perimeterwatch.clients.dns import PUBLIC_RESOLVERS, DnsClient
from perimeterwatch.core.models import AuthLevel, Authorisation, utcnow
from perimeterwatch.safety.netguard import is_public_ip
from perimeterwatch.storage.crypto import DataKeys
from perimeterwatch.storage.repo import TenantRepo, _aware
from perimeterwatch.storage.tables import AuthorisationAck, TargetRow

ACK_VALID_FOR = timedelta(days=30)
MAX_NAMESERVERS = 6


def new_token() -> str:
    return secrets.token_urlsafe(32)


def record_name(domain: str) -> str:
    return f"{VERIFY_LABEL}.{domain}"


def record_value(token: str) -> str:
    return f"{VERIFY_PREFIX}{token}"


def statement_for(domain: str) -> str:
    return f"I am authorised to test {domain}"


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    source: str  # authoritative | public resolvers | none
    detail: str


async def _zone_nameservers(domain: str, client: DnsClient) -> list[str]:
    """Addresses of the nameservers for the zone holding `domain`."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        answer = await client.query(zone, "NS")
        if not answer.ok:
            continue
        addresses: list[str] = []
        for server in answer.records[:MAX_NAMESERVERS]:
            ips, _ = await client.addresses(server)
            # Never send queries to an address a hostile zone could aim inward.
            addresses.extend(ip for ip in ips if is_public_ip(ip) and ":" not in ip)
        if addresses:
            return addresses[:MAX_NAMESERVERS]
    return []


async def _ask(server: str, name: str, timeout: float) -> tuple[bool, list[str]] | None:
    """Ask one server for TXT records. Returns (authoritative, values), or None on failure."""
    query = dns.message.make_query(name, dns.rdatatype.TXT)
    query.flags &= ~dns.flags.RD
    try:
        response = await dns.asyncquery.udp(query, server, timeout=timeout)
        if response.flags & dns.flags.TC:
            response = await dns.asyncquery.tcp(query, server, timeout=timeout)
    except (dns.exception.DNSException, OSError):
        return None
    values = [
        "".join(part.decode("utf-8", "replace") for part in rdata.strings)
        for rrset in response.answer
        if rrset.rdtype == dns.rdatatype.TXT
        for rdata in rrset
    ]
    return bool(response.flags & dns.flags.AA), values


async def check_dns(domain: str, token: str, *, timeout: float = 4.0) -> VerificationResult:
    """Look for the verification record.

    The answer must come from the domain's own nameservers, or failing that
    from at least two independent public resolvers. A local resolver or hosts
    file cannot satisfy this.
    """
    name = record_name(domain)
    expected = record_value(token)
    client = DnsClient(timeout_s=timeout)

    servers = await _zone_nameservers(domain, client)
    answers = await asyncio.gather(*(_ask(s, name, timeout) for s in servers))
    authoritative = [values for a in answers if a is not None for aa, values in [a] if aa]
    if authoritative:
        if any(expected in values for values in authoritative):
            return VerificationResult(True, "authoritative", f"Found at {name}.")
        if any(v.startswith(VERIFY_PREFIX) for values in authoritative for v in values):
            return VerificationResult(
                False,
                "authoritative",
                f"A record exists at {name}, but its value does not match. Copy the value again.",
            )

    agree = 0
    for resolver in PUBLIC_RESOLVERS:
        single = DnsClient(nameservers=(resolver,), timeout_s=timeout)
        answer = await single.query(name, "TXT")
        if expected in answer.records:
            agree += 1
    if agree >= 2:
        return VerificationResult(True, "public resolvers", f"Found at {name}.")

    return VerificationResult(
        False,
        "none",
        f"No matching TXT record at {name}. DNS changes can take a few minutes to appear.",
    )


def make_ack(
    target: TargetRow,
    *,
    full_name: str,
    organisation: str,
    role: str,
    keys: DataKeys,
) -> AuthorisationAck:
    now = utcnow()
    statement = statement_for(target.root_domain)
    ack = AuthorisationAck(
        id=uuid.uuid4(),
        tenant_id=target.tenant_id,
        target_id=target.id,
        full_name=full_name.strip(),
        organisation=organisation.strip(),
        role=role.strip(),
        statement=statement,
        os_user=getpass.getuser(),
        hostname=socket.gethostname(),
        created_at=now,
        expires_at=now + ACK_VALID_FOR,
        mac="",
    )
    ack.mac = keys.mac(_ack_message(ack, target.root_domain))
    return ack


def _ack_message(ack: AuthorisationAck, domain: str) -> str:
    created = _aware(ack.created_at)
    return "|".join(
        [
            str(ack.id),
            domain,
            ack.full_name,
            ack.organisation,
            ack.role,
            ack.statement,
            ack.os_user,
            ack.hostname,
            created.isoformat() if created else "",
        ]
    )


def ack_is_valid(ack: AuthorisationAck, domain: str, keys: DataKeys) -> bool:
    expires = _aware(ack.expires_at)
    if expires is None or expires <= utcnow():
        return False
    if ack.statement != statement_for(domain):
        return False
    return secrets.compare_digest(ack.mac, keys.mac(_ack_message(ack, domain)))


async def resolve_authorisation(
    repo: TenantRepo, target: TargetRow, keys: DataKeys
) -> Authorisation:
    """The authorisation in force right now. DNS proof is re-checked every time."""
    now = utcnow()
    verification = repo.get_verification(target.id)
    if verification is not None:
        result = await check_dns(target.root_domain, verification.token)
        verification.last_checked_at = now
        verification.last_result = result.detail[:200]
        if result.verified:
            verification.verified_at = now
            verification.consecutive_failures = 0
            return Authorisation(
                level=AuthLevel.DNS_VERIFIED,
                basis=f"Domain control was confirmed by DNS record ({result.source}).",
                checked_at=now,
            )
        verification.consecutive_failures += 1

    ack = repo.latest_ack(target.id)
    if ack is not None and ack_is_valid(ack, target.root_domain, keys):
        created = _aware(ack.created_at) or now
        return Authorisation(
            level=AuthLevel.ACKNOWLEDGED,
            basis=(
                f"Authorisation was stated by {ack.full_name} ({ack.role}, {ack.organisation}) "
                f"on {created:%d %B %Y}. Domain control was not proven."
            ),
            checked_at=now,
        )
    return Authorisation(checked_at=now)
