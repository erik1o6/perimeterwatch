"""Whether a nameserver gives away the whole DNS zone. Active: needs authorisation.

A zone transfer is a standard DNS request, meant for a domain's own secondary
nameservers. A server that answers it for anyone hands out a list of every host
the organisation has. The request is made once per nameserver. If it succeeds,
only the number of records is kept: the records themselves are not stored.
"""

from __future__ import annotations

import asyncio

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.zone

from parapet.clients.dns import DnsStatus
from parapet.core.context import ScanContext
from parapet.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from parapet.core.module import ModuleSpec, ScanModule, register
from parapet.safety.domains import registrable_domain
from parapet.safety.netguard import is_public_ip
from parapet.safety.targets import blocked_by

MAX_NAMESERVERS = 8
MAX_RECORDS = 100_000
TIMEOUT_S = 10.0


def try_transfer(address: str, zone: str) -> int | None:
    """Ask one server for the zone. Returns the record count, or None if refused."""
    try:
        transfer = dns.query.xfr(
            address, zone, timeout=TIMEOUT_S, lifetime=TIMEOUT_S * 2, relativize=False
        )
        count = 0
        for message in transfer:
            count += sum(len(rrset) for rrset in message.answer)
            if count > MAX_RECORDS:
                break
        return count or None
    except (dns.exception.DNSException, OSError, EOFError, ConnectionError):
        return None


@register
class ZoneTransfer(ScanModule):
    spec = ModuleSpec(
        name="zone_transfer",
        title="DNS zone transfer",
        category=Category.VULN,
        mode=ScanMode.ACTIVE,
        description="Whether your nameservers hand a full copy of your DNS zone to anyone.",
        contacts=("the domain's own nameservers, one zone transfer request each",),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        zone = registrable_domain(target.root_domain)
        answer = await ctx.dns.query(zone, "NS")
        if answer.status is DnsStatus.ERROR:
            return self.result(
                ModuleStatus.FAILED, skip_reason="the nameservers could not be looked up"
            )
        servers = sorted({r.lower().rstrip(".") for r in answer.records})[:MAX_NAMESERVERS]
        if not servers:
            return self.result(notes=["The domain lists no nameservers."])

        findings: list[Finding] = []
        notes: list[str] = []
        tried = 0
        for server in servers:
            ips, _ = await ctx.dns.addresses(server)
            usable = [ip for ip in ips if is_public_ip(ip) and ":" not in ip]
            if not usable:
                notes.append(f"{server} has no public address and was not asked.")
                continue
            if blocked_by(server, usable, ctx.settings.never_contact):
                notes.append(f"{server} is on the do-not-contact list and was not asked.")
                continue
            await ctx.limiter.acquire(server)
            tried += 1
            count = await asyncio.to_thread(try_transfer, usable[0], zone)
            if count is None:
                continue
            findings.append(
                self.finding(
                    "dns.zone_transfer.allowed",
                    AssetType.DOMAIN,
                    zone,
                    f"Nameserver {server} gives a full copy of the {zone} zone to anyone",
                    identity={"nameserver": server},
                    evidence={
                        "nameserver": server,
                        "records_offered": f"more than {MAX_RECORDS}"
                        if count > MAX_RECORDS
                        else count,
                        "records_kept": "none",
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        return self.result(findings=findings, notes=notes, stats={"nameservers_asked": tried})
