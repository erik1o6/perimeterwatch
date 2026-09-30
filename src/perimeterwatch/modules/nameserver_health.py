"""Whether each of a domain's nameservers answers for it properly.

Probe depth, not passive: this module sends a few ordinary DNS questions
straight to the domain's own nameservers, and one to a nameserver of the
parent zone (the registry). Nothing is sent that a resolver looking up the
domain would not send.

Only the nameservers the registry lists are asked, eight at most, and only at
public IPv4 addresses. Servers on the do-not-contact list are left alone.
Each server is sent about five questions:

  1. the zone's SOA record over UDP,
  2. the same over TCP,
  3. the zone's NS records, to compare with the registry's list,
  4. one question about a name outside the zone, to see whether the server
     looks up names for strangers.

Questions 1 and 2 are repeated at a second address when the server has one.
A server that does not answer is never reported as faulty: silence may be a
lost packet or a filter on the way. It is noted, and the result is marked
partial.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
from dns.rdtypes.ANY.NS import NS
from dns.rdtypes.ANY.SOA import SOA

from perimeterwatch.clients.dns import DnsStatus
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
from perimeterwatch.safety.domains import registrable_domain, validate_hostname
from perimeterwatch.safety.netguard import is_public_ip
from perimeterwatch.safety.targets import blocked_by

MAX_NAMESERVERS = 8
MAX_ADDRESSES = 2
MAX_PARENT_SERVERS = 3
# Answers are untrusted: no more than this many names are read from one.
MAX_NAMES = 16
TIMEOUT_S = 4.0

# The name asked about to see whether a server looks up names for strangers.
#
# It has to lie outside the zone being checked, exist, stay put, and belong to
# someone who does not mind being asked. example.com is reserved for
# documentation (RFC 2606 section 3) and registered to IANA in perpetuity
# (RFC 6761 section 6.5, point 7). It resolves like any other name: point 4 of
# the same section says caching servers "SHOULD resolve them normally", so an
# open resolver gives a real answer. It cannot be a scan target, because
# domain validation refuses the documentation domains.
#
# The root zone's NS records were the other candidate. They were passed over
# because a server can hand them out from its built-in hints file without
# looking anything up, which would look like an open resolver when it is not.
RECURSION_PROBE_NAME = "example.com."
RECURSION_PROBE_TYPE = "A"


class Outcome(StrEnum):
    ANSWERED = "answered"
    SILENT = "silent"  # timed out
    CLOSED = "closed"  # the connection was refused
    FAILED = "failed"  # any other error


@dataclass(frozen=True)
class Reply:
    outcome: Outcome
    message: dns.message.Message | None = None

    @property
    def answered(self) -> bool:
        return self.outcome is Outcome.ANSWERED and self.message is not None


def send(
    query: dns.message.Message, address: str, tcp: bool, timeout: float
) -> dns.message.Message:
    """One question to one address. Blocking: call it through asyncio.to_thread."""
    if tcp:
        return dns.query.tcp(query, address, timeout=timeout)
    return dns.query.udp(query, address, timeout=timeout)


def exchange(query: dns.message.Message, address: str, tcp: bool) -> Reply:
    """Send a question and sort the result. A timeout is tried once more."""
    # The last line of defence: whatever the caller did, a private address
    # is never sent anything.
    if not is_public_ip(address) or ":" in address:
        return Reply(Outcome.FAILED)
    for attempt in range(2):
        try:
            return Reply(Outcome.ANSWERED, send(query, address, tcp, TIMEOUT_S))
        except dns.exception.Timeout:
            if attempt:
                return Reply(Outcome.SILENT)
        except TimeoutError:
            if attempt:
                return Reply(Outcome.SILENT)
        except ConnectionRefusedError:
            return Reply(Outcome.CLOSED)
        except (dns.exception.DNSException, OSError, EOFError):
            return Reply(Outcome.FAILED)
    return Reply(Outcome.SILENT)


def make_query(name: str, rdtype: str, *, recurse: bool) -> dns.message.Message:
    query = dns.message.make_query(name, rdtype)
    if not recurse:
        query.flags &= ~dns.flags.RD
    return query


def clean_name(name: dns.name.Name) -> str | None:
    """A name from an answer as a checked hostname, or None if it is not one."""
    try:
        text = name.to_text(omit_final_dot=True)
    except dns.exception.DNSException:
        return None
    return clean_text(text)


def clean_text(text: str) -> str | None:
    if len(text) > 254:
        return None
    try:
        return validate_hostname(text, allow_reserved=True)
    except ValidationError:
        return None


def ns_names(sections: list[list[dns.rrset.RRset]], zone: dns.name.Name) -> tuple[set[str], int]:
    """Checked nameserver names for the zone, and how many were thrown away."""
    names: set[str] = set()
    dropped = 0
    seen = 0
    for section in sections:
        for rrset in section:
            if rrset.rdtype != dns.rdatatype.NS or rrset.name != zone:
                continue
            for rdata in rrset:
                if not isinstance(rdata, NS):
                    continue
                seen += 1
                if seen > MAX_NAMES:
                    return names, dropped
                name = clean_name(rdata.target)
                if name is None:
                    dropped += 1
                else:
                    names.add(name)
    return names, dropped


def judge_soa(message: dns.message.Message, zone: dns.name.Name) -> tuple[str, int | None]:
    """What a server's SOA answer says about it.

    The first value is "ok" (with the zone's serial number), one of the
    reasons in LAME_REASONS, or "unclear" when the server reported a failure
    of its own, which proves nothing either way.
    """
    rcode = message.rcode()
    if rcode == dns.rcode.REFUSED:
        return "refused", None
    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return "unclear", None
    if not message.flags & dns.flags.AA:
        return "not_authoritative", None
    for rrset in message.answer:
        if rrset.rdtype != dns.rdatatype.SOA or rrset.name != zone:
            continue
        for rdata in rrset:
            if isinstance(rdata, SOA):
                return "ok", int(rdata.serial)
    return "no_soa", None


def is_open_resolver(message: dns.message.Message) -> bool:
    """True only when the server says it will look names up, and did.

    The recursion-available flag alone is not enough: some servers set it and
    still refuse. An answer alone is not enough either: a server that happens
    to host the name answers from its own copy, with the authoritative flag.
    """
    if not message.flags & dns.flags.RA:
        return False
    if message.flags & dns.flags.AA:
        return False
    if message.rcode() != dns.rcode.NOERROR:
        return False
    return any(len(rrset) for rrset in message.answer)


LAME_REASONS = {
    "refused": "refuses questions about the zone",
    "not_authoritative": "answers, but not as a server that holds the zone",
    "no_soa": "holds no copy of the zone's main record",
}


@dataclass
class ServerReport:
    name: str
    addresses: list[str]
    lame: str | None = None
    serial: int | None = None
    no_tcp: list[str] = field(default_factory=list)
    open_resolver: bool = False
    zone_ns: set[str] | None = None
    dropped_names: int = 0
    notes: list[str] = field(default_factory=list)
    partial: bool = False
    queries: int = 0


@register
class NameserverHealth(ScanModule):
    spec = ModuleSpec(
        name="nameserver_health",
        title="Nameserver health",
        category=Category.SURFACE,
        mode=ScanMode.PROBE,
        description=(
            "Whether each nameserver answers for your domain, over both UDP and TCP, "
            "with the same version of the zone, and without looking up names for strangers."
        ),
        contacts=(
            "the domain's own nameservers, about five ordinary DNS questions each",
            "one nameserver of the parent zone, one question",
        ),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        zone = registrable_domain(target.root_domain)
        zone_name = dns.name.from_text(zone)
        notes: list[str] = []
        partial = False
        queries = 0

        parent_ns, parent_queries, parent_note = await self._parent_view(zone, zone_name, ctx)
        queries += parent_queries
        if parent_ns is None:
            partial = True
            notes.append(parent_note)
            answer = await ctx.dns.query(zone, "NS")
            if answer.status is DnsStatus.ERROR:
                return self.result(
                    ModuleStatus.FAILED, skip_reason="the nameservers could not be looked up"
                )
            listed = {name for r in answer.records[:MAX_NAMES] if (name := clean_text(r))}
        else:
            listed = parent_ns
        servers = sorted(listed)[:MAX_NAMESERVERS]
        if len(listed) > MAX_NAMESERVERS:
            notes.append(f"Only the first {MAX_NAMESERVERS} nameservers were checked.")
        if not servers:
            return self.result(
                ModuleStatus.PARTIAL if partial else ModuleStatus.OK,
                notes=[*notes, "The domain lists no nameservers."],
            )

        reports = await asyncio.gather(
            *(self._check_server(server, zone, zone_name, ctx) for server in servers)
        )
        checked = [r for r in reports if r.addresses]
        for report in reports:
            notes.extend(report.notes)
            partial = partial or report.partial
            queries += report.queries

        findings: list[Finding] = []
        for report in checked:
            findings.extend(self._server_findings(zone, report))
        mismatch = self._serial_finding(zone, checked)
        if mismatch is not None:
            findings.append(mismatch)
        if parent_ns is not None:
            delegation = self._delegation_finding(zone, parent_ns, checked, notes)
            if delegation is not None:
                findings.append(delegation)

        return self.result(
            ModuleStatus.PARTIAL if partial else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={"nameservers_asked": len(checked), "queries_sent": queries},
        )

    # -- the parent's list --------------------------------------------------

    async def _parent_view(
        self, zone: str, zone_name: dns.name.Name, ctx: ScanContext
    ) -> tuple[set[str] | None, int, str]:
        """The nameservers the parent zone lists, asked of the parent itself.

        A parent's nameserver does not hold the zone. Asked for its NS
        records, it answers with a referral: no authoritative flag, an empty
        answer, and the delegation in the authority section. Anything else is
        not the parent's view and is not used.
        """
        unavailable = (
            "The registry's list of nameservers could not be read, so it was not compared "
            "with the zone's own list. The nameservers were taken from public DNS instead."
        )
        candidates = await self._parent_servers(zone, ctx)
        queries = 0
        query = make_query(zone, "NS", recurse=False)
        for server, address in candidates:
            await ctx.limiter.acquire(server)
            queries += 1
            reply = await asyncio.to_thread(exchange, query, address, False)
            if reply.answered and reply.message is not None:
                if reply.message.flags & dns.flags.TC:
                    await ctx.limiter.acquire(server)
                    queries += 1
                    reply = await asyncio.to_thread(exchange, query, address, True)
            message = reply.message
            if not reply.answered or message is None:
                continue
            if message.rcode() != dns.rcode.NOERROR:
                continue
            if message.flags & dns.flags.AA or message.answer:
                # This server holds the zone as well, so its answer is the
                # zone's own list, not the registry's.
                continue
            names, dropped = ns_names([message.authority], zone_name)
            if names and not dropped:
                return names, queries, ""
        return None, queries, unavailable

    async def _parent_servers(self, zone: str, ctx: ScanContext) -> list[tuple[str, str]]:
        labels = zone.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            answer = await ctx.dns.query(parent, "NS")
            if not answer.ok:
                continue
            found: list[tuple[str, str]] = []
            for record in sorted(answer.records)[:MAX_NAMES]:
                if len(found) >= MAX_PARENT_SERVERS:
                    break
                server = clean_text(record)
                if server is None:
                    continue
                ips, _ = await ctx.dns.addresses(server)
                usable = [ip for ip in ips if is_public_ip(ip) and ":" not in ip]
                if not usable or blocked_by(server, usable, ctx.settings.never_contact):
                    continue
                found.append((server, usable[0]))
            return found
        return []

    # -- one nameserver -----------------------------------------------------

    async def _check_server(
        self, server: str, zone: str, zone_name: dns.name.Name, ctx: ScanContext
    ) -> ServerReport:
        report = ServerReport(name=server, addresses=[])
        ips, status = await ctx.dns.addresses(server)
        if status is DnsStatus.ERROR:
            report.partial = True
            report.notes.append(
                f"The address of {server} could not be looked up. It was not asked."
            )
            return report
        usable = sorted(ip for ip in ips if is_public_ip(ip) and ":" not in ip)
        if not usable:
            report.notes.append(f"{server} has no public address and was not asked.")
            return report
        if blocked_by(server, usable, ctx.settings.never_contact):
            report.notes.append(f"{server} is on the do-not-contact list and was not asked.")
            return report
        report.addresses = usable[:MAX_ADDRESSES]

        async def ask(query: dns.message.Message, address: str, tcp: bool) -> Reply:
            await ctx.limiter.acquire(server)
            report.queries += 1
            return await asyncio.to_thread(exchange, query, address, tcp)

        soa = make_query(zone, "SOA", recurse=False)
        # The first address that answered, and whether only TCP got through.
        reachable: tuple[str, bool] | None = None
        authoritative: str | None = None
        verdicts: list[str] = []
        for address in report.addresses:
            udp = await ask(soa, address, False)
            tcp = await ask(soa, address, True)
            if not udp.answered and not tcp.answered:
                report.partial = True
                report.notes.append(
                    f"{server} ({address}) did not answer. This may be a fault on the way "
                    "there, so it is not reported as a problem."
                )
                continue
            reachable = reachable or (address, not udp.answered)
            if udp.answered and not tcp.answered:
                report.no_tcp.append(address)
            if tcp.answered and not udp.answered:
                report.partial = True
                report.notes.append(
                    f"{server} ({address}) answered over TCP but not over UDP. "
                    "A lost packet can cause this, so it is not reported as a problem."
                )
            message = udp.message if udp.answered else tcp.message
            if (
                message is not None
                and message.flags & dns.flags.TC
                and tcp.answered
                and tcp.message is not None
            ):
                message = tcp.message
            if message is None:
                continue
            verdict, serial = judge_soa(message, zone_name)
            if verdict == "unclear":
                report.partial = True
                report.notes.append(
                    f"{server} ({address}) reported a failure of its own "
                    f"({dns.rcode.to_text(message.rcode())[:20]}). "
                    "This proves nothing, so it is not reported as a problem."
                )
                continue
            verdicts.append(verdict)
            if verdict == "ok":
                authoritative = authoritative or address
                if report.serial is None:
                    report.serial = serial

        if verdicts and "ok" not in verdicts:
            report.lame = verdicts[0]

        if authoritative is not None:
            reply = await ask(make_query(zone, "NS", recurse=False), authoritative, False)
            if reply.answered and reply.message is not None and reply.message.flags & dns.flags.AA:
                report.zone_ns, report.dropped_names = ns_names([reply.message.answer], zone_name)
            else:
                report.partial = True
                report.notes.append(f"{server} did not give the zone's own list of nameservers.")

        if reachable is not None and not _inside_probe_zone(zone):
            probe = make_query(RECURSION_PROBE_NAME, RECURSION_PROBE_TYPE, recurse=True)
            reply = await ask(probe, *reachable)
            if reply.answered and reply.message is not None:
                report.open_resolver = is_open_resolver(reply.message)
            else:
                report.partial = True
                report.notes.append(
                    f"{server} did not answer the question that shows whether it looks up "
                    "names for strangers, so this was not checked."
                )
        return report

    # -- findings -----------------------------------------------------------

    def _server_findings(self, zone: str, report: ServerReport) -> list[Finding]:
        findings: list[Finding] = []
        identity = {"nameserver": report.name}
        if report.lame is not None:
            findings.append(
                self.finding(
                    "dns.nameserver.lame",
                    AssetType.DOMAIN,
                    zone,
                    f"Nameserver {report.name} is listed for {zone} but does not answer for it",
                    identity=identity,
                    state={"reason": report.lame},
                    evidence={
                        "nameserver": report.name,
                        "addresses": report.addresses,
                        "what_happened": f"The server {LAME_REASONS[report.lame]}.",
                        "why_it_matters": (
                            "Lookups sent to this server fail and have to be tried again "
                            "elsewhere, which slows your domain down and leaves it with "
                            "less cover if another server fails."
                        ),
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        if report.no_tcp:
            findings.append(
                self.finding(
                    "dns.nameserver.no_tcp",
                    AssetType.DOMAIN,
                    zone,
                    f"Nameserver {report.name} answers over UDP but not over TCP",
                    identity=identity,
                    evidence={
                        "nameserver": report.name,
                        "addresses": report.no_tcp,
                        "why_it_matters": (
                            "Answers too large for UDP, such as signed ones, are fetched "
                            "over TCP. Without it those lookups fail."
                        ),
                    },
                    confidence=Confidence.LIKELY,
                )
            )
        if report.open_resolver:
            findings.append(
                self.finding(
                    "dns.nameserver.open_resolver",
                    AssetType.DOMAIN,
                    zone,
                    f"Nameserver {report.name} looks up any name for anyone",
                    identity=identity,
                    evidence={
                        "nameserver": report.name,
                        "asked_for": RECURSION_PROBE_NAME.rstrip("."),
                        "what_happened": (
                            "The server was asked to look up a name that has nothing to "
                            "do with your domain. It said it would, and gave an answer."
                        ),
                        "why_it_matters": (
                            "Such servers are used to flood others with traffic, and "
                            "can be fed false answers that they then pass on."
                        ),
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )
        return findings

    def _serial_finding(self, zone: str, reports: list[ServerReport]) -> Finding | None:
        serials = {r.name: r.serial for r in reports if r.serial is not None}
        if len(set(serials.values())) < 2:
            return None
        counts = Counter(serials.values())
        # The version most servers hold. On a tie, the highest number.
        common = max(counts, key=lambda serial: (counts[serial], serial))
        return self.finding(
            "dns.nameserver.serial_mismatch",
            AssetType.DOMAIN,
            zone,
            f"The nameservers for {zone} hold different versions of the zone",
            state={"out_of_step": sorted(n for n, s in serials.items() if s != common)},
            evidence={
                "versions": {name: serials[name] for name in sorted(serials)},
                "note": (
                    "A change to the zone takes time to reach every server, so a "
                    "difference seen once may be a change on its way. It is only a "
                    "problem if it persists from one scan to the next."
                ),
                "why_it_matters": (
                    "While the servers differ, visitors get different answers "
                    "depending on which server they happen to ask."
                ),
            },
            confidence=Confidence.CANDIDATE,
        )

    def _delegation_finding(
        self, zone: str, parent: set[str], reports: list[ServerReport], notes: list[str]
    ) -> Finding | None:
        answers = [r for r in reports if r.zone_ns is not None]
        if not answers:
            return None
        if any(r.dropped_names for r in answers):
            notes.append(
                "The zone's own list of nameservers held names that are not valid. They "
                "were ignored, and the list was not compared with the registry's."
            )
            return None
        child: set[str] = set()
        for report in answers:
            child |= report.zone_ns or set()
        if not child or child == parent:
            return None
        only_parent = sorted(parent - child)
        only_zone = sorted(child - parent)
        return self.finding(
            "dns.delegation.mismatch",
            AssetType.DOMAIN,
            zone,
            f"The registry and the {zone} zone list different nameservers",
            state={"only_at_registry": only_parent, "only_in_zone": only_zone},
            evidence={
                "listed_by_registry": sorted(parent),
                "listed_by_zone": sorted(child),
                "why_it_matters": (
                    "Resolvers use both lists. A server on only one of them may be one "
                    "you have stopped using. If someone else can take over that name, "
                    "they can answer for your domain."
                ),
            },
            confidence=Confidence.CONFIRMED,
        )


def _inside_probe_zone(zone: str) -> bool:
    probe = RECURSION_PROBE_NAME.rstrip(".")
    return zone == probe or zone.endswith("." + probe)
