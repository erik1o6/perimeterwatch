"""How well a signed zone is signed. Passive: public resolvers only.

DNSSEC signs a zone's records so that forged answers can be detected. A zone
can be signed and still be signed badly: with an algorithm that resolvers no
longer trust, with signatures about to lapse, or in a way that lets anyone
list every name in the zone. This module reads the zone's public signing
records through public resolvers and reports those cases.

Whether the zone is signed at all is reported elsewhere (dns.dnssec.disabled).
For an unsigned zone this module reports nothing and says so in a note.

At most four questions are asked, all of public resolvers, never of the
domain's own nameservers. Nothing here validates signatures: every record is
treated as untrusted text, and names are checked before they are shown.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdatatype
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.NSEC import NSEC
from dns.rdtypes.ANY.NSEC3 import NSEC3
from dns.rdtypes.ANY.RRSIG import RRSIG

from perimeterwatch.clients.dns import PUBLIC_RESOLVERS
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
    utcnow,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.domains import registrable_domain, validate_hostname

TIMEOUT_S = 4.0
# Answers are untrusted: no more than this many records of a kind are read.
MAX_RECORDS = 32
# A size that avoids fragmentation on almost every path. Larger answers come
# back truncated and are asked for again over TCP.
EDNS_PAYLOAD = 1232

# Algorithms that must not be used to sign a zone.
#
# RFC 9905 section 2: RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7) "MUST NOT be used
# when creating DNSKEY and RRSIG records", and must not be used when creating
# DS records either.
# RFC 9906 section 2 says the same of ECC-GOST (12).
# RFC 9904 section 2 adds the column "Use for DNSSEC Signing" to the IANA
# registry "DNS Security Algorithm Numbers", and section 3 (table 2) gives its
# first values. The set below is every entry that the registry marks MUST NOT
# in that column, as read on 2026-09-29:
# https://www.iana.org/assignments/dns-sec-alg-numbers
# Algorithm 10 (RSASHA512) is NOT RECOMMENDED there, not MUST NOT, so it is
# left out.
MUST_NOT_SIGN: dict[int, str] = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    12: "ECC-GOST",
}

# Digest types that must not be used in a DS record: the column "Use for
# DNSSEC Delegation" of the IANA registry "Digest Algorithms" (RFC 9904
# section 4, table 3). SHA-1 was set to MUST NOT by RFC 9905 section 5, and
# GOST R 34.11-94 by RFC 9906 section 2.
# https://www.iana.org/assignments/ds-rr-types
MUST_NOT_DIGEST: dict[int, str] = {1: "SHA-1", 3: "GOST R 34.11-94"}

# Algorithms whose public key is an RSA key in the layout of RFC 3110 section 2.
RSA_ALGORITHMS = frozenset({1, 5, 7, 8, 10})
# No RFC forbids shorter RSA keys outright. RFC 6781 section 3.4.2 names 2048
# bits as the usual size above 1024. The limit here is this project's rule.
MIN_RSA_BITS = 2048

# DNSKEY flag bits, RFC 4034 section 2.1.1 and RFC 5011 section 2.1.
FLAG_ZONE_KEY = 0x0100
FLAG_REVOKED = 0x0080

# Days remaining -> bucket. The finding changes only when a boundary is
# crossed, so it is not reported as changed every day.
BUCKETS = ((3, "3d"), (7, "7d"))
# Most urgent first.
BUCKET_ORDER = ("expired", "3d", "7d")


def send_udp(query: dns.message.Message, resolver: str, timeout: float) -> dns.message.Message:
    return dns.query.udp(query, resolver, timeout=timeout)


def send_tcp(query: dns.message.Message, resolver: str, timeout: float) -> dns.message.Message:
    return dns.query.tcp(query, resolver, timeout=timeout)


def lookup(name: str, rdtype: str) -> dns.message.Message | None:
    """Ask the public resolvers in turn. None means no usable answer was had.

    The DO bit asks for the signing records. The CD bit asks the resolver to
    hand over what it found even when its own validation fails: without it a
    zone whose signatures have expired gives only an error, and the expiry
    could never be seen. Blocking: call it through asyncio.to_thread.
    """
    try:
        query = dns.message.make_query(name, rdtype, want_dnssec=True, payload=EDNS_PAYLOAD)
    except (dns.exception.DNSException, ValueError):
        return None
    query.flags |= dns.flags.CD
    for resolver in PUBLIC_RESOLVERS:
        try:
            response = send_udp(query, resolver, TIMEOUT_S)
            if response.flags & dns.flags.TC:
                response = send_tcp(query, resolver, TIMEOUT_S)
        except (dns.exception.DNSException, OSError, EOFError):
            continue
        if response.flags & dns.flags.TC:
            continue
        # SERVFAIL, REFUSED and the rest say nothing about the zone itself.
        if response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return response
    return None


def random_label() -> str:
    """A label that cannot already exist in anyone's zone."""
    return secrets.token_hex(12)


def clean_name(name: dns.name.Name) -> str | None:
    """A name from an answer as a checked hostname, or None if it is not one."""
    try:
        text = name.to_text(omit_final_dot=True)
    except dns.exception.DNSException:
        return None
    if len(text) > 253:
        return None
    try:
        return validate_hostname(text, allow_reserved=True)
    except ValidationError:
        return None


def rdatas(
    section: list[dns.rrset.RRset],
    rdtype: dns.rdatatype.RdataType,
    owner: dns.name.Name | None = None,
    covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
) -> list[tuple[dns.name.Name, dns.rdata.Rdata]]:
    """Records of one type from a section, with their owner names. Capped."""
    out: list[tuple[dns.name.Name, dns.rdata.Rdata]] = []
    for rrset in section:
        if rrset.rdtype != rdtype or rrset.covers != covers:
            continue
        if owner is not None and rrset.name != owner:
            continue
        for rdata in rrset:
            if len(out) >= MAX_RECORDS:
                return out
            out.append((rrset.name, rdata))
    return out


def rsa_bits(key: bytes) -> int | None:
    """Length of the modulus of an RSA key laid out as in RFC 3110 section 2.

    The key starts with the length of the exponent: one octet, or a zero octet
    followed by two octets. The exponent follows, and the rest is the modulus.
    """
    if len(key) < 3 or len(key) > 4096:
        return None
    if key[0]:
        exponent_length, start = key[0], 1
    else:
        exponent_length, start = int.from_bytes(key[1:3], "big"), 3
    modulus = key[start + exponent_length :]
    if not exponent_length or not modulus:
        return None
    return int.from_bytes(modulus, "big").bit_length()


def key_problems(keys: list[DNSKEY]) -> list[str]:
    problems: set[str] = set()
    for key in keys:
        if not key.flags & FLAG_ZONE_KEY or key.flags & FLAG_REVOKED:
            continue
        algorithm = int(key.algorithm)
        if algorithm in MUST_NOT_SIGN:
            problems.add(
                f"A signing key uses {MUST_NOT_SIGN[algorithm]} (algorithm {algorithm}), "
                "which must no longer be used"
            )
        if algorithm in RSA_ALGORITHMS:
            bits = rsa_bits(key.key)
            if bits is not None and bits < MIN_RSA_BITS:
                problems.add(
                    f"An RSA signing key is {bits} bits long, shorter than {MIN_RSA_BITS} bits"
                )
    return sorted(problems)


def ds_problems(records: list[DS]) -> list[str]:
    problems: set[str] = set()
    for record in records:
        digest = int(record.digest_type)
        algorithm = int(record.algorithm)
        if digest in MUST_NOT_DIGEST:
            problems.add(
                f"The record at the registry that vouches for the zone's key uses a "
                f"{MUST_NOT_DIGEST[digest]} fingerprint (digest type {digest}), "
                "which must no longer be used"
            )
        if algorithm in MUST_NOT_SIGN:
            problems.add(
                f"The record at the registry points to a key using {MUST_NOT_SIGN[algorithm]} "
                f"(algorithm {algorithm}), which must no longer be used"
            )
    return sorted(problems)


def signature_bucket(
    expires: datetime, now: datetime, valid_for: timedelta | None = None
) -> str | None:
    """The bucket a signature falls in, or None if it has time enough left.

    `valid_for` is how long the signature was made to last. Providers that sign
    each answer as it is asked for, Cloudflare among them, make signatures
    that last about two days and replace them all the time. Such a signature
    always expires within a week, and that says nothing about the zone's
    health. So a signature counts towards a bucket only if it was made to
    last longer than the bucket's window. One that has expired always counts.
    """
    days = (expires - now).total_seconds() / 86400
    if days < 0:
        return "expired"
    for limit, label in BUCKETS:
        if days <= limit and (valid_for is None or valid_for > timedelta(days=limit)):
            return label
    return None


@dataclass(frozen=True)
class Denial:
    """How the zone proved that a name does not exist."""

    # compact | nsec | nsec3 | minimal | unknown
    method: str
    iterations: int | None = None
    # Two real names from the zone that the answer gave away, for display.
    neighbours: tuple[str, str] | None = None


def _within(name: dns.name.Name, zone: dns.name.Name) -> bool:
    return name == zone or name.is_subdomain(zone)


def classify_denial(
    response: dns.message.Message, qname: dns.name.Name, zone: dns.name.Name
) -> Denial:
    """Read the proof that `qname` does not exist.

    Plain NSEC (RFC 4035 section 3.1.3.2): the records that cover the name are
    owned by the real name before it and point to the real name after it.
    Asking again for a name just past that one gives the next pair, and so on
    through the whole zone.

    Compact denial of existence (RFC 9824 section 3.1): the server claims that
    the name exists with no records, and makes up an NSEC record whose owner
    is the name that was asked for. It names no neighbour, so nothing can be
    listed. RFC 9824 section 2 adds the NXNAME type (128) to the record's type
    list. Older deployments leave it out, so the owner name decides, not the
    type list. The response code is NOERROR, or NXDOMAIN where the resolver
    restores it (section 5.1).

    Minimally covering NSEC (RFC 4470 sections 3 and 4): the owner and the next
    name are made up to sit just either side of the name asked for. They
    contain octets that no hostname has, so they fail the hostname check here.
    """
    nsec = rdatas(response.authority, dns.rdatatype.NSEC)
    nsec3 = rdatas(response.authority, dns.rdatatype.NSEC3)

    if any(owner == qname for owner, _ in nsec):
        return Denial("compact")

    iterations = [
        int(rdata.iterations)
        for owner, rdata in nsec3
        if isinstance(rdata, NSEC3) and _within(owner, zone)
    ]
    if iterations:
        return Denial("nsec3", iterations=max(iterations))

    seen_nsec = False
    for owner, rdata in nsec:
        if not isinstance(rdata, NSEC) or not _within(owner, zone):
            continue
        seen_nsec = True
        if rdata.next == qname or not _within(rdata.next, zone):
            continue
        before, after = clean_name(owner), clean_name(rdata.next)
        if before is not None and after is not None:
            return Denial("nsec", neighbours=(before, after))
    return Denial("minimal" if seen_nsec else "unknown")


@register
class DnssecQuality(ScanModule):
    spec = ModuleSpec(
        name="dnssec_quality",
        title="DNSSEC signing quality",
        category=Category.SURFACE,
        mode=ScanMode.PASSIVE,
        description=(
            "For a signed zone: whether the signing algorithm is still trusted, whether "
            "the signatures are about to lapse, and whether the zone can be listed."
        ),
        contacts=("public DNS resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9), at most four lookups",),
        default_timeout_s=120,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        zone = registrable_domain(target.root_domain)
        zone_name = dns.name.from_text(zone)
        notes: list[str] = []
        findings: list[Finding] = []
        partial = False

        key_answer, ds_answer = await asyncio.gather(
            asyncio.to_thread(lookup, zone, "DNSKEY"),
            asyncio.to_thread(lookup, zone, "DS"),
        )
        lookups = 2
        keys: list[DNSKEY] = []
        delegations: list[DS] = []
        if key_answer is None:
            partial = True
            notes.append(
                "The zone's signing keys could not be looked up, so they were not checked."
            )
        else:
            keys = [
                rdata
                for _, rdata in rdatas(key_answer.answer, dns.rdatatype.DNSKEY, zone_name)
                if isinstance(rdata, DNSKEY)
            ]
        if ds_answer is None:
            partial = True
            notes.append(
                "The record at the registry that vouches for the zone's key could not be "
                "looked up, so it was not checked."
            )
        else:
            delegations = [
                rdata
                for _, rdata in rdatas(ds_answer.answer, dns.rdatatype.DS, zone_name)
                if isinstance(rdata, DS)
            ]

        if not keys and not delegations:
            if key_answer is not None and ds_answer is not None:
                notes.append(f"{zone} is not signed with DNSSEC, so there was nothing to check.")
            return self.result(
                ModuleStatus.PARTIAL if partial else ModuleStatus.OK,
                notes=notes,
                stats={"lookups": lookups},
            )

        problems = sorted({*key_problems(keys), *ds_problems(delegations)})
        if problems:
            findings.append(
                self.finding(
                    "dns.dnssec.weak_algorithm",
                    AssetType.DOMAIN,
                    zone,
                    f"{zone} is signed in a way that resolvers no longer trust",
                    state={"problems": problems},
                    evidence={
                        "problems": problems,
                        "why_it_matters": (
                            "Resolvers treat a zone signed like this as if it were not "
                            "signed at all, so forged answers are not detected."
                        ),
                        "key_algorithms": sorted({int(k.algorithm) for k in keys}),
                    },
                    confidence=Confidence.CONFIRMED,
                )
            )

        if not keys:
            if key_answer is not None:
                notes.append(
                    f"The registry vouches for a signing key, but {zone} publishes none. "
                    "Signatures and listing were not checked."
                )
            return self.result(
                ModuleStatus.PARTIAL if partial else ModuleStatus.OK,
                findings=findings,
                notes=notes,
                stats={"lookups": lookups},
            )

        probe = f"{random_label()}.{zone}"
        soa_answer, denial_answer = await asyncio.gather(
            asyncio.to_thread(lookup, zone, "SOA"),
            asyncio.to_thread(lookup, probe, "A"),
        )
        lookups += 2

        # -- signatures ---------------------------------------------------
        signatures: list[tuple[str, RRSIG]] = []
        for label, answer, covered in (
            ("DNSKEY", key_answer, dns.rdatatype.DNSKEY),
            ("SOA", soa_answer, dns.rdatatype.SOA),
        ):
            if answer is None:
                continue
            for _, rdata in rdatas(answer.answer, dns.rdatatype.RRSIG, zone_name, covered):
                # A signature by another zone's key proves nothing about this one.
                if isinstance(rdata, RRSIG) and rdata.signer == zone_name:
                    signatures.append((label, rdata))
        if soa_answer is None:
            partial = True
            notes.append(
                "The zone's main record could not be looked up, so its signature was not checked."
            )
        if not signatures:
            partial = True
            notes.append("No signatures came back, so their expiry could not be checked.")
        else:
            finding = self._signature_finding(zone, signatures)
            if finding is not None:
                findings.append(finding)

        # -- listing --------------------------------------------------------
        if denial_answer is None:
            partial = True
            notes.append(
                "The lookup that shows how the zone answers for a missing name failed, "
                "so listing was not checked."
            )
        else:
            denial = classify_denial(denial_answer, dns.name.from_text(probe), zone_name)
            findings.extend(self._denial_findings(zone, denial, notes))

        return self.result(
            ModuleStatus.PARTIAL if partial else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={"lookups": lookups},
        )

    def _signature_finding(self, zone: str, signatures: list[tuple[str, RRSIG]]) -> Finding | None:
        """One finding for the signature that runs out soonest, if any is close."""
        now = utcnow()
        due: list[tuple[int, datetime, str]] = []
        for record, signature in signatures:
            try:
                expires = datetime.fromtimestamp(signature.expiration, UTC)
                made = datetime.fromtimestamp(signature.inception, UTC)
            except (OverflowError, OSError, ValueError):
                continue
            found = signature_bucket(expires, now, expires - made)
            if found is not None:
                due.append((BUCKET_ORDER.index(found), expires, record))
        if not due:
            return None
        rank, expires, label = min(due)
        bucket = BUCKET_ORDER[rank]
        if bucket == "expired":
            title = f"A signature on the {zone} zone has expired"
            note = "The signature has already lapsed."
        else:
            title = f"A signature on the {zone} zone expires within {bucket[:-1]} days"
            note = "Less than three days remain."
        urgent = bucket in ("3d", "expired")
        return self.finding(
            "dns.dnssec.signature_expiring",
            AssetType.DOMAIN,
            zone,
            title,
            state={"bucket": bucket},
            evidence={
                "expires_on": expires.date().isoformat(),
                "signed_record": label,
                "why_it_matters": (
                    "Once a signature lapses, resolvers that check DNSSEC refuse every "
                    "answer from the zone, and the domain stops working for their users."
                ),
            },
            confidence=Confidence.CONFIRMED,
            severity_steps=1 if urgent else 0,
            severity_note=note if urgent else None,
        )

    def _denial_findings(self, zone: str, denial: Denial, notes: list[str]) -> list[Finding]:
        if denial.method == "nsec" and denial.neighbours is not None:
            before, after = denial.neighbours
            return [
                self.finding(
                    "dns.dnssec.zone_walkable",
                    AssetType.DOMAIN,
                    zone,
                    f"Anyone can list every name in the {zone} zone",
                    state={"method": "nsec"},
                    evidence={
                        "how": (
                            "Asked for a name that does not exist, the zone answers with "
                            "the real names either side of it. Repeating this walks "
                            "through the whole zone. Only one such question was asked."
                        ),
                        "names_given_away": [before, after],
                        "why_it_matters": (
                            "A full list of names shows an attacker every host you have, "
                            "including ones meant to be hard to find."
                        ),
                    },
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if denial.method == "nsec3" and denial.iterations:
            # RFC 9276 section 3.1: "If NSEC3 must be used, then an iterations
            # count of 0 MUST be used". Section 3.2 lets resolvers treat a zone
            # with a higher count as unsigned, or refuse to answer for it.
            return [
                self.finding(
                    "dns.dnssec.nsec3_iterations",
                    AssetType.DOMAIN,
                    zone,
                    f"The {zone} zone uses {denial.iterations} extra NSEC3 iterations",
                    state={"iterations": denial.iterations},
                    evidence={
                        "iterations": denial.iterations,
                        "recommended": 0,
                        "why_it_matters": (
                            "Extra iterations were meant to make names harder to guess, "
                            "but add no real protection. Resolvers may treat such a zone "
                            "as unsigned, or fail to answer for it."
                        ),
                    },
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if denial.method == "unknown":
            notes.append(
                "The answer for a missing name carried no proof of absence, so whether "
                "the zone can be listed could not be told. A wildcard record can cause this."
            )
        return []
