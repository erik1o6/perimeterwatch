"""DNSSEC signing quality and nameserver health. No network: every answer is built here."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from perimeterwatch.core.models import (
    Category,
    Confidence,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
)
from perimeterwatch.modules import dnssec_quality, nameserver_health
from perimeterwatch.modules.dnssec_quality import (
    DnssecQuality,
    classify_denial,
    rsa_bits,
    signature_bucket,
)
from perimeterwatch.modules.nameserver_health import NameserverHealth
from tests.conftest import ROOT

TARGET = Target(root_domain=ROOT)
ZONE = dns.name.from_text(ROOT)
PROBE_LABEL = "0123456789abcdef01234567"
PROBE = f"{PROBE_LABEL}.{ROOT}"
NOW = datetime.now(UTC)

ECDSA_KEY = base64.b64encode(bytes(range(64))).decode()
SIGNATURE = base64.b64encode(bytes(64)).decode()


def rsa_key(bits: int) -> str:
    """An RSA key in the layout of RFC 3110: exponent length, exponent, modulus."""
    modulus = b"\x80" + bytes(bits // 8 - 1)
    return base64.b64encode(b"\x03\x01\x00\x01" + modulus).decode()


def rr(name: str, rdtype: str, *values: str, ttl: int = 300) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        name if name.endswith(".") else name + ".", ttl, "IN", rdtype, *values
    )


def reply(
    name: str,
    rdtype: str,
    *,
    answer: list[dns.rrset.RRset] | None = None,
    authority: list[dns.rrset.RRset] | None = None,
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
    flags: int = 0,
    recursion_desired: bool = True,
) -> dns.message.Message:
    query = dns.message.make_query(name, rdtype)
    if not recursion_desired:
        query.flags &= ~dns.flags.RD
    message = dns.message.make_response(query)
    message.flags |= flags
    message.set_rcode(rcode)
    message.answer.extend(answer or [])
    message.authority.extend(authority or [])
    return message


def stamp(when: datetime) -> str:
    return when.strftime("%Y%m%d%H%M%S")


def rrsig(
    covered: str,
    expires: datetime,
    *,
    owner: str = ROOT,
    signer: str = ROOT,
    valid_for: timedelta = timedelta(days=14),
) -> dns.rrset.RRset:
    labels = len(owner.rstrip(".").split("."))
    text = (
        f"{covered} 13 {labels} 300 {stamp(expires)} {stamp(expires - valid_for)} "
        f"34505 {signer}. {SIGNATURE}"
    )
    return rr(owner, "RRSIG", text)


def soa(serial: int = 2415557203, zone: str = ROOT) -> dns.rrset.RRset:
    return rr(zone, "SOA", f"ns1.dnshost.net. dns.dnshost.net. {serial} 10000 2400 604800 300")


def findings_text(result: ModuleResult) -> str:
    return json.dumps([f.model_dump(mode="json") for f in result.findings])


def assert_clean(result: ModuleResult) -> None:
    """Nothing hostile reached a finding or a note."""
    text = findings_text(result) + json.dumps(result.notes)
    assert "\\\\" not in text, "an escaped octet from a DNS name got through"
    assert "\\u00" not in text, "a control character got through"
    assert "<script" not in text
    assert all(len(word) < 260 for word in text.split())


# ---------------------------------------------------------------------------
# dnssec_quality
# ---------------------------------------------------------------------------


class FakeResolvers:
    """Stands in for the public resolvers. Anything not listed times out."""

    def __init__(self) -> None:
        self.udp: dict[tuple[str, str], Any] = {}
        self.tcp: dict[tuple[str, str], Any] = {}
        self.calls: list[tuple[str, str, str, str]] = []
        self.queries: list[dns.message.Message] = []

    @staticmethod
    def key(query: dns.message.Message) -> tuple[str, str]:
        question = query.question[0]
        return (
            question.name.to_text(omit_final_dot=True).lower(),
            dns.rdatatype.to_text(question.rdtype),
        )

    def add(self, message: dns.message.Message, *, tcp: bool = False) -> None:
        (self.tcp if tcp else self.udp)[self.key(message)] = message

    def fail(self, name: str, rdtype: str, outcome: Any) -> None:
        self.udp[(name, rdtype)] = outcome
        self.tcp[(name, rdtype)] = outcome

    def _answer(
        self, table: dict[tuple[str, str], Any], how: str, query: Any, resolver: str
    ) -> Any:
        key = self.key(query)
        self.calls.append((how, resolver, *key))
        self.queries.append(query)
        outcome = table.get(key, dns.exception.Timeout())
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def send_udp(self, query: Any, resolver: str, timeout: float) -> Any:
        return self._answer(self.udp, "udp", query, resolver)

    def send_tcp(self, query: Any, resolver: str, timeout: float) -> Any:
        return self._answer(self.tcp, "tcp", query, resolver)


@pytest.fixture
def resolvers(monkeypatch: pytest.MonkeyPatch) -> FakeResolvers:
    fake = FakeResolvers()
    monkeypatch.setattr(dnssec_quality, "send_udp", fake.send_udp)
    monkeypatch.setattr(dnssec_quality, "send_tcp", fake.send_tcp)
    monkeypatch.setattr(dnssec_quality, "random_label", lambda: PROBE_LABEL)
    return fake


def compact_denial(name: str = PROBE, zone: str = ROOT) -> dns.message.Message:
    """The answer Cloudflare gives for a missing name, as seen through 1.1.1.1.

    NOERROR with an empty answer. The NSEC record is owned by the name that was
    asked for, points to that name with a zero octet label in front, and lists
    RRSIG, NSEC and type 128 (NXNAME).
    """
    expires = NOW + timedelta(days=1, hours=2)
    short = timedelta(days=2, hours=2)
    return reply(
        name,
        "A",
        flags=dns.flags.RA | dns.flags.AD,
        authority=[
            soa(zone=zone),
            rrsig("SOA", expires, owner=zone, signer=zone, valid_for=short),
            rr(name, "NSEC", f"\\000.{name}. RRSIG NSEC TYPE128"),
            rrsig("NSEC", expires, owner=name, signer=zone, valid_for=short),
        ],
    )


def plain_nsec_denial() -> dns.message.Message:
    """NXDOMAIN with two NSEC records that name real neighbours."""
    expires = NOW + timedelta(days=30)
    return reply(
        PROBE,
        "A",
        rcode=dns.rcode.NXDOMAIN,
        flags=dns.flags.RA,
        authority=[
            soa(),
            rrsig("SOA", expires),
            rr(f"mail.{ROOT}", "NSEC", f"sip.{ROOT}. A AAAA RRSIG NSEC"),
            rrsig("NSEC", expires, owner=f"mail.{ROOT}"),
            rr(ROOT, "NSEC", f"_dmarc.{ROOT}. A NS SOA MX TXT RRSIG NSEC DNSKEY"),
            rrsig("NSEC", expires),
        ],
    )


def nsec3_denial(iterations: int, salt: str = "-") -> dns.message.Message:
    rows = [
        ("4pabpkb9qfiu07timlng6l146arruuvn", "4pjsmcs7tu2a3mbd53l8cjkldatjp2mn", "A NS SOA RRSIG"),
        ("gom6ddlfr3ktmi9aql15vf7k6pe936jh", "gqvvlpk9qi9ld67o1ss5kl6jpctm1te8", "A RRSIG"),
        ("0g905rgle0ob9p7tim6511el0vhepk8p", "0jm5pi47l6q9n8el2ej7e9etc6n0i9dk", "MX RRSIG"),
    ]
    return reply(
        PROBE,
        "A",
        rcode=dns.rcode.NXDOMAIN,
        flags=dns.flags.RA,
        authority=[soa()]
        + [
            rr(f"{owner}.{ROOT}", "NSEC3", f"1 0 {iterations} {salt} {nxt} {types}")
            for owner, nxt, types in rows
        ],
    )


def sign(
    resolvers: FakeResolvers,
    *,
    keys: list[str] | None = None,
    ds: list[str] | None = None,
    expires: datetime | None = None,
    denial: dns.message.Message | None = None,
) -> None:
    """A healthy signed zone unless told otherwise."""
    expires = expires or NOW + timedelta(days=30)
    keys = keys if keys is not None else [f"256 3 13 {ECDSA_KEY}", f"257 3 13 {ECDSA_KEY}"]
    ds = ds if ds is not None else ["2371 13 2 " + "ab" * 32]
    resolvers.add(
        reply(ROOT, "DNSKEY", answer=[rr(ROOT, "DNSKEY", *keys), rrsig("DNSKEY", expires)])
        if keys
        else reply(ROOT, "DNSKEY", authority=[soa()])
    )
    resolvers.add(
        reply(ROOT, "DS", answer=[rr(ROOT, "DS", *ds)])
        if ds
        else reply(ROOT, "DS", authority=[soa(zone="xyz")])
    )
    resolvers.add(reply(ROOT, "SOA", answer=[soa(), rrsig("SOA", expires)]))
    resolvers.add(denial or compact_denial())


async def run_dnssec(make_ctx: Any) -> ModuleResult:
    return await DnssecQuality().run(TARGET, make_ctx())


class TestDnssecQuality:
    def test_spec(self) -> None:
        assert DnssecQuality.spec.mode is ScanMode.PASSIVE
        assert DnssecQuality.spec.category is Category.SURFACE

    async def test_unsigned_zone_gives_no_findings(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers, keys=[], ds=[])
        result = await run_dnssec(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.OK
        assert any("not signed" in note for note in result.notes)
        asked = {(name, rdtype) for _, _, name, rdtype in resolvers.calls}
        assert asked == {(ROOT, "DNSKEY"), (ROOT, "DS")}, "an unsigned zone gets no further lookups"

    async def test_healthy_zone_gives_no_findings(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers)
        result = await run_dnssec(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.OK
        assert result.stats == {"lookups": 4}

    async def test_queries_ask_for_signing_records(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers)
        await run_dnssec(make_ctx)
        assert {resolver for _, resolver, _, _ in resolvers.calls} == {"1.1.1.1"}
        for query in resolvers.queries:
            assert query.ednsflags & dns.flags.DO
            assert query.flags & dns.flags.CD

    @pytest.mark.parametrize(
        "keys",
        [
            [f"256 3 13 {ECDSA_KEY}", f"257 3 13 {ECDSA_KEY}"],
            [f"256 3 8 {rsa_key(2048)}", f"257 3 8 {rsa_key(2048)}"],
            [f"257 3 15 {base64.b64encode(bytes(32)).decode()}"],
        ],
    )
    async def test_current_algorithms_are_not_reported(
        self, make_ctx: Any, resolvers: FakeResolvers, keys: list[str]
    ) -> None:
        sign(resolvers, keys=keys)
        assert (await run_dnssec(make_ctx)).findings == []

    @pytest.mark.parametrize(
        ("keys", "expected"),
        [
            ([f"257 3 5 {rsa_key(2048)}"], "RSASHA1 (algorithm 5)"),
            ([f"257 3 7 {rsa_key(2048)}"], "RSASHA1-NSEC3-SHA1 (algorithm 7)"),
            ([f"257 3 3 {ECDSA_KEY}"], "DSA (algorithm 3)"),
            ([f"257 3 12 {ECDSA_KEY}"], "ECC-GOST (algorithm 12)"),
            ([f"256 3 8 {rsa_key(1024)}", f"257 3 8 {rsa_key(2048)}"], "1024 bits"),
        ],
    )
    async def test_weak_keys(
        self, make_ctx: Any, resolvers: FakeResolvers, keys: list[str], expected: str
    ) -> None:
        sign(resolvers, keys=keys)
        [finding] = (await run_dnssec(make_ctx)).findings
        assert finding.kind == "dns.dnssec.weak_algorithm"
        assert finding.severity is Severity.MEDIUM
        [problem] = finding.state["problems"]
        assert expected in problem

    async def test_sha1_ds_and_state_is_sorted(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(
            resolvers,
            keys=[f"257 3 8 {rsa_key(1024)}", f"256 3 5 {rsa_key(2048)}"],
            ds=["2371 8 1 " + "ab" * 20, "2371 8 2 " + "ab" * 32],
        )
        [finding] = (await run_dnssec(make_ctx)).findings
        problems = finding.state["problems"]
        assert len(problems) == 3 and problems == sorted(problems)
        assert any("SHA-1" in p and "digest type 1" in p for p in problems)

    async def test_revoked_and_non_zone_keys_are_ignored(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(
            resolvers,
            keys=[f"385 3 5 {rsa_key(1024)}", f"0 3 5 {rsa_key(1024)}", f"257 3 13 {ECDSA_KEY}"],
        )
        assert (await run_dnssec(make_ctx)).findings == []

    def test_rsa_key_length(self) -> None:
        assert rsa_bits(base64.b64decode(rsa_key(2048))) == 2048
        assert rsa_bits(base64.b64decode(rsa_key(1024))) == 1024
        long_exponent = b"\x00\x01\x00" + bytes(255) + b"\x01" + b"\x80" + bytes(255)
        assert rsa_bits(long_exponent) == 2048
        assert rsa_bits(b"") is None and rsa_bits(b"\x03\x01\x00\x01") is None
        assert rsa_bits(bytes(5000)) is None

    @pytest.mark.parametrize(
        ("remaining", "bucket"),
        [
            (timedelta(days=7, seconds=1), None),
            (timedelta(days=7), "7d"),
            (timedelta(days=3, seconds=1), "7d"),
            (timedelta(days=3), "3d"),
            (timedelta(seconds=0), "3d"),
            (timedelta(seconds=-1), "expired"),
            (timedelta(days=-400), "expired"),
            (timedelta(days=30), None),
        ],
    )
    def test_signature_buckets(self, remaining: timedelta, bucket: str | None) -> None:
        assert signature_bucket(NOW + remaining, NOW) == bucket

    @pytest.mark.parametrize(
        ("remaining", "bucket", "severity"),
        [
            (timedelta(days=6), "7d", Severity.MEDIUM),
            (timedelta(days=2), "3d", Severity.HIGH),
            (timedelta(days=-2), "expired", Severity.HIGH),
        ],
    )
    async def test_signature_expiring(
        self,
        make_ctx: Any,
        resolvers: FakeResolvers,
        remaining: timedelta,
        bucket: str,
        severity: Severity,
    ) -> None:
        sign(resolvers, expires=NOW + remaining, denial=nsec3_denial(0))
        [finding] = (await run_dnssec(make_ctx)).findings
        assert finding.kind == "dns.dnssec.signature_expiring"
        assert finding.state == {"bucket": bucket}, "the date itself must stay out of the state"
        assert finding.severity is severity
        assert (finding.severity_note is not None) == (severity is Severity.HIGH)

    @pytest.mark.parametrize(
        ("valid_for", "remaining", "bucket"),
        [
            # Signed as asked for, as Cloudflare does: two days, always about to expire.
            (timedelta(days=2, hours=2), timedelta(days=1, hours=2), None),
            (timedelta(days=2, hours=2), timedelta(seconds=-5), "expired"),
            (timedelta(days=5), timedelta(days=2), "3d"),
            (timedelta(days=5), timedelta(days=4), None),
            (timedelta(days=3), timedelta(days=1), None),
            (timedelta(days=7), timedelta(days=5), None),
            (timedelta(days=7, seconds=1), timedelta(days=5), "7d"),
        ],
    )
    def test_short_lived_signatures(
        self, valid_for: timedelta, remaining: timedelta, bucket: str | None
    ) -> None:
        assert signature_bucket(NOW + remaining, NOW, valid_for) == bucket

    async def test_zone_signed_as_asked_for_is_not_reported(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        """The shape of cloudflare.com: a long-lived key signature, a two day SOA signature."""
        sign(resolvers)
        short = rrsig("SOA", NOW + timedelta(days=1), valid_for=timedelta(days=2, hours=2))
        resolvers.add(reply(ROOT, "SOA", answer=[soa(), short]))
        result = await run_dnssec(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.OK

    async def test_soonest_signature_decides(self, make_ctx: Any, resolvers: FakeResolvers) -> None:
        sign(resolvers)
        resolvers.add(reply(ROOT, "SOA", answer=[soa(), rrsig("SOA", NOW + timedelta(days=5))]))
        [finding] = (await run_dnssec(make_ctx)).findings
        assert finding.state == {"bucket": "7d"} and finding.evidence["signed_record"] == "SOA"

    async def test_signature_by_another_zone_is_ignored(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers)
        resolvers.add(
            reply(
                ROOT,
                "SOA",
                answer=[
                    soa(),
                    rrsig("SOA", NOW + timedelta(days=30)),
                    rrsig("SOA", NOW - timedelta(days=9), signer="evil.example.net"),
                ],
            )
        )
        assert (await run_dnssec(make_ctx)).findings == []

    async def test_compact_denial_is_not_walkable(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers, denial=compact_denial())
        result = await run_dnssec(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.OK

    def test_compact_denial_shapes(self) -> None:
        qname = dns.name.from_text(PROBE)
        assert classify_denial(compact_denial(), qname, ZONE).method == "compact"
        # Older deployments leave out the NXNAME type.
        older = reply(PROBE, "A", authority=[rr(PROBE, "NSEC", f"\\000.{PROBE}. RRSIG NSEC")])
        assert classify_denial(older, qname, ZONE).method == "compact"
        # A resolver may restore the NXDOMAIN code (RFC 9824 section 5.1).
        restored = compact_denial()
        restored.set_rcode(dns.rcode.NXDOMAIN)
        assert classify_denial(restored, qname, ZONE).method == "compact"
        # Case differences in the owner name do not matter.
        shouting = reply(
            PROBE, "A", authority=[rr(PROBE.upper(), "NSEC", f"\\000.{PROBE}. RRSIG NSEC")]
        )
        assert classify_denial(shouting, qname, ZONE).method == "compact"

    async def test_minimally_covering_nsec_is_not_walkable(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        before = f"{PROBE_LABEL[:-1]}6" + "\\255" * 20 + f".{ROOT}"
        denial = reply(
            PROBE,
            "A",
            rcode=dns.rcode.NXDOMAIN,
            authority=[rr(before, "NSEC", f"\\000.{PROBE}. RRSIG NSEC")],
        )
        sign(resolvers, denial=denial)
        result = await run_dnssec(make_ctx)
        assert result.findings == []
        assert_clean(result)

    async def test_plain_nsec_is_walkable(self, make_ctx: Any, resolvers: FakeResolvers) -> None:
        sign(resolvers, denial=plain_nsec_denial())
        result = await run_dnssec(make_ctx)
        [finding] = result.findings
        assert finding.kind == "dns.dnssec.zone_walkable"
        assert finding.severity is Severity.LOW
        assert finding.evidence["names_given_away"] == [f"mail.{ROOT}", f"sip.{ROOT}"]
        probes = [c for c in resolvers.calls if c[2] == PROBE]
        assert len(probes) == 1, "one question only: the chain is never followed"
        assert not any(ROOT in c[2] and c[2] not in (ROOT, PROBE) for c in resolvers.calls)

    async def test_wildcard_answer_with_plain_nsec(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        denial = reply(
            PROBE,
            "A",
            answer=[rr(PROBE, "A", "104.18.0.1")],
            authority=[rr(f"mail.{ROOT}", "NSEC", f"sip.{ROOT}. A RRSIG NSEC")],
        )
        sign(resolvers, denial=denial)
        [finding] = (await run_dnssec(make_ctx)).findings
        assert finding.kind == "dns.dnssec.zone_walkable"

    async def test_no_proof_is_a_note(self, make_ctx: Any, resolvers: FakeResolvers) -> None:
        sign(resolvers, denial=reply(PROBE, "A", answer=[rr(PROBE, "A", "104.18.0.1")]))
        result = await run_dnssec(make_ctx)
        assert result.findings == []
        assert any("could not be told" in note for note in result.notes)

    async def test_nsec3_without_iterations(self, make_ctx: Any, resolvers: FakeResolvers) -> None:
        sign(resolvers, denial=nsec3_denial(0, salt="4c44934802d3"))
        result = await run_dnssec(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.OK

    @pytest.mark.parametrize("iterations", [1, 10, 500])
    async def test_nsec3_with_iterations(
        self, make_ctx: Any, resolvers: FakeResolvers, iterations: int
    ) -> None:
        sign(resolvers, denial=nsec3_denial(iterations, salt="ee"))
        [finding] = (await run_dnssec(make_ctx)).findings
        assert finding.kind == "dns.dnssec.nsec3_iterations"
        assert finding.state == {"iterations": iterations}

    async def test_nsec3_from_another_zone_is_ignored(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        denial = reply(
            PROBE,
            "A",
            rcode=dns.rcode.NXDOMAIN,
            authority=[
                rr("abc.example.net", "NSEC3", "1 0 50 - 4pjsmcs7tu2a3mbd53l8cjkldatjp2mn A")
            ],
        )
        sign(resolvers, denial=denial)
        assert (await run_dnssec(make_ctx)).findings == []

    @pytest.mark.parametrize(
        "failure",
        [
            dns.exception.Timeout(),
            OSError("network is unreachable"),
            dns.message.BadEDNS(),
            reply(ROOT, "DNSKEY", rcode=dns.rcode.SERVFAIL),
            reply(ROOT, "DNSKEY", rcode=dns.rcode.REFUSED),
        ],
    )
    @pytest.mark.parametrize("broken", ["DNSKEY", "DS", "SOA", "probe", "all"])
    async def test_failures_never_produce_findings(
        self, make_ctx: Any, resolvers: FakeResolvers, failure: Any, broken: str
    ) -> None:
        sign(resolvers)
        names = {
            "DNSKEY": (ROOT, "DNSKEY"),
            "DS": (ROOT, "DS"),
            "SOA": (ROOT, "SOA"),
            "probe": (PROBE, "A"),
        }
        for label, key in names.items():
            if broken in (label, "all"):
                resolvers.fail(*key, failure)
        result = await run_dnssec(make_ctx)
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL
        assert result.notes

    async def test_failed_key_lookup_is_not_read_as_unsigned(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers, ds=[])
        resolvers.fail(ROOT, "DNSKEY", dns.exception.Timeout())
        result = await run_dnssec(make_ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert not any("not signed" in note for note in result.notes)

    async def test_next_resolver_is_tried(
        self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[str] = []

        def udp(query: Any, resolver: str, timeout: float) -> Any:
            asked.append(resolver)
            if resolver == "1.1.1.1":
                raise dns.exception.Timeout()
            if resolver == "8.8.8.8":
                return reply(ROOT, "DNSKEY", rcode=dns.rcode.SERVFAIL)
            return reply(ROOT, "DNSKEY", answer=[rr(ROOT, "DNSKEY", f"257 3 13 {ECDSA_KEY}")])

        monkeypatch.setattr(dnssec_quality, "send_udp", udp)
        answer = dnssec_quality.lookup(ROOT, "DNSKEY")
        assert answer is not None and answer.answer
        assert asked == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    async def test_truncated_answer_is_asked_again_over_tcp(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers, keys=[f"257 3 5 {rsa_key(2048)}"])
        full = resolvers.udp[(ROOT, "DNSKEY")]
        resolvers.add(full, tcp=True)
        resolvers.add(reply(ROOT, "DNSKEY", flags=dns.flags.TC))
        result = await run_dnssec(make_ctx)
        assert ("tcp", "1.1.1.1", ROOT, "DNSKEY") in resolvers.calls
        assert [c[0] for c in resolvers.calls if c[3] != "DNSKEY"].count("tcp") == 0
        [finding] = result.findings
        assert finding.kind == "dns.dnssec.weak_algorithm"
        assert result.status is ModuleStatus.OK

    async def test_truncated_with_tcp_failing_is_partial(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        sign(resolvers, keys=[f"257 3 5 {rsa_key(2048)}"])
        resolvers.add(reply(ROOT, "DNSKEY", flags=dns.flags.TC))
        result = await run_dnssec(make_ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert not any(f.kind == "dns.dnssec.weak_algorithm" for f in result.findings)

    async def test_hostile_denial_never_reaches_a_finding(
        self, make_ctx: Any, resolvers: FakeResolvers
    ) -> None:
        # As long as a name can be on the wire, and full of octets no hostname has.
        long_name = ".".join(["\\255" * 63] * 3) + f".{'b' * 30}.{ROOT}"
        denial = reply(
            PROBE,
            "A",
            rcode=dns.rcode.NXDOMAIN,
            authority=[
                rr(f"evil\\010\\027name.{ROOT}", "NSEC", f"zzz.{ROOT}. A RRSIG NSEC"),
                rr(f"aaa.{ROOT}", "NSEC", f"\\<script\\>alert\\(1\\).{ROOT}. A RRSIG NSEC"),
                rr(f"bbb.{ROOT}", "NSEC", f"a\\ b\\;rm.{ROOT}. A RRSIG NSEC"),
                rr(f"ccc.{ROOT}", "NSEC", f"{long_name}. A RRSIG NSEC"),
                rr("www.example.net", "NSEC", "zzz.example.net. A RRSIG NSEC"),
                rr(f"ddd.{ROOT}", "NSEC", "zzz.example.net. A RRSIG NSEC"),
            ],
        )
        sign(resolvers, denial=denial)
        result = await run_dnssec(make_ctx)
        assert result.findings == []
        assert_clean(result)

    async def test_record_counts_are_capped(self, make_ctx: Any, resolvers: FakeResolvers) -> None:
        many = [
            f"257 3 13 {base64.b64encode(i.to_bytes(2, 'big') + bytes(62)).decode()}"
            for i in range(200)
        ]
        weak = f"257 3 5 {rsa_key(2048)}"
        sign(resolvers, keys=[*many, weak])
        result = await run_dnssec(make_ctx)
        key_answer = resolvers.udp[(ROOT, "DNSKEY")]
        kept = dnssec_quality.rdatas(key_answer.answer, dns.rdatatype.DNSKEY, ZONE)
        assert len(kept) == dnssec_quality.MAX_RECORDS
        assert_clean(result)


# ---------------------------------------------------------------------------
# nameserver_health
# ---------------------------------------------------------------------------

NS1, NS2, NS3 = "ns1.dnshost.net", "ns2.dnshost.net", "ns3.internal-dns.net"
IP1, IP2, PRIVATE = "198.41.0.4", "198.41.0.5", "10.0.0.53"
REGISTRY, REGISTRY_IP = "a.nic.xyz", "192.5.6.30"


@dataclass
class FakeServer:
    """One nameserver address and how it behaves."""

    serial: int = 2024010101
    authoritative: bool = True
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR
    has_soa: bool = True
    udp: Any = True  # True, or an exception to raise
    tcp: Any = True
    zone_ns: list[str] = field(default_factory=lambda: [NS1, NS2])
    recursion_available: bool = False
    recursion_answer: bool = False
    recursion: Any = True
    # Set for a nameserver of the parent zone: the delegation it hands out.
    referral: list[str] | None = None
    referral_raw: list[dns.rrset.RRset] | None = None


class FakeNet:
    def __init__(self) -> None:
        self.servers: dict[str, FakeServer] = {}
        self.calls: list[tuple[str, str, str, str, bool]] = []

    def send(self, query: Any, address: str, tcp: bool, timeout: float) -> Any:
        question = query.question[0]
        name = question.name.to_text(omit_final_dot=True)
        rdtype = dns.rdatatype.to_text(question.rdtype)
        recurse = bool(query.flags & dns.flags.RD)
        self.calls.append((address, "tcp" if tcp else "udp", name, rdtype, recurse))
        assert address in self.servers, f"unexpected question sent to {address}"
        server = self.servers[address]
        transport = server.tcp if tcp else server.udp
        if isinstance(transport, BaseException):
            raise transport
        message = dns.message.make_response(query)

        if server.referral is not None or server.referral_raw is not None:
            assert not recurse and (name, rdtype) == (ROOT, "NS")
            message.authority.extend(
                server.referral_raw or [rr(ROOT, "NS", *(f"{n}." for n in server.referral or []))]
            )
            return message

        if recurse:
            assert name == "example.com", "the recursion question must be about the safe name"
            if isinstance(server.recursion, BaseException):
                raise server.recursion
            if server.recursion_available:
                message.flags |= dns.flags.RA
            if server.recursion_answer:
                message.answer.append(rr("example.com", "A", "93.184.215.14"))
            else:
                message.set_rcode(dns.rcode.REFUSED)
            return message

        assert name == ROOT
        message.set_rcode(server.rcode)
        if server.rcode != dns.rcode.NOERROR:
            return message
        if server.authoritative:
            message.flags |= dns.flags.AA
        if rdtype == "SOA" and server.has_soa:
            message.answer.append(soa(server.serial))
        if rdtype == "NS" and server.authoritative:
            message.answer.append(rr(ROOT, "NS", *(f"{n}." for n in server.zone_ns)))
        return message

    def asked(self, address: str) -> list[tuple[str, str, str, str, bool]]:
        return [c for c in self.calls if c[0] == address]


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch, dns: Any) -> FakeNet:
    fake = FakeNet()
    fake.servers[IP1] = FakeServer()
    fake.servers[IP2] = FakeServer()
    fake.servers[REGISTRY_IP] = FakeServer(referral=[NS1, NS2])
    monkeypatch.setattr(nameserver_health, "send", fake.send)
    dns.add("xyz", "NS", [f"{REGISTRY}."])
    dns.add(REGISTRY, "A", [REGISTRY_IP])
    dns.add(ROOT, "NS", [f"{NS1}.", f"{NS2}."])
    dns.add(NS1, "A", [IP1])
    dns.add(NS2, "A", [IP2])
    dns.add(NS3, "A", [PRIVATE])
    return fake


async def run_health(make_ctx: Any, **settings: Any) -> ModuleResult:
    ctx = make_ctx(mode=ScanMode.PROBE)
    for name, value in settings.items():
        setattr(ctx.settings, name, value)
    return await NameserverHealth().run(TARGET, ctx)


def kinds(result: ModuleResult) -> list[str]:
    return sorted(f.kind for f in result.findings)


class TestNameserverHealth:
    def test_spec(self) -> None:
        assert NameserverHealth.spec.mode is ScanMode.PROBE
        assert NameserverHealth.spec.category is Category.SURFACE
        assert "Probe depth, not passive" in (nameserver_health.__doc__ or "")

    async def test_healthy_servers(self, make_ctx: Any, net: FakeNet) -> None:
        result = await run_health(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.OK
        assert result.notes == []
        assert result.stats["nameservers_asked"] == 2

    async def test_cost_per_nameserver(self, make_ctx: Any, net: FakeNet) -> None:
        result = await run_health(make_ctx)
        for address in (IP1, IP2):
            asked = [(how, rdtype, recurse) for _, how, _, rdtype, recurse in net.asked(address)]
            assert sorted(asked) == sorted(
                [
                    ("udp", "SOA", False),
                    ("tcp", "SOA", False),
                    ("udp", "NS", False),
                    ("udp", "A", True),
                ]
            )
        assert len(net.asked(REGISTRY_IP)) == 1
        assert result.stats["queries_sent"] == len(net.calls) == 9

    async def test_second_address_stays_within_budget(
        self, make_ctx: Any, net: FakeNet, dns: Any
    ) -> None:
        extra = ["198.41.0.6", "198.41.0.7", "198.41.0.8"]
        dns.add(NS1, "A", [IP1, *extra])
        for address in extra:
            net.servers[address] = FakeServer()
        await run_health(make_ctx)
        to_ns1 = [c for c in net.calls if c[0] in (IP1, *extra)]
        assert len(to_ns1) == 6
        assert {c[0] for c in to_ns1} == {IP1, "198.41.0.6"}

    async def test_only_the_safe_name_is_asked_with_recursion(
        self, make_ctx: Any, net: FakeNet
    ) -> None:
        await run_health(make_ctx)
        for _, _, name, _, recurse in net.calls:
            assert recurse == (name == "example.com")

    @pytest.mark.parametrize(
        ("change", "reason"),
        [
            ({"authoritative": False}, "not_authoritative"),
            ({"rcode": dns.rcode.REFUSED}, "refused"),
            ({"has_soa": False}, "no_soa"),
        ],
    )
    async def test_lame_server(
        self, make_ctx: Any, net: FakeNet, change: dict[str, Any], reason: str
    ) -> None:
        net.servers[IP2] = FakeServer(**change)
        result = await run_health(make_ctx)
        [finding] = result.findings
        assert finding.kind == "dns.nameserver.lame"
        assert finding.identity == {"nameserver": NS2}
        assert finding.state == {"reason": reason}
        assert finding.severity is Severity.MEDIUM

    @pytest.mark.parametrize(
        "failure",
        [
            dns.exception.Timeout(),
            TimeoutError(),
            OSError("no route to host"),
            ConnectionRefusedError(),
            dns.message.ShortHeader(),
        ],
    )
    async def test_silent_server_is_not_lame(
        self, make_ctx: Any, net: FakeNet, failure: BaseException
    ) -> None:
        net.servers[IP2] = FakeServer(udp=failure, tcp=failure)
        result = await run_health(make_ctx)
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL
        assert any(NS2 in note and "did not answer" in note for note in result.notes)

    async def test_every_server_silent(self, make_ctx: Any, net: FakeNet) -> None:
        for address in (IP1, IP2, REGISTRY_IP):
            net.servers[address] = FakeServer(
                udp=dns.exception.Timeout(), tcp=dns.exception.Timeout()
            )
        result = await run_health(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.PARTIAL

    @pytest.mark.parametrize("rcode", [dns.rcode.SERVFAIL, dns.rcode.NOTIMP, dns.rcode.FORMERR])
    async def test_server_failure_is_not_lame(
        self, make_ctx: Any, net: FakeNet, rcode: dns.rcode.Rcode
    ) -> None:
        net.servers[IP2] = FakeServer(rcode=rcode)
        result = await run_health(make_ctx)
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL

    @pytest.mark.parametrize(
        "failure", [dns.exception.Timeout(), ConnectionRefusedError(), EOFError()]
    )
    async def test_no_tcp(self, make_ctx: Any, net: FakeNet, failure: BaseException) -> None:
        net.servers[IP1] = FakeServer(tcp=failure)
        result = await run_health(make_ctx)
        [finding] = result.findings
        assert finding.kind == "dns.nameserver.no_tcp"
        assert finding.identity == {"nameserver": NS1}
        assert finding.evidence["addresses"] == [IP1]

    async def test_tcp_only_is_a_note(self, make_ctx: Any, net: FakeNet) -> None:
        net.servers[IP1] = FakeServer(udp=dns.exception.Timeout())
        result = await run_health(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.PARTIAL

    async def test_serial_mismatch_is_a_candidate(self, make_ctx: Any, net: FakeNet) -> None:
        net.servers[IP2] = FakeServer(serial=2024010100)
        result = await run_health(make_ctx)
        [finding] = result.findings
        assert finding.kind == "dns.nameserver.serial_mismatch"
        assert finding.confidence is Confidence.CANDIDATE
        assert finding.state == {"out_of_step": [NS2]}
        assert "only a problem if it persists" in finding.evidence["note"]
        assert "2024010100" not in json.dumps(finding.state), "serials change: not in the state"
        assert finding.evidence["versions"] == {NS1: 2024010101, NS2: 2024010100}

    async def test_matching_serials(self, make_ctx: Any, net: FakeNet) -> None:
        assert "dns.nameserver.serial_mismatch" not in kinds(await run_health(make_ctx))

    @pytest.mark.parametrize(
        ("flag", "answer", "reported"),
        [(True, True, True), (True, False, False), (False, True, False), (False, False, False)],
    )
    async def test_open_resolver_needs_flag_and_answer(
        self, make_ctx: Any, net: FakeNet, flag: bool, answer: bool, reported: bool
    ) -> None:
        net.servers[IP1] = FakeServer(recursion_available=flag, recursion_answer=answer)
        result = await run_health(make_ctx)
        assert kinds(result) == (["dns.nameserver.open_resolver"] if reported else [])
        assert result.status is ModuleStatus.OK
        if reported:
            assert result.findings[0].identity == {"nameserver": NS1}

    def test_open_resolver_rules(self) -> None:
        answer = [rr("example.com", "A", "93.184.215.14")]
        open_ = reply("example.com", "A", answer=answer, flags=dns.flags.RA)
        assert nameserver_health.is_open_resolver(open_)
        hosted = reply("example.com", "A", answer=answer, flags=dns.flags.RA | dns.flags.AA)
        assert not nameserver_health.is_open_resolver(hosted)
        failed = reply(
            "example.com", "A", answer=answer, flags=dns.flags.RA, rcode=dns.rcode.SERVFAIL
        )
        assert not nameserver_health.is_open_resolver(failed)
        referral = reply(
            "example.com",
            "A",
            flags=dns.flags.RA,
            authority=[rr("com", "NS", "a.gtld-servers.net.")],
        )
        assert not nameserver_health.is_open_resolver(referral)

    async def test_recursion_question_unanswered(self, make_ctx: Any, net: FakeNet) -> None:
        net.servers[IP1] = FakeServer(recursion=dns.exception.Timeout())
        result = await run_health(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.PARTIAL

    async def test_lame_server_can_still_be_an_open_resolver(
        self, make_ctx: Any, net: FakeNet
    ) -> None:
        net.servers[IP2] = FakeServer(
            authoritative=False, recursion_available=True, recursion_answer=True
        )
        result = await run_health(make_ctx)
        assert kinds(result) == ["dns.nameserver.lame", "dns.nameserver.open_resolver"]

    async def test_delegation_mismatch(self, make_ctx: Any, net: FakeNet) -> None:
        old = "ns9.oldhost.net"
        for address in (IP1, IP2):
            net.servers[address] = FakeServer(zone_ns=[NS1, old])
        result = await run_health(make_ctx)
        [finding] = result.findings
        assert finding.kind == "dns.delegation.mismatch"
        assert finding.state == {"only_at_registry": [NS2], "only_in_zone": [old]}
        assert not net.asked("203.0.113.9")
        assert result.status is ModuleStatus.OK

    async def test_delegation_case_and_dots_do_not_matter(
        self, make_ctx: Any, net: FakeNet
    ) -> None:
        net.servers[REGISTRY_IP] = FakeServer(referral=[NS1.upper(), NS2])
        assert (await run_health(make_ctx)).findings == []

    @pytest.mark.parametrize(
        "registry",
        [
            FakeServer(udp=dns.exception.Timeout(), tcp=dns.exception.Timeout()),
            FakeServer(rcode=dns.rcode.SERVFAIL),
            FakeServer(rcode=dns.rcode.REFUSED),
            # A server that holds the zone itself gives the zone's list, not the registry's.
            FakeServer(zone_ns=[NS1]),
            FakeServer(referral_raw=[rr("other-zone.xyz", "NS", f"{NS1}.")]),
        ],
    )
    async def test_registry_unreadable_leaves_mismatch_out(
        self, make_ctx: Any, net: FakeNet, registry: FakeServer
    ) -> None:
        net.servers[REGISTRY_IP] = registry
        for address in (IP1, IP2):
            net.servers[address] = FakeServer(zone_ns=[NS1, "ns9.oldhost.net"])
        result = await run_health(make_ctx)
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL
        assert any("registry's list" in note for note in result.notes)
        assert result.stats["nameservers_asked"] == 2, "public DNS supplies the list instead"

    async def test_registry_answer_truncated(
        self, make_ctx: Any, net: FakeNet, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = net.send

        def send(query: Any, address: str, tcp: bool, timeout: float) -> Any:
            message = original(query, address, tcp, timeout)
            if address == REGISTRY_IP and not tcp:
                message.authority.clear()
                message.flags |= dns.flags.TC
            return message

        monkeypatch.setattr(nameserver_health, "send", send)
        result = await run_health(make_ctx)
        assert [c[1] for c in net.asked(REGISTRY_IP)] == ["udp", "tcp"]
        assert result.findings == [] and result.status is ModuleStatus.OK

    async def test_private_addresses_are_never_asked(
        self, make_ctx: Any, net: FakeNet, dns: Any
    ) -> None:
        net.servers[REGISTRY_IP] = FakeServer(referral=[NS1, NS2, NS3])
        dns.add("ns4.internal-dns.net", "A", ["127.0.0.1"])
        dns.add("ns5.internal-dns.net", "A", ["169.254.169.254"])
        dns.add("ns6.internal-dns.net", "AAAA", ["2001:4860:4860::8888"])
        net.servers[REGISTRY_IP].referral = [
            NS1, NS2, NS3, "ns4.internal-dns.net", "ns5.internal-dns.net", "ns6.internal-dns.net",
        ]  # fmt: skip
        result = await run_health(make_ctx)
        assert {c[0] for c in net.calls} == {IP1, IP2, REGISTRY_IP}
        for server in (NS3, "ns4.internal-dns.net", "ns5.internal-dns.net", "ns6.internal-dns.net"):
            assert any(f"{server} has no public address" in note for note in result.notes)
        assert "dns.nameserver.lame" not in kinds(result)

    async def test_mixed_addresses_only_public_asked(
        self, make_ctx: Any, net: FakeNet, dns: Any
    ) -> None:
        dns.add(NS1, "A", [PRIVATE, IP1])
        await run_health(make_ctx)
        assert not net.asked(PRIVATE) and net.asked(IP1)

    @pytest.mark.parametrize(
        "address", [PRIVATE, "127.0.0.1", "169.254.169.254", "::1", "2001:4860:4860::8888"]
    )
    def test_exchange_refuses_unsafe_addresses(self, net: FakeNet, address: str) -> None:
        query = nameserver_health.make_query(ROOT, "SOA", recurse=False)
        outcome = nameserver_health.exchange(query, address, False)
        assert not outcome.answered and net.calls == []

    async def test_private_registry_server_is_never_asked(
        self, make_ctx: Any, net: FakeNet, dns: Any
    ) -> None:
        dns.add(REGISTRY, "A", [PRIVATE])
        result = await run_health(make_ctx)
        assert not net.asked(PRIVATE) and not net.asked(REGISTRY_IP)
        assert result.status is ModuleStatus.PARTIAL

    @pytest.mark.parametrize("entry", ["dnshost.net", NS1, IP1, "198.41.0.0/24"])
    async def test_do_not_contact_list(self, make_ctx: Any, net: FakeNet, entry: str) -> None:
        net.servers[IP1] = FakeServer(authoritative=False)
        result = await run_health(make_ctx, never_contact=[entry])
        assert not net.asked(IP1)
        assert result.findings == []
        assert any(f"{NS1} is on the do-not-contact list" in note for note in result.notes)

    async def test_do_not_contact_covers_the_registry(self, make_ctx: Any, net: FakeNet) -> None:
        result = await run_health(make_ctx, never_contact=["nic.xyz"])
        assert not net.asked(REGISTRY_IP)
        assert result.status is ModuleStatus.PARTIAL

    async def test_at_most_eight_nameservers(self, make_ctx: Any, net: FakeNet, dns: Any) -> None:
        names = [f"ns{i:02d}.dnshost.net" for i in range(12)]
        for i, name in enumerate(names):
            address = f"198.41.1.{i + 1}"
            dns.add(name, "A", [address])
            net.servers[address] = FakeServer(zone_ns=names)
        net.servers[REGISTRY_IP] = FakeServer(referral=names)
        result = await run_health(make_ctx)
        assert result.stats["nameservers_asked"] == 8
        assert any("first 8" in note for note in result.notes)

    async def test_address_lookup_failure(self, make_ctx: Any, net: FakeNet, dns: Any) -> None:
        dns.errors.add(NS2)
        result = await run_health(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.PARTIAL
        assert not net.asked(IP2)

    async def test_hostile_names_from_the_zone(
        self, make_ctx: Any, net: FakeNet, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hostile = [
            rr(
                ROOT,
                "NS",
                f"{NS1}.",
                "evil\\010\\027name.example.net.",
                "\\<script\\>alert\\(1\\).example.net.",
                f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 50}.net.",
            )
        ]
        original = net.send

        def send(query: Any, address: str, tcp: bool, timeout: float) -> Any:
            message = original(query, address, tcp, timeout)
            if address in (IP1, IP2) and query.question[0].rdtype == dns.rdatatype.NS:
                message.answer.clear()
                message.answer.extend(hostile)
            return message

        monkeypatch.setattr(nameserver_health, "send", send)
        result = await run_health(make_ctx)
        assert result.findings == []
        assert any("not valid" in note for note in result.notes)
        assert_clean(result)

    async def test_hostile_names_from_the_registry(self, make_ctx: Any, net: FakeNet) -> None:
        net.servers[REGISTRY_IP] = FakeServer(
            referral_raw=[
                rr(ROOT, "NS", f"{NS1}.", "evil\\010name.example.net.", "a\\;b\\ c.example.net.")
            ]
        )
        result = await run_health(make_ctx)
        assert result.findings == [] and result.status is ModuleStatus.PARTIAL
        assert {c[0] for c in net.calls} == {IP1, IP2, REGISTRY_IP}
        assert_clean(result)

    async def test_hostile_names_from_public_dns(
        self, make_ctx: Any, net: FakeNet, dns: Any
    ) -> None:
        net.servers[REGISTRY_IP] = FakeServer(rcode=dns_rcode_servfail())
        dns.add(
            ROOT,
            "NS",
            [
                f"{NS1}.",
                "evil\x08name.example.net.",
                "x" * 400,
                "<script>.example.net",
                "10.0.0.53",
            ],
        )
        result = await run_health(make_ctx)
        assert result.stats["nameservers_asked"] == 1
        assert {c[0] for c in net.calls} == {IP1, REGISTRY_IP}
        assert_clean(result)

    async def test_too_many_names_are_capped(self, make_ctx: Any, net: FakeNet) -> None:
        names, dropped = nameserver_health.ns_names(
            [[rr(ROOT, "NS", *(f"ns{i}.dnshost.net." for i in range(100)))]], ZONE
        )
        assert len(names) == nameserver_health.MAX_NAMES and dropped == 0


def dns_rcode_servfail() -> dns.rcode.Rcode:
    # The `dns` fixture hides the dns package inside the tests above.
    import dns.rcode as rcode

    return rcode.SERVFAIL
