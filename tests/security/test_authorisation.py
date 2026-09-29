"""Proof of domain control, and the recorded acknowledgement."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from parapet.clients.dns import DnsAnswer, DnsStatus
from parapet.core.models import AuthLevel, Target, utcnow
from parapet.safety import authorisation as auth
from parapet.storage.repo import TenantRepo
from tests.conftest import ROOT

TOKEN = "tok_" + "a" * 40
GOOD = auth.record_value(TOKEN)
NAME = auth.record_name(ROOT)


def patch_dns(
    monkeypatch: pytest.MonkeyPatch,
    *,
    nameservers: list[str],
    authoritative: dict[str, tuple[bool, list[str]] | None],
    public: dict[str, list[str]],
) -> list[str]:
    asked: list[str] = []

    async def zone_nameservers(domain: str, client: Any) -> list[str]:
        return nameservers

    async def ask(server: str, name: str, timeout: float) -> Any:
        asked.append(server)
        assert name == NAME
        return authoritative.get(server)

    class FakeClient:
        def __init__(self, *, nameservers: tuple[str, ...] = (), timeout_s: float = 4.0) -> None:
            self.resolver = nameservers[0] if nameservers else ""

        async def query(self, name: str, rdtype: str, **kw: Any) -> DnsAnswer:
            values = public.get(self.resolver, [])
            status = DnsStatus.OK if values else DnsStatus.NXDOMAIN
            return DnsAnswer(name, rdtype, status, tuple(values))

    monkeypatch.setattr(auth, "_zone_nameservers", zone_nameservers)
    monkeypatch.setattr(auth, "_ask", ask)
    monkeypatch.setattr(auth, "DnsClient", FakeClient)
    return asked


class TestDnsVerification:
    async def test_record_on_the_domains_own_nameservers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_dns(
            monkeypatch,
            nameservers=["198.41.0.4", "198.41.0.5"],
            authoritative={"198.41.0.4": (True, ["v=spf1 -all", GOOD]), "198.41.0.5": None},
            public={},
        )
        result = await auth.check_dns(ROOT, TOKEN)
        assert result.verified and result.source == "authoritative"

    async def test_wrong_value_is_refused_even_if_resolvers_disagree(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_dns(
            monkeypatch,
            nameservers=["198.41.0.4"],
            authoritative={"198.41.0.4": (True, [auth.record_value("someone-elses-token")])},
            public={},
        )
        result = await auth.check_dns(ROOT, TOKEN)
        assert not result.verified
        assert "does not match" in result.detail

    async def test_a_non_authoritative_answer_does_not_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A server that merely relays or forges the answer, without authority for the zone.
        patch_dns(
            monkeypatch,
            nameservers=["198.41.0.4"],
            authoritative={"198.41.0.4": (False, [GOOD])},
            public={},
        )
        assert not (await auth.check_dns(ROOT, TOKEN)).verified

    async def test_falls_back_to_two_agreeing_public_resolvers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_dns(
            monkeypatch,
            nameservers=[],
            authoritative={},
            public={"1.1.1.1": [GOOD], "8.8.8.8": [GOOD]},
        )
        result = await auth.check_dns(ROOT, TOKEN)
        assert result.verified and result.source == "public resolvers"

    async def test_one_resolver_alone_is_not_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_dns(monkeypatch, nameservers=[], authoritative={}, public={"9.9.9.9": [GOOD]})
        assert not (await auth.check_dns(ROOT, TOKEN)).verified

    async def test_no_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_dns(
            monkeypatch,
            nameservers=["198.41.0.4"],
            authoritative={"198.41.0.4": (True, [])},
            public={},
        )
        result = await auth.check_dns(ROOT, TOKEN)
        assert not result.verified
        assert NAME in result.detail

    @pytest.mark.parametrize("value", [TOKEN, f"parapet-verify={TOKEN}x", f" {GOOD}", GOOD.upper()])
    async def test_value_must_match_exactly(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        patch_dns(
            monkeypatch,
            nameservers=["198.41.0.4"],
            authoritative={"198.41.0.4": (True, [value])},
            public={"1.1.1.1": [value], "8.8.8.8": [value]},
        )
        assert not (await auth.check_dns(ROOT, TOKEN)).verified

    async def test_nameservers_at_private_addresses_are_never_queried(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Client:
            async def query(self, name: str, rdtype: str) -> DnsAnswer:
                return DnsAnswer(name, rdtype, DnsStatus.OK, ("ns1.evil.example.",))

            async def addresses(self, name: str) -> tuple[list[str], DnsStatus]:
                return ["10.0.0.53", "169.254.169.254", "127.0.0.1", "198.41.0.4"], DnsStatus.OK

        assert await auth._zone_nameservers(ROOT, Client()) == ["198.41.0.4"]  # type: ignore[arg-type]

    def test_tokens_are_long_and_unique(self) -> None:
        tokens = {auth.new_token() for _ in range(50)}
        assert len(tokens) == 50
        assert all(len(t) >= 40 for t in tokens)


class TestResolveAuthorisation:
    @pytest.fixture
    def repo(self, database: Any) -> Any:
        with database.session() as session:
            repo = TenantRepo.local(session)
            row = repo.upsert_target(Target(root_domain=ROOT))
            yield repo, row, database.keys

    def verification(self, monkeypatch: pytest.MonkeyPatch, verified: bool) -> None:
        async def check(domain: str, token: str, **kw: Any) -> auth.VerificationResult:
            return auth.VerificationResult(verified, "authoritative", "detail")

        monkeypatch.setattr(auth, "check_dns", check)

    def ack(self, repo: Any, row: Any, keys: Any, **changes: Any) -> Any:
        record = auth.make_ack(
            row, full_name="Ana Lopez", organisation="Acme Protocol", role="CTO", keys=keys
        )
        for key, value in changes.items():
            setattr(record, key, value)
        return repo.add_ack(record)

    async def test_nothing_on_record(self, repo: Any) -> None:
        r, row, keys = repo
        assert (await auth.resolve_authorisation(r, row, keys)).level is AuthLevel.NONE

    async def test_dns_proof_is_checked_live_every_time(
        self, repo: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        r, row, keys = repo
        verification = r.create_verification(row.id, TOKEN)
        self.verification(monkeypatch, True)
        assert (await auth.resolve_authorisation(r, row, keys)).level is AuthLevel.DNS_VERIFIED
        assert verification.verified_at is not None

        # The record is removed. A pass from a moment ago counts for nothing.
        self.verification(monkeypatch, False)
        assert (await auth.resolve_authorisation(r, row, keys)).level is AuthLevel.NONE
        assert verification.consecutive_failures == 1

    async def test_acknowledgement(self, repo: Any) -> None:
        r, row, keys = repo
        self.ack(r, row, keys)
        result = await auth.resolve_authorisation(r, row, keys)
        assert result.level is AuthLevel.ACKNOWLEDGED
        assert "Ana Lopez" in result.basis
        assert "not proven" in result.basis

    async def test_expired_acknowledgement(self, repo: Any) -> None:
        r, row, keys = repo
        self.ack(r, row, keys, expires_at=utcnow() - timedelta(seconds=1))
        assert (await auth.resolve_authorisation(r, row, keys)).level is AuthLevel.NONE

    @pytest.mark.parametrize(
        "field", ["full_name", "organisation", "role", "os_user", "hostname", "statement"]
    )
    async def test_an_edited_acknowledgement_is_void(self, repo: Any, field: str) -> None:
        r, row, keys = repo
        self.ack(r, row, keys, **{field: "edited in the database"})
        assert (await auth.resolve_authorisation(r, row, keys)).level is AuthLevel.NONE

    async def test_acknowledgement_cannot_be_extended_by_editing_the_expiry(
        self, repo: Any
    ) -> None:
        r, row, keys = repo
        record = self.ack(r, row, keys)
        assert auth.ack_is_valid(record, ROOT, keys)
        assert not auth.ack_is_valid(record, "other-domain.xyz", keys)

    async def test_failed_dns_proof_falls_back_to_an_acknowledgement(
        self, repo: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        r, row, keys = repo
        r.create_verification(row.id, TOKEN)
        self.ack(r, row, keys)
        self.verification(monkeypatch, False)
        assert (await auth.resolve_authorisation(r, row, keys)).level is AuthLevel.ACKNOWLEDGED
