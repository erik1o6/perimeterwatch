"""Certificate watching: messages are fed in by hand. Nothing connects anywhere."""

from __future__ import annotations

import ast
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from parapet.config import Settings
from parapet.core.models import utcnow
from parapet.storage.repo import Cache
from parapet.storage.tables import (
    AlertChannel,
    AlertDelivery,
    AuditLog,
    DomainVerification,
    TargetRow,
    Tenant,
)
from parapet.worker import certwatch
from parapet.worker.certwatch import CertWatcher, brand_label, check_url, defang, names_in
from tests.conftest import ROOT, fixture_text

LOOKALIKE = "acme-protocol-app.com"


class Clock:
    def __init__(self) -> None:
        self.now = utcnow()

    def __call__(self) -> datetime:
        return self.now

    def forward(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


def add_org(
    database: Any,
    *domains: str,
    verified: bool = True,
    channel: bool = True,
    scan_interval_hours: int | None = None,
) -> uuid.UUID:
    with database.session() as db:
        tenant = Tenant(name=f"org {domains[0]}")
        db.add(tenant)
        db.flush()
        for domain in domains:
            target = TargetRow(
                tenant_id=tenant.id,
                root_domain=domain,
                scan_interval_hours=scan_interval_hours,
                next_scan_at=utcnow() + timedelta(hours=20) if scan_interval_hours else None,
            )
            db.add(target)
            db.flush()
            db.add(
                DomainVerification(
                    tenant_id=tenant.id,
                    target_id=target.id,
                    token="parapet-verify-test",
                    verified_at=utcnow() if verified else None,
                )
            )
        if channel:
            db.add(
                AlertChannel(
                    tenant_id=tenant.id,
                    kind="email",
                    label="security",
                    config={"to": f"security@{domains[0]}"},
                )
            )
        return tenant.id


def cert(*names: Any) -> str:
    return json.dumps(
        {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": list(names)}}}
    )


def deliveries(database: Any, tenant_id: uuid.UUID | None = None) -> list[AlertDelivery]:
    with database.session() as db:
        rows = list(db.scalars(select(AlertDelivery).order_by(AlertDelivery.created_at)))
    return [r for r in rows if tenant_id is None or r.tenant_id == tenant_id]


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def acme(database: Any) -> uuid.UUID:
    return add_org(database, ROOT)


@pytest.fixture
def watcher(settings: Settings, database: Any, clock: Clock, acme: uuid.UUID) -> CertWatcher:
    made = CertWatcher(settings, database, clock=clock)
    made.reload()
    return made


def matched(watcher: CertWatcher, *names: str) -> list[str]:
    return [m.name for m in watcher.match(names_in(cert(*names)))]


class TestBrandLabel:
    @pytest.mark.parametrize(
        ("domain", "label"),
        [
            (ROOT, "acme-protocol"),
            ("app.acme-protocol.xyz", "acme-protocol"),
            ("example-bank.co.uk", "example-bank"),
            ("sixsix.io", "sixsix"),
            ("acme.xyz", None),
            ("short.co.uk", None),
            ("localhost", None),
            ("", None),
        ],
    )
    def test_first_label_of_the_registrable_domain(self, domain: str, label: str | None) -> None:
        assert brand_label(domain) == label

    def test_same_minimum_as_the_lookalike_scan(self) -> None:
        from parapet.modules import lookalikes

        assert certwatch.MIN_BRAND_LENGTH == lookalikes.MIN_BRAND_LENGTH_FOR_CT


class TestMatching:
    @pytest.mark.parametrize(
        "name",
        [
            LOOKALIKE,
            f"login.{LOOKALIKE}",
            f"*.{LOOKALIKE}",
            "acme-protocol.com",
            "myacme-protocol.io",
            "acme-protocol.evil-hosting.net",
            "www.acme-protocol.pages.example.net",
            "ACME-PROTOCOL-APP.COM.",
            "xn--acme-protocol-9db.com",
        ],
    )
    def test_names_that_use_the_brand_match(self, watcher: CertWatcher, name: str) -> None:
        assert len(matched(watcher, name)) == 1

    @pytest.mark.parametrize(
        "name",
        [
            ROOT,
            f"app.{ROOT}",
            f"*.{ROOT}",
            f"deep.er.still.{ROOT}",
            "example.org",
            "acme.xyz",
            "acme-protoco1.com",
            # The brand is inside a longer word of a subdomain of an unrelated domain.
            "myacme-protocolx.hosting.net",
            "xacme-protocol-cdn.assets.example.net",
        ],
    )
    def test_own_and_unrelated_names_do_not(self, watcher: CertWatcher, name: str) -> None:
        assert matched(watcher, name) == []

    def test_a_name_that_only_ends_like_the_domain_is_not_own(self, watcher: CertWatcher) -> None:
        assert matched(watcher, "notacme-protocol.xyz") == ["notacme-protocol.xyz"]

    def test_another_verified_domain_of_the_same_organisation_is_own(
        self, settings: Settings, database: Any
    ) -> None:
        add_org(database, ROOT, "acme-protocol.com")
        watcher = CertWatcher(settings, database)
        watcher.reload()
        assert matched(watcher, "acme-protocol.com", "www.acme-protocol.com", f"a.{ROOT}") == []
        assert matched(watcher, "acme-protocol.net") == ["acme-protocol.net", "acme-protocol.net"]
        assert watcher.handle(cert("acme-protocol.net")) == 1, "one notice, not one per domain"

    def test_each_organisation_is_matched_separately(
        self, watcher: CertWatcher, database: Any, acme: uuid.UUID
    ) -> None:
        rival = add_org(database, "rival-protocol.xyz")
        watcher.reload()
        watcher.handle(cert("rival-protocol-login.com"))
        watcher.handle(cert(LOOKALIKE))
        assert [d.subject for d in deliveries(database, rival)] == [
            "rival-protocol.xyz: a certificate using your name was issued"
        ]
        assert LOOKALIKE.split(".")[0] not in deliveries(database, rival)[0].body
        assert len(deliveries(database, acme)) == 1

    def test_one_label_contained_in_another(self, settings: Settings, database: Any) -> None:
        short = add_org(database, "paywall.io")
        long = add_org(database, "paywallet.io")
        watcher = CertWatcher(settings, database)
        watcher.reload()
        found = {(m.watched.tenant_id, m.name) for m in watcher.match(["paywallet-login.com"])}
        assert found == {(short, "paywallet-login.com"), (long, "paywallet-login.com")}
        assert {m.watched.tenant_id for m in watcher.match(["paywall-login.com"])} == {short}

    def test_matching_uses_no_database(
        self, watcher: CertWatcher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("the database was used for a message that matches nothing")

        monkeypatch.setattr(watcher.database, "session", refuse)
        for line in fixture_text("certstream", "stream.jsonl").splitlines():
            if LOOKALIKE not in line and "evil-hosting" not in line:
                assert watcher.handle(line) == 0
        assert watcher.counters.errors == 0


class TestWhatIsWatched:
    def test_unverified_domains_are_not_watched(self, settings: Settings, database: Any) -> None:
        add_org(database, ROOT, verified=False)
        watcher = CertWatcher(settings, database)
        assert watcher.reload() == 0
        assert watcher.handle(cert(LOOKALIKE)) == 0
        assert deliveries(database) == []

    def test_short_names_are_not_watched(self, settings: Settings, database: Any) -> None:
        add_org(database, "acme.xyz")
        watcher = CertWatcher(settings, database)
        assert watcher.reload() == 0
        assert watcher.handle(cert("acme-login.com")) == 0

    def test_a_withdrawn_verification_stops_the_watch(
        self, watcher: CertWatcher, database: Any, clock: Clock
    ) -> None:
        with database.session() as db:
            db.scalars(select(DomainVerification)).one().verified_at = None
        clock.forward(minutes=6)
        watcher.reload_if_due()
        assert watcher.handle(cert(LOOKALIKE)) == 0

    def test_the_list_is_refreshed_periodically_not_per_message(
        self, watcher: CertWatcher, clock: Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loads: list[int] = []
        monkeypatch.setattr(watcher, "reload", lambda: loads.append(1))
        for _ in range(500):
            watcher.reload_if_due()
        assert loads == []
        clock.forward(minutes=6)
        for _ in range(500):
            watcher.reload_if_due()
        assert loads == [1]

    def test_a_database_that_is_down_does_not_stop_the_watcher(
        self, watcher: CertWatcher, clock: Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken() -> int:
            raise RuntimeError("database is down")

        monkeypatch.setattr(watcher, "reload", broken)
        clock.forward(minutes=6)
        watcher.reload_if_due()
        assert watcher.counters.errors == 1
        assert matched(watcher, LOOKALIKE), "the last list that loaded stays in use"

    def test_the_number_of_watched_domains_is_capped(
        self, settings: Settings, database: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(certwatch, "MAX_WATCHED", 2)
        for n in range(4):
            add_org(database, f"organisation{n}.com", channel=False)
        watcher = CertWatcher(settings, database)
        assert watcher.reload() == 2


class TestNotices:
    def test_a_match_is_recorded_and_queued(
        self, watcher: CertWatcher, database: Any, acme: uuid.UUID
    ) -> None:
        assert watcher.handle(cert(LOOKALIKE, f"login.{LOOKALIKE}", f"*.{LOOKALIKE}")) == 1
        (delivery,) = deliveries(database, acme)
        assert delivery.status == "pending"
        assert delivery.subject == f"{ROOT}: a certificate using your name was issued"
        assert "acme-protocol-app[.]com" in delivery.body
        assert "login[.]acme-protocol-app[.]com" in delivery.body
        assert "has not contacted" in delivery.body
        assert "http://testserver/targets" in delivery.body
        with database.session() as db:
            entry = db.scalars(select(AuditLog).where(AuditLog.action == "certwatch.match")).one()
        assert entry.tenant_id == acme
        assert entry.object_id == LOOKALIKE
        assert entry.meta == {"names": [LOOKALIKE, f"login.{LOOKALIKE}"], "resembles": [ROOT]}

    def test_the_name_is_never_written_as_a_link(self, watcher: CertWatcher, database: Any) -> None:
        watcher.handle(cert(LOOKALIKE, f"login.{LOOKALIKE}"))
        (delivery,) = deliveries(database)
        for text in (delivery.subject, delivery.body):
            assert LOOKALIKE not in text
            assert "http://acme" not in text and "https://acme" not in text
        assert defang("a.b.example") == "a[.]b[.]example"

    def test_plain_wording(self, watcher: CertWatcher, database: Any) -> None:
        watcher.handle(cert(LOOKALIKE))
        (delivery,) = deliveries(database)
        assert chr(0x2014) not in delivery.subject + delivery.body
        assert "organization" not in delivery.body

    def test_without_a_channel_the_match_is_still_recorded(
        self, settings: Settings, database: Any
    ) -> None:
        add_org(database, ROOT, channel=False)
        watcher = CertWatcher(settings, database)
        watcher.reload()
        assert watcher.handle(cert(LOOKALIKE)) == 0
        with database.session() as db:
            assert db.scalars(select(AuditLog.action)).all() == ["certwatch.match"]

    def test_the_fixture_stream(self, watcher: CertWatcher, database: Any) -> None:
        queued = [
            watcher.handle(line) for line in fixture_text("certstream", "stream.jsonl").splitlines()
        ]
        assert queued == [0, 1, 0, 0, 0, 1]
        bodies = [d.body for d in deliveries(database)]
        assert "acme-protocol-app[.]com" in bodies[0]
        assert "evil-hosting[.]net" in bodies[1]
        assert watcher.counters.messages == 6
        assert watcher.counters.dropped == 1, "the heartbeat carries no names"


class TestDeduplication:
    def test_the_same_domain_alerts_once_in_a_day(
        self, watcher: CertWatcher, database: Any, clock: Clock
    ) -> None:
        assert watcher.handle(cert(LOOKALIKE)) == 1
        assert watcher.handle(cert(LOOKALIKE)) == 0
        clock.forward(hours=23)
        assert watcher.handle(cert(f"shop.{LOOKALIKE}", f"mail.{LOOKALIKE}")) == 0
        assert len(deliveries(database)) == 1
        assert watcher.counters.repeats == 2

        clock.forward(hours=2)
        assert watcher.handle(cert(LOOKALIKE)) == 1
        assert len(deliveries(database)) == 2

    def test_a_different_domain_still_alerts(self, watcher: CertWatcher, database: Any) -> None:
        assert watcher.handle(cert(LOOKALIKE)) == 1
        assert watcher.handle(cert("acme-protocol-airdrop.io")) == 1
        assert len(deliveries(database)) == 2

    def test_a_restart_does_not_repeat_an_alert(
        self, watcher: CertWatcher, settings: Settings, database: Any, clock: Clock
    ) -> None:
        assert watcher.handle(cert(LOOKALIKE)) == 1
        restarted = CertWatcher(settings, database, clock=clock)
        restarted.reload()
        assert restarted.handle(cert(LOOKALIKE)) == 0
        assert restarted.handle(cert(LOOKALIKE)) == 0
        assert len(deliveries(database)) == 1

    def test_what_is_remembered_is_capped(
        self, watcher: CertWatcher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(certwatch, "MAX_REMEMBERED", 3)
        monkeypatch.setattr(certwatch, "MAX_NOTICES_PER_TENANT", 100)
        for n in range(10):
            watcher.handle(cert(f"acme-protocol-{n}.com"))
        assert len(watcher._told) == 3


class TestRateLimit:
    def test_a_flood_of_matches_sends_few_alerts(
        self, watcher: CertWatcher, database: Any, clock: Clock
    ) -> None:
        for n in range(300):
            watcher.handle(cert(f"acme-protocol-{n}.com", f"www.acme-protocol-{n}.com"))
        assert len(deliveries(database)) == certwatch.MAX_NOTICES_PER_TENANT == 5
        assert watcher.counters.held_back == 295
        with database.session() as db:
            assert len(db.scalars(select(AuditLog)).all()) == 5, "the flood is not written down"

        clock.forward(minutes=61)
        assert watcher.handle(cert("acme-protocol-later.com")) == 1
        latest = deliveries(database)[-1]
        assert "295 other certificate(s)" in latest.body

    def test_a_flood_does_not_use_the_database(
        self, watcher: CertWatcher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for n in range(5):
            watcher.handle(cert(f"acme-protocol-{n}.com"))

        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("the database was used while alerts were held back")

        monkeypatch.setattr(watcher.database, "session", refuse)
        for n in range(5, 200):
            assert watcher.handle(cert(f"acme-protocol-{n}.com")) == 0
        assert watcher.handle(cert("acme-protocol-0.com")) == 0
        assert watcher.counters.errors == 0

    def test_one_organisation_cannot_use_up_the_alerts_of_another(
        self, watcher: CertWatcher, database: Any
    ) -> None:
        rival = add_org(database, "rival-protocol.xyz")
        watcher.reload()
        for n in range(50):
            watcher.handle(cert(f"acme-protocol-{n}.com"))
        assert watcher.handle(cert("rival-protocol-login.com")) == 1
        assert len(deliveries(database, rival)) == 1

    def test_there_is_a_limit_for_the_whole_service(
        self, watcher: CertWatcher, database: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(certwatch, "MAX_NOTICES_IN_TOTAL", 3)
        add_org(database, "rival-protocol.xyz")
        watcher.reload()
        for n in range(3):
            assert watcher.handle(cert(f"acme-protocol-{n}.com")) == 1
        assert watcher.handle(cert("rival-protocol-login.com")) == 0


class TestNextScan:
    def test_a_scheduled_scan_is_brought_forward_once(
        self, settings: Settings, database: Any, clock: Clock
    ) -> None:
        add_org(database, ROOT, scan_interval_hours=24)
        with database.session() as db:
            Cache(db).set("crtsh:brand:current", "%acme-protocol%", "[]", timedelta(hours=24))
            Cache(db).set("crtsh:subdomains:all", f"%.{ROOT}", "[]", timedelta(hours=24))
        watcher = CertWatcher(settings, database, clock=clock)
        watcher.reload()
        watcher.handle(cert(LOOKALIKE))
        with database.session() as db:
            target = db.scalars(select(TargetRow)).one()
            assert target.next_scan_at is not None
            moved_to = target.next_scan_at.replace(tzinfo=None)
            assert abs(moved_to - clock.now.replace(tzinfo=None)) < timedelta(seconds=1)
            assert Cache(db).get("crtsh:brand:current", "%acme-protocol%") is None
            assert Cache(db).get("crtsh:subdomains:all", f"%.{ROOT}") == "[]"
            target.next_scan_at = clock.now + timedelta(hours=24)

        watcher.handle(cert("acme-protocol-airdrop.io"))
        with database.session() as db:
            target = db.scalars(select(TargetRow)).one()
            assert target.next_scan_at is not None
            assert target.next_scan_at.replace(tzinfo=None) > clock.now.replace(tzinfo=None)

    def test_a_domain_scanned_only_on_request_is_left_alone(
        self, watcher: CertWatcher, database: Any
    ) -> None:
        watcher.handle(cert(LOOKALIKE))
        with database.session() as db:
            assert db.scalars(select(TargetRow)).one().next_scan_at is None


class TestHostileInput:
    @pytest.mark.parametrize(
        "message",
        [
            "",
            "not json",
            "null",
            "[]",
            "5",
            '"text"',
            "{}",
            '{"message_type": "certificate_update"}',
            '{"message_type": "certificate_update", "data": null}',
            '{"message_type": "certificate_update", "data": []}',
            '{"message_type": "certificate_update", "data": {"leaf_cert": "x"}}',
            '{"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": "x"}}}',
            '{"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": {}}}}',
            '{"message_type": "dns_entries", "data": {"a": 1}}',
            '{"message_type": "heartbeat", "data": ["acme-protocol-app.com"]}',
            '{"message_type": ["certificate_update"], "data": ["acme-protocol-app.com"]}',
            '{"data": {"leaf_cert": {"all_domains": ["acme-protocol-app.com"]}}}',
            '{"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": ["acme-pro',
            "[" * 100_000,
            '{"a":' * 100_000,
            b"\xff\xfe\x00acme-protocol-app.com",
            b"",
            None,
            5,
            ["acme-protocol-app.com"],
            {"message_type": "dns_entries", "data": ["acme-protocol-app.com"]},
        ],
    )
    def test_malformed_messages_are_dropped(
        self, watcher: CertWatcher, database: Any, message: Any
    ) -> None:
        assert watcher.handle(message) == 0
        assert deliveries(database) == []
        assert watcher.counters.errors == 0
        assert watcher.counters.dropped == 1

    def test_bytes_are_accepted(self, watcher: CertWatcher) -> None:
        assert watcher.handle(cert(LOOKALIKE).encode()) == 1

    def test_oversized_messages_are_dropped(self, watcher: CertWatcher, database: Any) -> None:
        padding = "x" * certwatch.MAX_MESSAGE_BYTES
        big = json.dumps(
            {
                "message_type": "certificate_update",
                "data": {"leaf_cert": {"all_domains": [LOOKALIKE], "as_der": padding}},
            }
        )
        assert watcher.handle(big) == 0
        assert watcher.handle(big.encode()) == 0
        assert deliveries(database) == []
        assert watcher.counters.dropped == 2

    def test_names_in_one_message_are_capped(self, watcher: CertWatcher) -> None:
        many = [f"host{n}.example.org" for n in range(5000)]
        assert len(names_in(cert(*many, LOOKALIKE))) == certwatch.MAX_NAMES_PER_MESSAGE
        assert watcher.handle(cert(*many, LOOKALIKE)) == 0

    @pytest.mark.parametrize(
        "name",
        [
            "acme-protocol-app.com/../../etc/passwd",
            "acme-protocol-app.com\nBcc: everyone@example.org",
            "acme-protocol-app.com\x00",
            "<script>alert(1)</script>.acme-protocol-app.com",
            "acme-protocol-app.com; rm -rf /",
            "acme-protocol app.com",
            "https://acme-protocol-app.com/login",
            "user@acme-protocol-app.com",
            "-acme-protocol-app.com",
            "acme-protocol-app..com",
            "acme-protocol",
            "acme-protocol.localhost-only-name",
            "acme-protocol.10",
            "10.0.0.1",
            "acme-protocol-" + "a" * 70 + ".com",
            "acme-protocol." + "a." * 130 + "com",
            "a" * 300 + ".acme-protocol-app.com",
        ],
    )
    def test_hostile_names_are_refused(
        self, watcher: CertWatcher, database: Any, name: str
    ) -> None:
        assert watcher.handle(cert(name)) == 0
        assert deliveries(database) == []
        assert watcher.counters.errors == 0

    def test_a_name_in_another_script_is_shown_in_its_encoded_form(
        self, watcher: CertWatcher, database: Any
    ) -> None:
        assert watcher.handle(cert("acme-protocol-\u0430pp.com")) == 1
        (delivery,) = deliveries(database)
        assert "xn--acme-protocol-pp-6dn[.]com" in delivery.body
        assert delivery.body.isascii()

    def test_values_that_are_not_text_are_skipped(self, watcher: CertWatcher) -> None:
        assert names_in(cert(5, None, ["x"], {"a": 1}, True, "", LOOKALIKE)) == [LOOKALIKE]

    def test_a_failure_while_recording_is_contained(
        self, watcher: CertWatcher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("database is down")

        monkeypatch.setattr(watcher.database, "session", broken)
        assert watcher.handle(cert(LOOKALIKE)) == 0
        assert watcher.counters.errors == 1
        monkeypatch.undo()
        assert watcher.handle(cert(LOOKALIKE)) == 1, "nothing was marked as told"


class TestNoContact:
    def test_the_watcher_has_nothing_to_contact_a_domain_with(self) -> None:
        tree = ast.parse(Path(certwatch.__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        for module in imported:
            assert not module.startswith(
                ("httpx", "socket", "dns", "urllib.request", "parapet.clients", "parapet.modules")
            ), module


class TestAddress:
    @pytest.mark.parametrize(
        "url", ["ws://certstream:8080/", "wss://certstream.internal.example/domains-only"]
    )
    def test_websocket_addresses_are_accepted(self, url: str) -> None:
        assert check_url(url) == url

    @pytest.mark.parametrize(
        "url",
        [None, "", "  ", 5, "http://certstream:8080/", "certstream:8080", "ws://", "file:///etc",
         "ws://host/ path", "ws://host/\npath", "ws://host/" + "a" * 500, "ws://[bad"],
    )  # fmt: skip
    def test_anything_else_is_refused(self, url: Any) -> None:
        assert check_url(url) is None

    def test_without_the_setting_the_watcher_stays_off(
        self, settings: Settings, database: Any
    ) -> None:
        def connect(url: str) -> Any:
            raise AssertionError("nothing may be connected to")

        watcher = CertWatcher(settings, database, connect=connect)
        assert watcher.url is None
        asyncio.run(watcher.run_forever(asyncio.Event()))


class FakeStream:
    """Stands in for the websocket library. Each connection plays one script."""

    def __init__(self, scripts: list[list[Any]], stopping: asyncio.Event) -> None:
        self.scripts = scripts
        self.stopping = stopping
        self.opened: list[str] = []

    def __call__(self, url: str) -> Any:
        self.opened.append(url)
        if not self.scripts:
            self.stopping.set()
            raise ConnectionRefusedError("no more connections in this test")
        return _Connection(self.scripts.pop(0))


class _Connection:
    def __init__(self, script: list[Any]) -> None:
        self.script = script

    async def __aenter__(self) -> Any:
        if self.script and isinstance(self.script[0], Exception):
            raise self.script[0]
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    def __aiter__(self) -> Any:
        return self

    async def __anext__(self) -> Any:
        if not self.script:
            raise StopAsyncIteration
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestConnection:
    @pytest.fixture(autouse=True)
    def no_waiting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(certwatch, "BACKOFF_FIRST_S", 0.001)
        monkeypatch.setattr(certwatch, "BACKOFF_MAX_S", 0.004)

    def run(self, settings: Settings, database: Any, scripts: list[list[Any]]) -> Any:
        async def go() -> tuple[CertWatcher, FakeStream]:
            stopping = asyncio.Event()
            stream = FakeStream(scripts, stopping)
            watcher = CertWatcher(settings, database, connect=stream)
            watcher.url = "ws://certstream:8080/"
            await asyncio.wait_for(watcher.run_forever(stopping), 10)
            return watcher, stream

        return asyncio.run(go())

    def test_it_reconnects_and_carries_on(
        self, settings: Settings, database: Any, acme: uuid.UUID
    ) -> None:
        watcher, stream = self.run(
            settings,
            database,
            [
                [ConnectionRefusedError("refused")],
                [cert("shop.example.org"), "garbage", ConnectionResetError("reset")],
                [OSError("network is unreachable")],
                [cert(LOOKALIKE), cert(LOOKALIKE)],
                [],
            ],
        )
        assert len(stream.opened) == 6
        assert set(stream.opened) == {"ws://certstream:8080/"}
        assert watcher.counters.messages == 4
        assert len(deliveries(database, acme)) == 1

    def test_the_wait_between_attempts_grows_and_is_capped(
        self, settings: Settings, database: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        waits: list[float] = []
        real_wait_for = asyncio.wait_for

        async def record(awaitable: Any, timeout: float) -> Any:
            if timeout < 1:
                waits.append(timeout)
            return await real_wait_for(awaitable, timeout)

        monkeypatch.setattr(certwatch.asyncio, "wait_for", record)
        self.run(settings, database, [[OSError("down")] for _ in range(6)])
        assert len(waits) == 6
        ceilings = [0.001, 0.002, 0.004, 0.004, 0.004, 0.004]
        for wait, ceiling in zip(waits, ceilings, strict=True):
            assert ceiling / 2 <= wait <= ceiling

    def test_a_missing_websocket_package_switches_it_off_quietly(
        self, settings: Settings, database: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing(name: str) -> Any:
            raise ModuleNotFoundError(name)

        monkeypatch.setattr(certwatch.importlib, "import_module", missing)
        watcher = CertWatcher(settings, database)
        watcher.url = "ws://certstream:8080/"
        asyncio.run(asyncio.wait_for(watcher.run_forever(asyncio.Event()), 5))

    def test_stopping_ends_the_loop(self, settings: Settings, database: Any) -> None:
        async def go() -> int:
            stopping = asyncio.Event()

            class Endless(_Connection):
                async def __anext__(self) -> Any:
                    await asyncio.sleep(0)
                    if watcher.counters.messages >= 20:
                        stopping.set()
                    return cert("shop.example.org")

            watcher = CertWatcher(settings, database, connect=lambda url: Endless([]))
            watcher.url = "ws://certstream:8080/"
            await asyncio.wait_for(watcher.run_forever(stopping), 10)
            return watcher.counters.messages

        assert asyncio.run(go()) >= 20
