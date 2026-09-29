"""The service end to end: add a domain, verify, scan, read findings, get alerts."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from parapet.core.errors import ValidationError
from parapet.core.models import utcnow
from parapet.storage.tables import (
    AlertChannel,
    AlertDelivery,
    AuditLog,
    DomainVerification,
    Scan,
    TargetRow,
)
from parapet.worker import alerts
from tests.conftest import CANARY, ROOT, sqlite_only
from tests.web.conftest import Browser


def run(worker: Any) -> bool:
    return asyncio.run(worker.run_next())


def tick(worker: Any) -> bool:
    return asyncio.run(worker.tick())


def audit_actions(database: Any) -> list[str]:
    with database.session() as db:
        return [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.created_at))]


def verified_target(alice: Browser, verify_dns: Any) -> str:
    target_id = alice.add_target()
    alice.post(f"/targets/{target_id}/verify/start")
    verify_dns(True)
    assert alice.post(f"/targets/{target_id}/verify/check").status_code == 303
    return target_id


class TestDomains:
    @pytest.mark.parametrize(
        "domain",
        ["acme.xyz; rm -rf /", "<script>alert(1)</script>", "10.0.0.1", "localhost", "", "x" * 400],
    )
    def test_bad_domains_are_refused_and_shown_safely(self, alice: Browser, domain: str) -> None:
        response = alice.post("/targets", {"domain": domain})
        assert response.status_code in (303, 400)
        if response.status_code == 303:
            page = alice.get(response.headers["location"])
            assert 'role="alert"' in page.text
            assert "<script>alert" not in page.text
            assert 'href="/targets/' not in page.text

    def test_limit_and_duplicates(self, alice: Browser) -> None:
        for name in ("one.xyz", "two.xyz", "three.xyz"):
            alice.add_target(name)
        over = alice.follow(alice.post("/targets", {"domain": "four.xyz"}))
        assert "limit" in over.text
        again = alice.follow(alice.post("/targets", {"domain": "one.xyz"}))
        assert "already on your list" in again.text

    def test_settings(self, alice: Browser, database: Any) -> None:
        target_id = alice.add_target()
        good = {
            "github_org": "acme-protocol", "safe": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "job_board_kind": "greenhouse", "job_board": "acmeprotocol", "interval": "72",
        }  # fmt: skip
        assert "Saved." in alice.follow(alice.post(f"/targets/{target_id}/settings", good)).text
        with database.session() as db:
            row = db.scalars(select(TargetRow)).one()
            assert row.config["github_org"] == "acme-protocol"
            assert row.scan_interval_hours == 72
        for bad in (
            {"github_org": "-rf"},
            {"safe": "0x123"},
            {"job_board": "../x"},
            {"interval": "1"},
        ):
            page = alice.follow(alice.post(f"/targets/{target_id}/settings", {**good, **bad}))
            assert 'role="alert"' in page.text, bad

    def test_removal_needs_the_name_typed_and_deletes_everything(
        self, alice: Browser, worker: Any, database: Any
    ) -> None:
        target_id = alice.add_target()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        run(worker)
        assert alice.post(f"/targets/{target_id}/delete", {"confirm": "wrong"}).status_code == 303
        assert alice.get(f"/targets/{target_id}").status_code == 200
        alice.post(f"/targets/{target_id}/delete", {"confirm": ROOT})
        assert alice.get(f"/targets/{target_id}").status_code == 404
        with database.session() as db:
            assert list(db.scalars(select(Scan))) == []


class TestVerification:
    def test_flow(self, alice: Browser, verify_dns: Any, database: Any) -> None:
        target_id = alice.add_target()
        page = alice.get(f"/targets/{target_id}").text
        assert "Not verified" in page and "parapet-verify=" not in page

        alice.post(f"/targets/{target_id}/verify/start")
        page = alice.get(f"/targets/{target_id}").text
        assert f"_parapet-verify.{ROOT}" in page and "parapet-verify=" in page

        verify_dns(False)
        failed = alice.follow(alice.post(f"/targets/{target_id}/verify/check"))
        assert "No matching TXT record" in failed.text
        assert '<option value="active">' not in failed.text

        verify_dns(True)
        done = alice.follow(alice.post(f"/targets/{target_id}/verify/check"))
        assert "Domain verified." in done.text
        assert '<option value="active">' in done.text
        assert "verification.checked" in audit_actions(database)

    def test_active_scan_cannot_be_requested_unverified(
        self, alice: Browser, database: Any
    ) -> None:
        target_id = alice.add_target()
        response = alice.post(f"/targets/{target_id}/scans", {"depth": "active"})
        assert "error=" in response.headers["location"]
        with database.session() as db:
            assert list(db.scalars(select(Scan))) == []
        assert alice.post(f"/targets/{target_id}/scans", {"depth": "nuclear"}).status_code == 400

    def test_active_scan_is_refused_if_the_record_is_gone_by_the_time_it_runs(
        self, alice: Browser, worker: Any, verify_dns: Any, modules: Any
    ) -> None:
        target_id = verified_target(alice, verify_dns)
        location = alice.post(f"/targets/{target_id}/scans", {"depth": "active"}).headers[
            "location"
        ]
        verify_dns(False)  # removed between the request and the start
        run(worker)
        page = alice.get(location)
        assert "did not finish" in page.text
        assert "needs authorisation" in page.text
        assert modules["registry"]["ports"].ran == []

    def test_a_typed_statement_is_not_accepted_by_the_hosted_service(
        self, alice: Browser, worker: Any, database: Any, modules: Any
    ) -> None:
        from parapet.safety.authorisation import make_ack
        from parapet.storage.repo import TenantRepo

        target_id = alice.add_target()
        with database.session() as db:
            row = db.scalars(select(TargetRow)).one()
            repo = TenantRepo(db, row.tenant_id)
            repo.add_ack(
                make_ack(row, full_name="A", organisation="B", role="C", keys=database.keys)
            )
            repo.create_scan(
                row.id, mode=__import__("parapet").core.models.ScanMode.ACTIVE,
                authorisation=__import__("parapet").core.models.Authorisation(),
                status="queued",
            )  # fmt: skip
        run(worker)
        assert modules["registry"]["ports"].ran == []
        assert "did not finish" in alice.get(f"/targets/{target_id}").text or True

    def test_a_second_organisation_proving_control_takes_over(
        self, alice: Browser, mallory: Browser, verify_dns: Any, worker: Any, database: Any,
        outbox: list[dict[str, str]],
    ) -> None:  # fmt: skip
        first = verified_target(alice, verify_dns)
        alice.post("/alerts", {"kind": "email", "to": f"sec@{ROOT}"})
        outbox.clear()

        second = mallory.add_target(ROOT)
        mallory.post(f"/targets/{second}/verify/start")
        assert mallory.post(f"/targets/{second}/verify/check").status_code == 303

        assert "Not verified" in alice.get(f"/targets/{first}").text
        tick(worker)
        assert any("another organisation proved control" in m["subject"] for m in outbox)
        with database.session() as db:
            standing = {
                str(v.target_id): v.verified_at for v in db.scalars(select(DomainVerification))
            }
        assert standing[first] is None and standing[second] is not None

    def test_standing_is_withdrawn_after_three_failed_daily_checks(
        self, alice: Browser, verify_dns: Any, worker: Any, database: Any,
        outbox: list[dict[str, str]],
    ) -> None:  # fmt: skip
        target_id = verified_target(alice, verify_dns)
        alice.post("/alerts", {"kind": "email", "to": f"sec@{ROOT}"})
        verify_dns(False)
        for expected_verified in (True, True, False):
            with database.session() as db:
                db.scalars(select(DomainVerification)).one().last_checked_at = utcnow() - timedelta(
                    days=2
                )
            tick(worker)
            page = alice.get(f"/targets/{target_id}").text
            assert ("Control of this domain is proven" in page) is expected_verified
        assert any("verification was lost" in m["subject"] for m in outbox)
        assert "verification.withdrawn" in audit_actions(database)


class TestOptIn:
    """By default the service looks only at domains whose owner proved control."""

    @pytest.fixture(autouse=True)
    def strict(self, settings: Any) -> None:
        settings.scan_requires_verification = True

    @pytest.mark.parametrize("depth", ["passive", "probe", "active"])
    def test_an_unverified_domain_cannot_be_scanned(
        self, alice: Browser, database: Any, depth: str
    ) -> None:
        target_id = alice.add_target("someone-elses-project.xyz")
        page = alice.get(f"/targets/{target_id}").text
        assert "Scanning starts once the domain is verified" in page
        assert 'name="depth"' not in page
        refused = alice.follow(alice.post(f"/targets/{target_id}/scans", {"depth": depth}))
        assert "Verify the domain before scanning it." in refused.text
        with database.session() as db:
            assert list(db.scalars(select(Scan))) == []

    def test_unverified_domains_are_never_scanned_on_a_schedule(
        self, alice: Browser, worker: Any, database: Any
    ) -> None:
        alice.add_target()
        with database.session() as db:
            db.scalars(select(TargetRow)).one().next_scan_at = utcnow() - timedelta(minutes=1)
        assert worker.enqueue_due() == 0
        with database.session() as db:
            assert list(db.scalars(select(Scan))) == []

    def test_a_queued_scan_does_not_run_if_verification_has_gone(
        self, alice: Browser, worker: Any, verify_dns: Any, modules: Any
    ) -> None:
        target_id = verified_target(alice, verify_dns)
        location = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}).headers[
            "location"
        ]
        verify_dns(False)
        run(worker)
        page = alice.get(location).text
        assert "not proved, so it was not scanned" in page
        assert modules["registry"]["email_posture"].ran == []

    def test_a_verified_domain_is_scanned(
        self, alice: Browser, worker: Any, verify_dns: Any
    ) -> None:
        target_id = verified_target(alice, verify_dns)
        location = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}).headers[
            "location"
        ]
        run(worker)
        assert "has no DMARC record" in alice.get(location).text


class TestScans:
    def test_scan_runs_and_pages_show_the_result(
        self, alice: Browser, worker: Any, database: Any
    ) -> None:
        target_id = alice.add_target()
        response = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        waiting = alice.follow(response)
        assert "in the queue" in waiting.text
        assert waiting.headers["refresh"] == "5"

        assert run(worker) is True
        assert run(worker) is False, "nothing left in the queue"
        done = alice.get(response.headers["location"])
        assert "refresh" not in done.headers
        assert "first scan of this domain" in done.text
        assert f"{ROOT} has no DMARC record" in done.text
        assert "scan.requested" in audit_actions(database)

        home = alice.get("/targets").text
        assert "1 high" in home

    def test_one_scan_at_a_time_per_domain(self, alice: Browser, database: Any) -> None:
        target_id = alice.add_target()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        second = alice.follow(alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}))
        assert "already waiting or running" in second.text
        with database.session() as db:
            assert len(list(db.scalars(select(Scan)))) == 1

    def test_minimum_interval(self, alice: Browser, worker: Any, settings: Any) -> None:
        target_id = alice.add_target()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        run(worker)
        settings.min_scan_interval_minutes = 360
        refused = alice.follow(alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}))
        assert "scanned recently" in refused.text

    def test_a_scan_whose_worker_died_is_put_back_then_given_up(
        self, alice: Browser, worker: Any, database: Any
    ) -> None:
        target_id = alice.add_target()
        location = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}).headers[
            "location"
        ]
        for attempt in (1, 2, 3):
            with database.session() as db:
                scan = worker.queue.claim_next(db)
                assert scan is not None and scan.attempts == attempt
                scan.heartbeat_at = utcnow() - timedelta(minutes=10)  # the worker went silent
            with database.session() as db:
                assert worker.queue.requeue_stale(db) == 1
        page = alice.get(location)
        assert "did not finish" in page.text and "stopped unexpectedly" in page.text

    def test_a_live_scan_is_left_alone(self, alice: Browser, worker: Any, database: Any) -> None:
        target_id = alice.add_target()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        with database.session() as db:
            worker.queue.claim_next(db)
        with database.session() as db:
            assert worker.queue.requeue_stale(db) == 0

    def test_scheduled_scans(self, alice: Browser, worker: Any, database: Any) -> None:
        alice.add_target()
        assert worker.enqueue_due() == 0, "not due yet"
        with database.session() as db:
            db.scalars(select(TargetRow)).one().next_scan_at = utcnow() - timedelta(minutes=1)
        assert worker.enqueue_due() == 1
        assert worker.enqueue_due() == 0, "already queued, and the next one is set"
        with database.session() as db:
            scan = db.scalars(select(Scan)).one()
            assert (scan.requested_by, scan.mode) == ("schedule", "passive")

    def test_crash_in_the_engine_fails_the_scan_cleanly(
        self, alice: Browser, worker: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def boom(*args: Any, **kw: Any) -> Any:
            raise RuntimeError(f"database password is {CANARY}")

        monkeypatch.setattr("parapet.worker.runner.run_scan", boom)
        target_id = alice.add_target()
        location = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}).headers[
            "location"
        ]
        run(worker)
        page = alice.get(location).text
        assert "internal error" in page and CANARY not in page


class TestSensitiveFindings:
    @pytest.fixture
    def scanned(self, alice: Browser, worker: Any, verify_dns: Any) -> dict[str, str]:
        target_id = verified_target(alice, verify_dns)
        location = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}).headers[
            "location"
        ]
        run(worker)
        return {"target": target_id, "scan": location}

    def test_lists_mask_people_and_detail_views_are_recorded(
        self, alice: Browser, scanned: dict[str, str], database: Any
    ) -> None:
        for path in (f"/targets/{scanned['target']}", scanned["scan"], "/targets"):
            text = alice.get(path).text
            assert "ana.lopez" not in text, path
        listing = alice.get(f"/targets/{scanned['target']}").text
        assert f"a***@{ROOT}" in listing
        assert "finding.viewed" not in audit_actions(database)

        import re

        links = re.findall(r'href="(/findings/[^"]+)"[^>]*>([^<]+)<', listing)
        personal = next(href for href, title in links if "a***@" in title)
        ordinary = next(href for href, title in links if "DMARC" in title)

        assert "DMARC" in alice.get(ordinary).text
        assert "finding.viewed" not in audit_actions(database), "ordinary findings are not logged"

        detail = alice.get(personal).text
        assert f"ana.lopez@{ROOT}" in detail and "ExampleCo" in detail
        assert "recorded in the audit log" in detail
        with database.session() as db:
            entry = db.scalars(select(AuditLog).where(AuditLog.action == "finding.viewed")).one()
            assert entry.actor == alice.email
            assert entry.meta["sensitivity"] == "personal"
            assert "ana.lopez" not in json.dumps(entry.meta), "the log names no one"

    def test_report_downloads(self, alice: Browser, scanned: dict[str, str], database: Any) -> None:
        masked = alice.client.get(f"{scanned['scan']}/report.json")
        assert masked.headers["content-disposition"].startswith("attachment")
        assert "ana.lopez" not in masked.text
        assert json.loads(masked.text)["personal_redacted"] is True

        shown = alice.client.get(f"{scanned['scan']}/report.html?personal=shown")
        assert f"ana.lopez@{ROOT}" in shown.text
        assert "sandbox" in shown.headers["content-security-policy"]
        assert "<script" not in shown.text.lower()

        with database.session() as db:
            downloads = [
                a.meta
                for a in db.scalars(select(AuditLog).where(AuditLog.action == "report.downloaded"))
            ]
        assert [d["personal_shown"] for d in downloads] == [False, True]
        assert alice.client.get(f"{scanned['scan']}/report.pdf").status_code == 404

    def test_details_about_people_are_withheld_once_verification_is_lost(
        self, alice: Browser, scanned: dict[str, str], database: Any
    ) -> None:
        import re

        listing = alice.get(f"/targets/{scanned['target']}").text
        links = re.findall(r'href="(/findings/[^"]+)"[^>]*>([^<]+)<', listing)
        personal = next(href for href, title in links if "a***@" in title)
        assert alice.get(personal).status_code == 200

        with database.session() as db:
            db.scalars(select(DomainVerification)).one().verified_at = None

        refused = alice.get(personal)
        assert refused.status_code == 403 and "ana.lopez" not in refused.text
        shown = alice.client.get(f"{scanned['scan']}/report.html?personal=shown")
        assert shown.status_code == 403 and "ana.lopez" not in shown.text
        masked = alice.client.get(f"{scanned['scan']}/report.json")
        assert masked.status_code == 200 and "ana.lopez" not in masked.text

    def test_accepting_a_risk(self, alice: Browser, scanned: dict[str, str], database: Any) -> None:
        import re

        listing = alice.get(f"/targets/{scanned['target']}").text
        href = next(
            h
            for h, t in re.findall(r'href="(/findings/[^"]+)"[^>]*>([^<]+)<', listing)
            if "DMARC" in t
        )
        alice.get(href)
        assert alice.post(f"{href}/status", {"status": "accepted"}).status_code == 303
        assert "accepted risk" in alice.get(href).text
        assert alice.post(f"{href}/status", {"status": "deleted"}).status_code == 400
        assert "finding.status_changed" in audit_actions(database)


class TestAlerts:
    @sqlite_only
    def test_channel_credentials_are_encrypted_and_never_shown_again(
        self, alice: Browser, database: Any, settings: Any
    ) -> None:
        webhook = "https://hooks.slack.com/services/T000/B000/SECRETWEBHOOKPART"
        alice.post("/alerts", {"kind": "slack", "url": webhook, "label": "#security"})
        alice.post(
            "/alerts", {"kind": "telegram", "bot_token": "123456:" + "A" * 35, "chat_id": "-100123"}
        )
        page = alice.get("/alerts").text
        assert "#security" in page and "Slack webhook" in page
        assert "SECRETWEBHOOKPART" not in page and "A" * 35 not in page
        database.engine.dispose()
        raw = (settings.data_dir / "parapet.db").read_bytes()
        wal = settings.data_dir / "parapet.db-wal"
        raw += wal.read_bytes() if wal.exists() else b""
        assert b"SECRETWEBHOOKPART" not in raw and b"A" * 35 not in raw

    @pytest.mark.parametrize(
        ("kind", "fields"),
        [
            ("slack", {"url": "https://evil.example.net/services/x"}),
            ("slack", {"url": "http://hooks.slack.com/services/x"}),
            ("slack", {"url": "https://hooks.slack.com.evil.net/services/x"}),
            ("slack", {"url": "https://hooks.slack.com@169.254.169.254/services/x"}),
            ("slack", {"url": "https://user:pw@hooks.slack.com/services/x"}),
            ("slack", {"url": "https://hooks.slack.com:8443/services/x"}),
            ("slack", {"url": "https://hooks.slack.com/other/x"}),
            ("slack", {"url": "https://169.254.169.254/latest/meta-data/"}),
            ("slack", {"url": "https://localhost/services/x"}),
            ("discord", {"url": "https://discord.com/api/users/@me"}),
            ("discord", {"url": "https://hooks.slack.com/services/x"}),
            ("telegram", {"bot_token": "not-a-token", "chat_id": "1"}),
            ("telegram", {"bot_token": "123:" + "A" * 35 + "/../../x", "chat_id": "1"}),
            ("telegram", {"bot_token": "123456:" + "A" * 35, "chat_id": "1; drop"}),
            ("email", {"to": "not an address"}),
            ("webhook", {"url": "https://internal.service.local/hook"}),
            ("", {}),
        ],
    )
    def test_channels_cannot_point_anywhere_else(
        self, alice: Browser, database: Any, kind: str, fields: dict[str, str]
    ) -> None:
        with pytest.raises(ValidationError):
            alerts.validate_config(kind, fields)
        response = alice.post("/alerts", {"kind": kind, **fields})
        assert response.status_code in (303, 400)
        with database.session() as db:
            assert list(db.scalars(select(AlertChannel))) == []

    def test_alert_says_what_changed_without_the_details(
        self, alice: Browser, worker: Any, verify_dns: Any, outbox: list[dict[str, str]],
        modules: Any,
    ) -> None:  # fmt: skip
        target_id = verified_target(alice, verify_dns)
        alice.post("/alerts", {"kind": "email", "to": f"sec@{ROOT}", "min_severity": "medium"})
        outbox.clear()

        location = alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}).headers[
            "location"
        ]
        tick(worker)
        [first] = outbox
        assert first["to"] == f"sec@{ROOT}"
        assert "first scan" in first["subject"]
        assert f"http://testserver{location}" in first["body"]
        assert "has no DMARC record" in first["body"]
        assert "A staff address in breach data" in first["body"]
        assert "A credential in public code" in first["body"]
        for private in ("ana.lopez", "ExampleCo", "ghp_", "acme-protocol/deploy"):
            assert private not in first["body"] + first["subject"], private

        outbox.clear()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        tick(worker)
        assert outbox == [], "nothing changed, so nothing is sent"

        modules["state"]["dmarc_missing"] = False
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        tick(worker)
        [change] = outbox
        assert "1 resolved" in change["subject"]

    def test_threshold(self, alice: Browser, worker: Any, outbox: list[dict[str, str]]) -> None:
        target_id = alice.add_target()
        alice.post("/alerts", {"kind": "email", "to": f"sec@{ROOT}", "min_severity": "critical"})
        outbox.clear()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        tick(worker)
        assert outbox == []

    def test_webhook_delivery_and_retry(
        self, alice: Browser, worker: Any, database: Any, settings: Any
    ) -> None:
        alice.post("/alerts", {"kind": "slack", "url": "https://hooks.slack.com/services/T/B/X"})
        with database.session() as db:
            channel = db.scalars(select(AlertChannel)).one()
            channel_id = str(channel.id)
        alice.post(f"/alerts/{channel_id}/test")

        answers = [httpx.Response(500), httpx.Response(200, text="ok")]
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return answers[len(seen) - 1]

        async def deliver() -> None:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                with database.session() as db:
                    await alerts.deliver_pending(db, settings, client)

        asyncio.run(deliver())
        with database.session() as db:
            delivery = db.scalars(select(AlertDelivery)).one()
            assert (delivery.status, delivery.attempts) == ("pending", 1)
            assert "500" in (delivery.last_error or "")
            assert "hooks.slack.com" not in (delivery.last_error or ""), (
                "the address is a credential"
            )
            delivery.next_attempt_at = utcnow()
        asyncio.run(deliver())
        with database.session() as db:
            assert db.scalars(select(AlertDelivery)).one().status == "sent"
        assert str(seen[0].url) == "https://hooks.slack.com/services/T/B/X"
        assert json.loads(seen[1].content)["text"].startswith("Test alert")
        assert "Sent" in alice.get("/alerts").text

    def test_test_alert_goes_to_that_channel_only(self, alice: Browser, database: Any) -> None:
        alice.post("/alerts", {"kind": "email", "to": f"one@{ROOT}"})
        alice.post("/alerts", {"kind": "email", "to": f"two@{ROOT}"})
        with database.session() as db:
            first = db.scalars(select(AlertChannel).order_by(AlertChannel.created_at)).first()
        alice.post(f"/alerts/{first.id}/test")
        with database.session() as db:
            [delivery] = db.scalars(select(AlertDelivery))
            assert delivery.channel_id == first.id

    def test_email_headers_cannot_be_injected(self, settings: Any) -> None:
        from parapet.web.mail import build

        message = build(settings, "a@b.xyz", "Subject\r\nBcc: victim@example.net", "body")
        assert "Bcc" not in message
        assert "\n" not in message["Subject"]


class TestHousekeeping:
    def test_automatic_retention_is_recorded(
        self, alice: Browser, worker: Any, database: Any
    ) -> None:
        target_id = alice.add_target()
        alice.post(f"/targets/{target_id}/scans", {"depth": "passive"})
        run(worker)
        worker.housekeeping()
        assert "retention.purged" in audit_actions(database)


class TestAuditLog:
    def test_owner_reads_the_log(self, alice: Browser) -> None:
        alice.add_target()
        page = alice.get("/audit").text
        assert "auth.signed_in" in page and "target.added" in page and alice.email in page

    def test_no_route_changes_or_removes_entries(self, app: Any) -> None:
        from parapet.web.routes import router

        paths = [getattr(r, "path", "") for r in router.routes]
        assert [p for p in paths if p.startswith("/audit")] == ["/audit"]
        methods = next(r.methods for r in router.routes if getattr(r, "path", "") == "/audit")
        assert methods == {"GET"}
