"""One organisation must never see or change another's data.

Alice's organisation owns a domain with a scan, findings and an alert channel.
Mallory, signed in to a different organisation, tries every route with Alice's
identifiers. Everything must answer as if those objects did not exist.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from perimeterwatch.storage.tables import AlertChannel, AuditLog, FindingRow, Scan, TargetRow
from tests.conftest import ROOT
from tests.web.conftest import Browser

# Path parameters each route takes, filled in from Alice's objects.
SAMPLE = {
    "target_id": "target",
    "scan_id": "scan",
    "finding_id": "finding",
    "channel_id": "channel",
}
# Routes that take no identifier and only ever act on the caller's own tenant.
NO_IDENTIFIER = {
    "/", "/login", "/logout", "/healthz", "/report.css", "/targets", "/alerts", "/audit",
    "/auth/{token}", "/legal", "/legal/{slug}", "/.well-known/security.txt",
}  # fmt: skip


@pytest.fixture
def world(
    alice: Browser, mallory: Browser, worker: Any, verify_dns: Any, database: Any
) -> dict[str, Any]:
    target_id = alice.add_target()
    alice.post(f"/targets/{target_id}/verify/start")
    verify_dns(True)
    assert alice.post(f"/targets/{target_id}/verify/check").status_code == 303
    alice.follow(alice.post(f"/targets/{target_id}/scans", {"depth": "passive"}))
    alice.post("/alerts", {"kind": "email", "to": f"sec@{ROOT}", "label": "Inbox"})

    import asyncio

    asyncio.run(worker.run_next())
    with database.session() as db:
        ids = {
            "target": target_id,
            "scan": str(db.scalars(select(Scan)).one().id),
            "finding": str(
                db.scalars(select(FindingRow).where(FindingRow.sensitivity == "personal")).one().id
            ),
            "channel": str(db.scalars(select(AlertChannel)).one().id),
        }
    mallory.add_target("rival-protocol.xyz")
    return {"ids": ids, "alice": alice, "mallory": mallory}


def routes_with_identifiers(app: Any) -> list[tuple[str, str]]:
    from perimeterwatch.web.routes import router

    found = []
    for route in router.routes:
        path = getattr(route, "path", "")
        if path.startswith("/static") or path in NO_IDENTIFIER:
            continue
        for method in sorted(getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}):
            found.append((method, path))
    return sorted(found)


def fill(path: str, ids: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name == "fmt":
            return "json"
        return ids[SAMPLE[name]]

    return re.sub(r"\{(\w+)\}", replace, path)


class TestIsolation:
    def test_the_matrix_covers_every_route(self, app: Any) -> None:
        """A new route with an identifier must be added to SAMPLE, or this fails."""
        unknown = set()
        for _method, path in routes_with_identifiers(app):
            for name in re.findall(r"\{(\w+)\}", path):
                if name not in SAMPLE and name != "fmt":
                    unknown.add(f"{path}: {name}")
        assert unknown == set()
        assert len(routes_with_identifiers(app)) >= 12

    def test_every_route_hides_another_tenants_objects(
        self, app: Any, world: dict[str, Any]
    ) -> None:
        mallory: Browser = world["mallory"]
        alice: Browser = world["alice"]
        checked = 0
        for method, template in routes_with_identifiers(app):
            path = fill(template, world["ids"])
            if method == "GET":
                theirs = mallory.client.get(path)
                own = alice.client.get(path)
                assert own.status_code == 200, f"{path} should work for its owner"
            else:
                theirs = mallory.post(
                    path, {"confirm": ROOT, "status": "accepted", "depth": "passive"}
                )
            assert theirs.status_code == 404, f"{method} {template} answered {theirs.status_code}"
            for leak in (ROOT, "ana.lopez", "ExampleCo", "DMARC", "pw-verify"):
                assert leak not in theirs.text, f"{method} {template} leaked {leak!r}"
            checked += 1
        assert checked >= 12

    def test_nothing_of_alices_was_changed(
        self, app: Any, world: dict[str, Any], database: Any
    ) -> None:
        mallory: Browser = world["mallory"]
        for method, template in routes_with_identifiers(app):
            if method == "POST":
                mallory.post(fill(template, world["ids"]), {"confirm": ROOT, "status": "accepted"})
        with database.session() as db:
            target = db.get(TargetRow, uuid.UUID(world["ids"]["target"]))
            assert target is not None and target.root_domain == ROOT
            assert len(list(db.scalars(select(Scan).where(Scan.target_id == target.id)))) == 1
            finding = db.get(FindingRow, uuid.UUID(world["ids"]["finding"]))
            assert finding is not None and finding.status == "open"
            assert db.get(AlertChannel, uuid.UUID(world["ids"]["channel"])) is not None

    def test_lists_show_only_the_callers_own(self, world: dict[str, Any]) -> None:
        mallory: Browser = world["mallory"]
        for path in ("/targets", "/alerts", "/audit"):
            text = mallory.get(path).text
            assert "rival-protocol.xyz" in text or path != "/targets"
            for leak in (f"alice@{ROOT}", f"sec@{ROOT}", "Inbox", f">{ROOT}<"):
                assert leak not in text, f"{path} leaked {leak!r}"

    def test_attempts_are_not_written_to_the_victims_audit_log(
        self, world: dict[str, Any], database: Any
    ) -> None:
        mallory: Browser = world["mallory"]
        mallory.client.get(f"/findings/{world['ids']['finding']}")
        with database.session() as db:
            actors = {a.actor for a in db.scalars(select(AuditLog)) if "finding" in a.action}
        assert "mallory@rival-protocol.xyz" not in actors

    def test_tenant_cannot_be_chosen_by_the_request(
        self, world: dict[str, Any], database: Any
    ) -> None:
        mallory: Browser = world["mallory"]
        with database.session() as db:
            alices_tenant = str(db.get(TargetRow, uuid.UUID(world["ids"]["target"])).tenant_id)
        for extra in ({"tenant_id": alices_tenant}, {"tenant": alices_tenant}):
            mallory.post("/targets", {"domain": "third-protocol.xyz", **extra})
        mallory.client.get(f"/targets?tenant_id={alices_tenant}")
        with database.session() as db:
            row = db.scalars(
                select(TargetRow).where(TargetRow.root_domain == "third-protocol.xyz")
            ).one()
            assert str(row.tenant_id) != alices_tenant

    def test_two_tenants_can_list_the_same_domain_separately(
        self, world: dict[str, Any], database: Any
    ) -> None:
        mallory: Browser = world["mallory"]
        theirs = mallory.add_target(ROOT)
        assert theirs != world["ids"]["target"]
        page = mallory.get(f"/targets/{theirs}").text
        assert "Not verified" in page
        assert "ana.lopez" not in page and "pw-verify" not in page

    @pytest.mark.parametrize(
        "bad",
        [
            "not-a-uuid",
            "1",
            "00000000-0000-0000-0000-000000000000",
            "%00",
            "' OR '1'='1",
        ],
    )
    def test_malformed_identifiers(self, alice: Browser, bad: str) -> None:
        for prefix in ("/targets/", "/scans/", "/findings/"):
            response = alice.client.get(prefix + bad)
            assert response.status_code == 404
            assert "Traceback" not in response.text


class TestRoles:
    def test_viewers_can_read_but_not_change(self, alice: Browser, database: Any) -> None:
        from perimeterwatch.storage.tables import Membership

        target_id = alice.add_target()
        with database.session() as db:
            db.scalars(select(Membership)).one().role = "viewer"
        assert alice.get(f"/targets/{target_id}").status_code == 200
        assert "<form" not in alice.get(f"/targets/{target_id}").text.split("</header>")[1]
        for path, data in [
            ("/targets", {"domain": "other.xyz"}),
            (f"/targets/{target_id}/scans", {"depth": "passive"}),
            (f"/targets/{target_id}/verify/start", {}),
            (f"/targets/{target_id}/delete", {"confirm": ROOT}),
            ("/alerts", {"kind": "email", "to": f"x@{ROOT}"}),
        ]:
            assert alice.post(path, data).status_code == 403, path
        assert alice.get("/audit").status_code == 403
