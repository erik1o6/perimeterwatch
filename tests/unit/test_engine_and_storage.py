from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta
from typing import Any, ClassVar

import pytest

from parapet.core import engine
from parapet.core.errors import AuthorisationError, ConfigError, ValidationError
from parapet.core.models import (
    AssetType,
    AuthLevel,
    Authorisation,
    Category,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Sensitivity,
    Target,
    utcnow,
)
from parapet.core.module import ModuleSpec, ScanModule
from parapet.storage.crypto import DataKeys, new_key
from parapet.storage.repo import Cache, TenantRepo
from parapet.storage.tables import Tenant
from tests.conftest import CANARY, ROOT, sqlite_only

TARGET = Target(root_domain=ROOT, staff_emails=[f"ana@{ROOT}"])


def make_module(
    name: str,
    *,
    mode: ScanMode = ScanMode.PASSIVE,
    behaviour: Any = None,
    **spec: Any,
) -> type[ScanModule]:
    class Fake(ScanModule):
        ran: ClassVar[list[str]] = []

        async def run(self, target: Target, ctx: Any) -> ModuleResult:
            type(self).ran.append(name)
            if behaviour is not None:
                return await behaviour(self, target, ctx)
            return self.result()

    Fake.spec = ModuleSpec(name=name, title=name, category=Category.SURFACE, mode=mode, **spec)
    Fake.ran = []
    return Fake


@pytest.fixture
def modules(monkeypatch: pytest.MonkeyPatch) -> dict[str, type[ScanModule]]:
    registry: dict[str, type[ScanModule]] = {}
    monkeypatch.setattr("parapet.core.module.all_modules", lambda: dict(registry))
    monkeypatch.setattr(engine, "all_modules", lambda: dict(registry))
    monkeypatch.setattr("parapet.report.build.all_modules", lambda: dict(registry))
    return registry


async def scan(database: Any, settings: Any, **kwargs: Any) -> Any:
    kwargs.setdefault("mode", ScanMode.PASSIVE)
    kwargs.setdefault("authorisation", Authorisation())
    with database.session() as session:
        tenant = TenantRepo.local(session).tenant_id
    return await engine.run_scan(
        TARGET, settings=settings, database=database, tenant_id=tenant, **kwargs
    )


class TestGating:
    async def test_active_scan_without_authorisation_is_refused(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        modules["ports"] = make_module("ports", mode=ScanMode.ACTIVE)
        with pytest.raises(AuthorisationError):
            await scan(database, settings, mode=ScanMode.ACTIVE)
        assert modules["ports"].ran == []

    async def test_modules_above_the_requested_depth_are_skipped(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        modules["passive"] = make_module("passive")
        modules["probe"] = make_module("probe", mode=ScanMode.PROBE)
        modules["active"] = make_module("active", mode=ScanMode.ACTIVE)
        snapshot, _ = await scan(database, settings)
        status = snapshot.module_status()
        assert status == {
            "passive": ModuleStatus.OK,
            "probe": ModuleStatus.SKIPPED,
            "active": ModuleStatus.SKIPPED,
        }
        assert modules["probe"].ran == modules["active"].ran == []

    async def test_acknowledgement_allows_active_but_not_personal_data(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        modules["active"] = make_module("active", mode=ScanMode.ACTIVE)
        modules["people"] = make_module("people", requires_verification=True)
        acknowledged = Authorisation(level=AuthLevel.ACKNOWLEDGED, basis="stated")
        snapshot, _ = await scan(
            database, settings, mode=ScanMode.ACTIVE, authorisation=acknowledged
        )
        status = snapshot.module_status()
        assert status["active"] is ModuleStatus.OK
        assert status["people"] is ModuleStatus.SKIPPED
        assert modules["people"].ran == []

    async def test_missing_key_binary_and_target_setting_skip_with_a_hint(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        modules["needs_key"] = make_module("needs_key", requires_keys=("GITHUB_TOKEN",))
        modules["needs_bin"] = make_module("needs_bin", requires_binaries=("subfinder",))
        modules["needs_any"] = make_module("needs_any", any_of_binaries=("trufflehog", "gitleaks"))
        modules["needs_org"] = make_module("needs_org", requires_target=("github_org",))
        snapshot, _ = await scan(database, settings)
        by_name = {m.module: m for m in snapshot.modules}
        assert all(m.status is ModuleStatus.SKIPPED for m in by_name.values())
        assert by_name["needs_key"].skip_reason == "missing key: GITHUB_TOKEN"
        assert by_name["needs_bin"].hint == "parapet tools install subfinder"
        assert "trufflehog or gitleaks" in (by_name["needs_any"].skip_reason or "")
        assert "github org" in (by_name["needs_org"].skip_reason or "")

    def test_unknown_module_names_are_rejected(self, modules: Any) -> None:
        modules["real"] = make_module("real")
        with pytest.raises(ValidationError):
            engine.select_modules({"real", "imaginary"}, None)
        with pytest.raises(ValidationError):
            engine.select_modules(None, {"--help"})


class TestExecution:
    async def test_dependencies_run_first_and_are_pulled_in(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        order: list[str] = []

        def tracked(name: str, **spec: Any) -> type[ScanModule]:
            async def behaviour(self: Any, target: Any, ctx: Any) -> ModuleResult:
                order.append(name)
                return self.result()

            return make_module(name, behaviour=behaviour, **spec)

        modules["c"] = tracked("c", depends_on=("b",))
        modules["b"] = tracked("b", depends_on=("a",))
        modules["a"] = tracked("a")
        modules["unrelated"] = tracked("unrelated")
        await scan(database, settings, only={"c"})
        assert order == ["a", "b", "c"]

    async def test_a_crashing_module_does_not_stop_the_scan_or_leak_secrets(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        async def crash(self: Any, target: Any, ctx: Any) -> ModuleResult:
            raise RuntimeError(f"request failed with token {CANARY}")

        modules["bad"] = make_module("bad", behaviour=crash)
        modules["good"] = make_module("good")
        snapshot, _ = await scan(database, settings)
        by_name = {m.module: m for m in snapshot.modules}
        assert by_name["good"].status is ModuleStatus.OK
        assert by_name["bad"].status is ModuleStatus.FAILED
        assert CANARY not in (by_name["bad"].skip_reason or "")
        assert "[redacted]" in (by_name["bad"].skip_reason or "")

    async def test_a_slow_module_times_out(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        import asyncio

        async def hang(self: Any, target: Any, ctx: Any) -> ModuleResult:
            await asyncio.sleep(30)
            return self.result()

        modules["slow"] = make_module("slow", behaviour=hang, default_timeout_s=0)
        snapshot, _ = await scan(database, settings)
        assert snapshot.modules[0].status is ModuleStatus.FAILED
        assert "timed out" in (snapshot.modules[0].skip_reason or "")

    async def test_staff_addresses_never_enter_snapshots(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        modules["m"] = make_module("m")
        snapshot, _ = await scan(database, settings)
        assert snapshot.target.staff_emails == []
        with database.session() as session:
            repo = TenantRepo.local(session)
            stored = repo.load_snapshot(repo.get_scan(snapshot.scan_id))
            assert stored.target.staff_emails == []
            # The input itself is still on file for the next scan.
            assert repo.target_model(repo.get_target(ROOT)).staff_emails == [f"ana@{ROOT}"]


class TestPersistence:
    async def test_second_scan_diffs_against_the_first(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        present = {"value": True}

        async def behaviour(self: Any, target: Any, ctx: Any) -> ModuleResult:
            findings = []
            if present["value"]:
                findings.append(
                    self.finding("dns.caa.missing", AssetType.DOMAIN, ROOT, "no CAA record")
                )
            return self.result(findings=findings)

        modules["m"] = make_module("m", behaviour=behaviour)
        _, first = await scan(database, settings)
        assert first.baseline and len(first.new) == 1

        _, second = await scan(database, settings)
        assert not second.baseline and not second.has_changes and second.unchanged == 1

        present["value"] = False
        _, third = await scan(database, settings)
        assert len(third.resolved) == 1

        present["value"] = True
        await scan(database, settings)
        with database.session() as session:
            repo = TenantRepo.local(session)
            from sqlalchemy import select

            from parapet.storage.tables import FindingEvent, FindingRow

            events = [
                e.event
                for e in session.scalars(select(FindingEvent).order_by(FindingEvent.created_at))
            ]
            assert events == ["new", "resolved", "reopened"]
            [row] = session.scalars(select(FindingRow))
            assert row.status == "open" and row.resolved_at is None
            assert len(repo.list_scans(repo.get_target(ROOT).id, status="done")) == 4

    async def test_snapshot_round_trip(self, database: Any, settings: Any, modules: Any) -> None:
        async def behaviour(self: Any, target: Any, ctx: Any) -> ModuleResult:
            return self.result(
                assets=[self.asset(AssetType.SUBDOMAIN, f"app.{ROOT}", state={"resolves": True})],
                findings=[
                    self.finding(
                        "breach.account",
                        AssetType.EMAIL_ADDRESS,
                        f"ana@{ROOT}",
                        "in a breach",
                        sensitivity=Sensitivity.PERSONAL,
                        evidence={"breach": "ExampleCo 2024"},
                    )
                ],
            )

        modules["m"] = make_module("m", behaviour=behaviour)
        snapshot, _ = await scan(database, settings)
        with database.session() as session:
            repo = TenantRepo.local(session)
            stored = repo.load_snapshot(repo.get_scan(snapshot.scan_id))
        assert stored.findings[0].model_dump() == snapshot.findings[0].model_dump()
        assert stored.assets[0].fingerprint == snapshot.assets[0].fingerprint
        assert stored.assets[0].facets == snapshot.assets[0].facets

    @sqlite_only
    async def test_findings_are_encrypted_on_disk(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        async def behaviour(self: Any, target: Any, ctx: Any) -> ModuleResult:
            return self.result(
                findings=[
                    self.finding(
                        "breach.account",
                        AssetType.EMAIL_ADDRESS,
                        f"ana@{ROOT}",
                        f"ana@{ROOT} is in a breach",
                        sensitivity=Sensitivity.PERSONAL,
                        evidence={"breach": "ExampleCo 2024"},
                    )
                ]
            )

        modules["m"] = make_module("m", behaviour=behaviour)
        await scan(database, settings)
        database.engine.dispose()
        raw = sqlite3.connect(settings.data_dir / "parapet.db")
        raw.execute("PRAGMA wal_checkpoint(FULL)")
        dump = "\n".join(raw.iterdump())
        raw.close()
        assert f"ana@{ROOT}" not in dump
        assert "ExampleCo" not in dump
        for name in ("parapet.db", "parapet.db-wal"):
            path = settings.data_dir / name
            if path.exists():
                assert b"ana@" not in path.read_bytes()


class TestTenantIsolation:
    def test_one_tenant_cannot_see_another(self, database: Any) -> None:
        with database.session() as session:
            a_id, b_id = uuid.uuid4(), uuid.uuid4()
            session.add_all([Tenant(id=a_id, name="a"), Tenant(id=b_id, name="b")])
            session.flush()
            a, b = TenantRepo(session, a_id), TenantRepo(session, b_id)
            row = a.upsert_target(TARGET)
            scan_row = a.create_scan(row.id, mode=ScanMode.PASSIVE, authorisation=Authorisation())
            a.create_verification(row.id, "token")
            a.audit("x", actor="a", object_type="target")

            assert b.get_target(ROOT) is None
            assert b.get_target_by_id(row.id) is None
            assert b.list_targets() == []
            assert b.get_scan(scan_row.id) is None
            assert b.list_scans(row.id) == []
            assert b.find_scan(row.id, "latest") is None
            assert b.get_verification(row.id) is None
            assert b.latest_ack(row.id) is None
            assert b.list_audit() == []
            assert b.remove_target(ROOT) is False
            assert a.get_target(ROOT) is not None

    def test_same_domain_in_two_tenants_stays_separate(self, database: Any) -> None:
        with database.session() as session:
            a_id, b_id = uuid.uuid4(), uuid.uuid4()
            session.add_all([Tenant(id=a_id, name="a"), Tenant(id=b_id, name="b")])
            session.flush()
            ra = TenantRepo(session, a_id).upsert_target(TARGET)
            rb = TenantRepo(session, b_id).upsert_target(Target(root_domain=ROOT))
            assert ra.id != rb.id
            assert TenantRepo.target_model(rb).staff_emails == []


class TestCrypto:
    def test_rotation_keeps_old_data_readable_and_fingerprints_stable(self) -> None:
        old, new = new_key(), new_key()
        before = DataKeys([old])
        token = before.encrypt(b"secret")
        after = DataKeys([new, old])
        assert after.decrypt(token) == b"secret"
        assert after.blind_key == before.blind_key
        assert DataKeys([new]).decrypt(after.rotate(token)) == b"secret"

    def test_wrong_key_fails_clearly(self) -> None:
        token = DataKeys([new_key()]).encrypt(b"secret")
        with pytest.raises(ConfigError):
            DataKeys([new_key()]).decrypt(token)

    def test_invalid_key_is_rejected(self) -> None:
        with pytest.raises(ConfigError):
            DataKeys(["not-a-key"])
        with pytest.raises(ConfigError):
            DataKeys([])

    def test_key_is_required_outside_development(self, settings: Any) -> None:
        from parapet.storage.crypto import load_keys

        with pytest.raises(ConfigError):
            load_keys(settings.model_copy(update={"env": "production"}))

    @sqlite_only
    def test_local_key_file_is_private(self, database: Any, settings: Any) -> None:
        key_file = settings.data_dir / "data.key"
        assert key_file.stat().st_mode & 0o777 == 0o600
        assert (settings.data_dir / "parapet.db").stat().st_mode & 0o777 == 0o600


class TestCacheAndRetention:
    def test_cache_expires(self, database: Any) -> None:
        with database.session() as session:
            cache = Cache(session)
            cache.set("ns", "k", "v", timedelta(hours=1))
            cache.set("ns", "old", "v", timedelta(seconds=-1))
            assert cache.get("ns", "k") == "v"
            assert cache.get("ns", "old") is None
            assert cache.get("other", "k") is None
            assert cache.purge_expired() == 1

    async def test_purge_keeps_the_latest_scan(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        modules["m"] = make_module("m")
        for _ in range(3):
            await scan(database, settings)
        with database.session() as session:
            repo = TenantRepo.local(session)
            removed = repo.purge_scans_before(utcnow() + timedelta(days=1))
            assert removed == 2
            remaining = repo.list_scans(repo.get_target(ROOT).id)
            assert len(remaining) == 1
            assert repo.load_snapshot(remaining[0]).modules[0].module == "m"


class TestRetentionOfFindings:
    async def test_resolved_findings_and_expired_statements_are_purged(
        self, database: Any, settings: Any, modules: Any
    ) -> None:
        from sqlalchemy import select

        from parapet.safety.authorisation import make_ack
        from parapet.storage.tables import AuthorisationAck, FindingRow

        present = {"value": True}

        async def behaviour(self: Any, target: Any, ctx: Any) -> ModuleResult:
            findings = []
            if present["value"]:
                findings.append(
                    self.finding(
                        "breach.account",
                        AssetType.EMAIL_ADDRESS,
                        f"ana@{ROOT}",
                        "in a breach",
                        sensitivity=Sensitivity.PERSONAL,
                    )
                )
            findings.append(self.finding("dns.caa.missing", AssetType.DOMAIN, ROOT, "no CAA"))
            return self.result(findings=findings)

        modules["m"] = make_module("m", behaviour=behaviour)
        await scan(database, settings)
        present["value"] = False
        await scan(database, settings)

        with database.session() as session:
            repo = TenantRepo.local(session)
            row = repo.get_target(ROOT)
            expired = make_ack(row, full_name="A", organisation="B", role="C", keys=database.keys)
            expired.expires_at = utcnow() - timedelta(days=200)
            repo.add_ack(expired)
            repo.add_ack(
                make_ack(row, full_name="A", organisation="B", role="C", keys=database.keys)
            )

            statuses = sorted(f.status for f in session.scalars(select(FindingRow)))
            assert statuses == ["open", "resolved"]

            repo.purge_scans_before(utcnow() - timedelta(days=90))
            assert len(list(session.scalars(select(FindingRow)))) == 2, "too recent to purge"
            assert len(list(session.scalars(select(AuthorisationAck)))) == 1

            repo.purge_scans_before(utcnow() + timedelta(seconds=1))
            [kept] = session.scalars(select(FindingRow))
            assert kept.status == "open" and kept.kind == "dns.caa.missing"
