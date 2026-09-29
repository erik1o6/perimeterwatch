"""The worker: runs queued scans, schedules regular ones, sends alerts, tidies up."""

from __future__ import annotations

import asyncio
import contextlib
import signal
import uuid
from datetime import timedelta

from sqlalchemy import select

from parapet.clients.http import make_client
from parapet.config import Settings
from parapet.core.engine import run_scan
from parapet.core.errors import ParapetError
from parapet.core.models import AuthLevel, ScanMode, utcnow
from parapet.logging import get_logger, scrub
from parapet.safety.authorisation import resolve_authorisation
from parapet.storage.db import Database
from parapet.storage.repo import Cache, TenantRepo, _aware
from parapet.storage.tables import DomainVerification, Scan, TargetRow
from parapet.web import auth as web_auth
from parapet.worker import alerts
from parapet.worker.queue import QueueError, TableQueue

HEARTBEAT_EVERY = 30
REVERIFY_EVERY = timedelta(hours=24)
FAILURES_BEFORE_DOWNGRADE = 3
log = get_logger("worker")


class Worker:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.queue = TableQueue(timedelta(minutes=settings.min_scan_interval_minutes))
        self.stopping = asyncio.Event()
        self._last_housekeeping = utcnow() - timedelta(days=1)

    # -- one scan --------------------------------------------------------------

    async def run_next(self) -> bool:
        """Run one queued scan, if there is one. Returns whether it did."""
        with self.database.session() as db:
            scan = self.queue.claim_next(db)
            if scan is None:
                return False
            scan_id, tenant_id, target_id = scan.id, scan.tenant_id, scan.target_id
            mode = ScanMode(scan.mode)
            only = set(scan.only_modules) if scan.only_modules else None
            skip = set(scan.skip_modules) if scan.skip_modules else None
            requested_by = scan.requested_by

        beat = asyncio.create_task(self._heartbeat(scan_id))
        try:
            await self._run(scan_id, tenant_id, target_id, mode, only, skip, requested_by)
        except ParapetError as exc:
            self._fail(scan_id, tenant_id, str(exc))
        except Exception as exc:
            log.error(
                "scan crashed", scan=str(scan_id)[:8], error=scrub(f"{type(exc).__name__}: {exc}")
            )
            self._fail(scan_id, tenant_id, "The scan stopped because of an internal error.")
        finally:
            beat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await beat
        return True

    async def _run(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target_id: uuid.UUID,
        mode: ScanMode,
        only: set[str] | None,
        skip: set[str] | None,
        requested_by: str,
    ) -> None:
        with self.database.session() as db:
            repo = TenantRepo(db, tenant_id)
            row = repo.get_target_by_id(target_id)
            if row is None:
                raise ParapetError("The domain was removed before the scan started.")
            target = repo.target_model(row)
            authorisation = await resolve_authorisation(repo, row, self.database.keys)
        # The hosted service accepts proof of domain control only. A typed
        # statement is for the command line, where the operator is the user.
        if authorisation.level is AuthLevel.ACKNOWLEDGED:
            authorisation = authorisation.model_copy(update={"level": AuthLevel.NONE})
        # Checked again here: the record may have gone since the scan was requested.
        if (
            self.settings.scan_requires_verification
            and authorisation.level is not AuthLevel.DNS_VERIFIED
        ):
            raise ParapetError(
                "Control of this domain is not proved, so it was not scanned. "
                "Check the DNS record on the domain's page."
            )

        snapshot, diff = await run_scan(
            target,
            settings=self.settings,
            database=self.database,
            tenant_id=tenant_id,
            mode=mode,
            authorisation=authorisation,
            only=only,
            skip=skip,
            requested_by=requested_by,
            scan_id=scan_id,
        )
        with self.database.session() as db:
            alerts.queue_alerts(
                db, self.settings, tenant_id=tenant_id, scan_id=scan_id,
                snapshot=snapshot, diff=diff,
            )  # fmt: skip
            row = TenantRepo(db, tenant_id).get_target_by_id(target_id)
            if row is not None and row.scan_interval_hours:
                row.next_scan_at = utcnow() + timedelta(hours=row.scan_interval_hours)

    def _fail(self, scan_id: uuid.UUID, tenant_id: uuid.UUID, message: str) -> None:
        with self.database.session() as db:
            repo = TenantRepo(db, tenant_id)
            scan = repo.get_scan(scan_id)
            if scan is not None and scan.status != "done":
                repo.fail_scan(scan, message)

    async def _heartbeat(self, scan_id: uuid.UUID) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_EVERY)
            with self.database.session() as db:
                self.queue.heartbeat(db, scan_id)

    # -- scheduled work ----------------------------------------------------------

    def enqueue_due(self) -> int:
        """Queue a scan for every domain whose regular scan is due."""
        queued = 0
        now = utcnow()
        with self.database.session() as db:
            due = db.scalars(
                select(TargetRow).where(
                    TargetRow.scan_interval_hours.is_not(None), TargetRow.next_scan_at <= now
                )
            )
            for row in list(due):
                repo = TenantRepo(db, row.tenant_id)
                verification = repo.get_verification(row.id)
                verified = bool(verification and verification.verified_at)
                if self.settings.scan_requires_verification and not verified:
                    row.next_scan_at = now + timedelta(hours=row.scan_interval_hours or 24)
                    continue
                # Scheduled scans go as deep as the domain's standing allows, short of active.
                mode = (
                    ScanMode.PROBE
                    if verification and verification.verified_at
                    else ScanMode.PASSIVE
                )
                try:
                    self.queue.enqueue_scan(repo, row, mode, "schedule", enforce_interval=False)
                    queued += 1
                except QueueError:
                    pass
                row.next_scan_at = now + timedelta(hours=row.scan_interval_hours or 24)
        return queued

    async def reverify(self) -> None:
        """Re-check proof of domain control daily. Withdraw standing after repeated failures."""
        cutoff = utcnow() - REVERIFY_EVERY
        with self.database.session() as db:
            rows = [
                v
                for v in db.scalars(
                    select(DomainVerification).where(DomainVerification.verified_at.is_not(None))
                )
                if (_aware(v.last_checked_at) or cutoff) <= cutoff
            ]
            for verification in rows:
                repo = TenantRepo(db, verification.tenant_id)
                row = repo.get_target_by_id(verification.target_id)
                if row is None:
                    continue
                await resolve_authorisation(repo, row, self.database.keys)
                if verification.consecutive_failures >= FAILURES_BEFORE_DOWNGRADE:
                    verification.verified_at = None
                    repo.audit(
                        "verification.withdrawn", actor="system", object_type="target",
                        object_id=str(row.id),
                    )  # fmt: skip
                    alerts.queue_notice(
                        db,
                        tenant_id=verification.tenant_id,
                        subject=f"{row.root_domain}: domain verification was lost",
                        body=(
                            f"The DNS record that proves control of {row.root_domain} could not "
                            "be found on three checks in a row.\n\nActive checks and breach "
                            "details are switched off for this domain until the record is back."
                        ),
                    )

    def housekeeping(self) -> None:
        now = utcnow()
        if now - self._last_housekeeping < timedelta(hours=6):
            return
        self._last_housekeeping = now
        cutoff = now - timedelta(days=self.settings.retention_days)
        with self.database.session() as db:
            Cache(db).purge_expired()
            web_auth.purge_expired(db)
            tenants = {t for (t,) in db.execute(select(TargetRow.tenant_id).distinct())}
            for tenant_id in tenants:
                repo = TenantRepo(db, tenant_id)
                removed = repo.purge_scans_before(cutoff)
                repo.audit(
                    "retention.purged", actor="system", object_type="scan",
                    meta={"removed": removed, "older_than_days": self.settings.retention_days},
                )  # fmt: skip

    # -- loop --------------------------------------------------------------------

    async def tick(self) -> bool:
        with self.database.session() as db:
            self.queue.requeue_stale(db)
        self.enqueue_due()
        ran = await self.run_next()
        await self.reverify()
        # Delivery comes last, so notices raised in this round go out in this round.
        async with make_client(self.settings) as client:
            with self.database.session() as db:
                await alerts.deliver_pending(db, self.settings, client)
        self.housekeeping()
        return ran

    async def run_forever(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self.stopping.set)
        log.warning("worker started")
        while not self.stopping.is_set():
            try:
                ran = await self.tick()
            except Exception as exc:
                log.error("worker tick failed", error=scrub(f"{type(exc).__name__}: {exc}"))
                ran = False
            if not ran:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.stopping.wait(), self.settings.worker_poll_seconds)
        log.warning("worker stopped")


_ = Scan
