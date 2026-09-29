"""The scan queue. The `scans` table is the queue, so there is nothing else to run.

On Postgres several workers can claim jobs safely (FOR UPDATE SKIP LOCKED).
On SQLite, used for local development, run a single worker.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from parapet.core.models import Authorisation, ScanMode, utcnow
from parapet.storage.repo import TenantRepo, _aware
from parapet.storage.tables import Scan, TargetRow

STALE_AFTER = timedelta(minutes=5)
MAX_ATTEMPTS = 3
ACTIVE_STATES = ("queued", "running")


class QueueError(Exception):
    """The scan cannot be queued. The message is safe to show."""


class JobQueue(Protocol):
    def enqueue_scan(
        self, repo: TenantRepo, target: TargetRow, mode: ScanMode, requested_by: str
    ) -> Scan: ...
    def claim_next(self, db: Session) -> Scan | None: ...
    def heartbeat(self, db: Session, scan_id: uuid.UUID) -> None: ...
    def requeue_stale(self, db: Session) -> int: ...


class TableQueue:
    def __init__(self, min_interval: timedelta = timedelta(0)) -> None:
        self.min_interval = min_interval

    def enqueue_scan(
        self,
        repo: TenantRepo,
        target: TargetRow,
        mode: ScanMode,
        requested_by: str,
        *,
        enforce_interval: bool = True,
    ) -> Scan:
        scans = repo.list_scans(target.id, limit=20)
        if any(s.status in ACTIVE_STATES for s in scans):
            raise QueueError("A scan of this domain is already waiting or running.")
        if enforce_interval and self.min_interval:
            last = next((s for s in scans if s.status == "done"), None)
            finished = _aware(last.finished_at) if last else None
            if finished and utcnow() - finished < self.min_interval:
                wait = self.min_interval - (utcnow() - finished)
                minutes = max(1, int(wait.total_seconds() // 60))
                raise QueueError(
                    f"This domain was scanned recently. The next scan can start in {minutes} minutes."
                )
        # Authorisation is decided when the scan starts, not when it is requested.
        return repo.create_scan(
            target.id,
            mode=mode,
            authorisation=Authorisation(),
            requested_by=requested_by,
            status="queued",
        )

    def claim_next(self, db: Session) -> Scan | None:
        query = select(Scan).where(Scan.status == "queued").order_by(Scan.created_at).limit(1)
        if db.get_bind().dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        scan = db.scalars(query).first()
        if scan is None:
            return None
        now = utcnow()
        scan.status = "running"
        scan.claimed_at = now
        scan.heartbeat_at = now
        scan.started_at = now
        scan.attempts += 1
        db.flush()
        return scan

    def heartbeat(self, db: Session, scan_id: uuid.UUID) -> None:
        scan = db.get(Scan, scan_id)
        if scan is not None and scan.status == "running":
            scan.heartbeat_at = utcnow()
            db.flush()

    def requeue_stale(self, db: Session) -> int:
        """Put back scans whose worker stopped reporting. Give up after a few attempts."""
        cutoff = utcnow() - STALE_AFTER
        moved = 0
        for scan in db.scalars(select(Scan).where(Scan.status == "running")):
            beat = _aware(scan.heartbeat_at)
            if beat is not None and beat > cutoff:
                continue
            if scan.attempts >= MAX_ATTEMPTS:
                scan.status = "failed"
                scan.error = "The scan stopped unexpectedly and was not retried again."
                scan.finished_at = utcnow()
            else:
                scan.status = "queued"
                scan.claimed_at = None
                scan.heartbeat_at = None
            moved += 1
        db.flush()
        return moved
