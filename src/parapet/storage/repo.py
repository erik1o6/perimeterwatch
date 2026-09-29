"""The only query path. Every read and write is scoped to one tenant."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from parapet.core.diff import ScanDiff
from parapet.core.models import (
    Asset,
    AuthLevel,
    Authorisation,
    Finding,
    ModuleResult,
    ScanMode,
    ScanSnapshot,
    Target,
    utcnow,
)
from parapet.storage.tables import (
    LOCAL_TENANT_ID,
    AlertChannel,
    AlertDelivery,
    AuditLog,
    AuthorisationAck,
    DomainVerification,
    FindingEvent,
    FindingRow,
    HttpCache,
    ModuleRun,
    Scan,
    ScanAsset,
    ScanFinding,
    TargetRow,
    Tenant,
)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes. They were stored as UTC."""
    from datetime import UTC

    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class TenantRepo:
    def __init__(self, session: Session, tenant_id: uuid.UUID) -> None:
        self.session = session
        self.tenant_id = tenant_id

    # -- tenants ------------------------------------------------------------

    @classmethod
    def local(cls, session: Session) -> TenantRepo:
        """The single tenant used by the command line."""
        if session.get(Tenant, LOCAL_TENANT_ID) is None:
            session.add(Tenant(id=LOCAL_TENANT_ID, name="local"))
            session.flush()
        return cls(session, LOCAL_TENANT_ID)

    # -- targets ------------------------------------------------------------

    def get_target(self, root_domain: str) -> TargetRow | None:
        return self.session.scalars(
            select(TargetRow).where(
                TargetRow.tenant_id == self.tenant_id, TargetRow.root_domain == root_domain
            )
        ).first()

    def get_target_by_id(self, target_id: uuid.UUID) -> TargetRow | None:
        return self.session.scalars(
            select(TargetRow).where(
                TargetRow.tenant_id == self.tenant_id, TargetRow.id == target_id
            )
        ).first()

    def list_targets(self) -> list[TargetRow]:
        return list(
            self.session.scalars(
                select(TargetRow)
                .where(TargetRow.tenant_id == self.tenant_id)
                .order_by(TargetRow.root_domain)
            )
        )

    def upsert_target(self, target: Target) -> TargetRow:
        row = self.get_target(target.root_domain)
        config = target.model_dump(mode="json", exclude={"staff_emails"})
        if row is None:
            row = TargetRow(tenant_id=self.tenant_id, root_domain=target.root_domain, config=config)
            self.session.add(row)
        else:
            row.config = config
        row.staff_emails = target.staff_emails or None
        self.session.flush()
        return row

    def remove_target(self, root_domain: str) -> bool:
        row = self.get_target(root_domain)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    @staticmethod
    def target_model(row: TargetRow) -> Target:
        data = dict(row.config or {})
        data["root_domain"] = row.root_domain
        data["staff_emails"] = row.staff_emails or []
        return Target.model_validate(data)

    # -- authorisation ------------------------------------------------------

    def get_verification(self, target_id: uuid.UUID) -> DomainVerification | None:
        return self.session.scalars(
            select(DomainVerification).where(
                DomainVerification.tenant_id == self.tenant_id,
                DomainVerification.target_id == target_id,
            )
        ).first()

    def create_verification(self, target_id: uuid.UUID, token: str) -> DomainVerification:
        existing = self.get_verification(target_id)
        if existing is not None:
            self.session.delete(existing)
            self.session.flush()
        row = DomainVerification(tenant_id=self.tenant_id, target_id=target_id, token=token)
        self.session.add(row)
        self.session.flush()
        return row

    def add_ack(self, ack: AuthorisationAck) -> AuthorisationAck:
        ack.tenant_id = self.tenant_id
        self.session.add(ack)
        self.session.flush()
        return ack

    def latest_ack(self, target_id: uuid.UUID) -> AuthorisationAck | None:
        return self.session.scalars(
            select(AuthorisationAck)
            .where(
                AuthorisationAck.tenant_id == self.tenant_id,
                AuthorisationAck.target_id == target_id,
            )
            .order_by(AuthorisationAck.created_at.desc())
        ).first()

    # -- scans --------------------------------------------------------------

    def create_scan(
        self,
        target_id: uuid.UUID,
        *,
        mode: ScanMode,
        authorisation: Authorisation,
        requested_by: str = "cli",
        status: str = "running",
        scan_id: uuid.UUID | None = None,
        only: set[str] | None = None,
        skip: set[str] | None = None,
    ) -> Scan:
        now = utcnow()
        scan = Scan(
            id=scan_id or uuid.uuid4(),
            tenant_id=self.tenant_id,
            target_id=target_id,
            status=status,
            mode=mode.value,
            auth_level=authorisation.level.value,
            auth_basis=authorisation.basis,
            requested_by=requested_by,
            only_modules=sorted(only) if only else None,
            skip_modules=sorted(skip) if skip else None,
            started_at=now if status == "running" else None,
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def get_scan(self, scan_id: uuid.UUID) -> Scan | None:
        return self.session.scalars(
            select(Scan).where(Scan.tenant_id == self.tenant_id, Scan.id == scan_id)
        ).first()

    def find_scan(self, target_id: uuid.UUID, ref: str) -> Scan | None:
        """Look up a finished scan by 'latest', 'previous', full id, or id prefix."""
        scans = self.list_scans(target_id, status="done")
        if ref == "latest":
            return scans[0] if scans else None
        if ref == "previous":
            return scans[1] if len(scans) > 1 else None
        matches = [s for s in scans if str(s.id).startswith(ref.lower())]
        return matches[0] if len(matches) == 1 else None

    def list_scans(
        self, target_id: uuid.UUID, *, status: str | None = None, limit: int = 100
    ) -> list[Scan]:
        query = select(Scan).where(Scan.tenant_id == self.tenant_id, Scan.target_id == target_id)
        if status:
            query = query.where(Scan.status == status)
        query = query.order_by(Scan.created_at.desc()).limit(limit)
        return list(self.session.scalars(query))

    def previous_scan(self, scan: Scan) -> Scan | None:
        return self.session.scalars(
            select(Scan)
            .where(
                Scan.tenant_id == self.tenant_id,
                Scan.target_id == scan.target_id,
                Scan.status == "done",
                Scan.id != scan.id,
                Scan.created_at < scan.created_at,
            )
            .order_by(Scan.created_at.desc())
        ).first()

    def save_results(self, scan: Scan, snapshot: ScanSnapshot) -> None:
        for module in snapshot.modules:
            self._save_module(scan, module)
        for asset in snapshot.assets:
            self.session.add(
                ScanAsset(
                    tenant_id=self.tenant_id,
                    scan_id=scan.id,
                    fingerprint=asset.fingerprint,
                    state_hash=asset.state_hash,
                    type=asset.type.value,
                    key=asset.key,
                    source_module=asset.source_module,
                    attributes=asset.attributes,
                    state=asset.state,
                    facets=asset.facets,
                )
            )
        seen: set[str] = set()
        for finding in snapshot.findings:
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            self.session.add(
                ScanFinding(
                    tenant_id=self.tenant_id,
                    scan_id=scan.id,
                    fingerprint=finding.fingerprint,
                    state_hash=finding.state_hash,
                    kind=finding.kind,
                    module=finding.module,
                    severity=int(finding.severity),
                    sensitivity=finding.sensitivity.value,
                    body=finding.model_dump(mode="json"),
                )
            )
        scan.status = "done"
        scan.finished_at = snapshot.finished_at or utcnow()
        scan.tool_versions = snapshot.tool_versions
        self.session.flush()

    def _save_module(self, scan: Scan, module: ModuleResult) -> None:
        self.session.add(
            ModuleRun(
                tenant_id=self.tenant_id,
                scan_id=scan.id,
                module=module.module,
                status=module.status.value,
                skip_reason=module.skip_reason,
                hint=module.hint,
                notes=module.notes,
                stats=module.stats,
                started_at=module.started_at,
                finished_at=module.finished_at,
            )
        )

    def fail_scan(self, scan: Scan, error: str) -> None:
        scan.status = "failed"
        scan.error = error[:2000]
        scan.finished_at = utcnow()
        self.session.flush()

    def load_snapshot(self, scan: Scan) -> ScanSnapshot:
        target_row = self.get_target_by_id(scan.target_id)
        if target_row is None:
            raise LookupError("Scan has no target.")
        runs = self.session.scalars(
            select(ModuleRun)
            .where(ModuleRun.tenant_id == self.tenant_id, ModuleRun.scan_id == scan.id)
            .order_by(ModuleRun.started_at, ModuleRun.module)
        )
        modules: dict[str, ModuleResult] = {}
        for run in runs:
            modules[run.module] = ModuleResult(
                module=run.module,
                status=run.status,
                skip_reason=run.skip_reason,
                hint=run.hint,
                notes=list(run.notes or []),
                stats=dict(run.stats or {}),
                started_at=_aware(run.started_at) or utcnow(),
                finished_at=_aware(run.finished_at) or utcnow(),
            )
        for row in self.session.scalars(
            select(ScanAsset).where(
                ScanAsset.tenant_id == self.tenant_id, ScanAsset.scan_id == scan.id
            )
        ):
            asset = Asset(
                type=row.type,
                key=row.key,
                attributes=dict(row.attributes or {}),
                state=dict(row.state or {}),
                facets=dict(row.facets or {}),
                source_module=row.source_module,
                fingerprint=row.fingerprint,
                state_hash=row.state_hash,
            )
            if row.source_module in modules:
                modules[row.source_module].assets.append(asset)
        for frow in self.session.scalars(
            select(ScanFinding).where(
                ScanFinding.tenant_id == self.tenant_id, ScanFinding.scan_id == scan.id
            )
        ):
            finding = Finding.model_validate(frow.body)
            if finding.module in modules:
                modules[finding.module].findings.append(finding)
        return ScanSnapshot(
            scan_id=scan.id,
            target=self.target_model(target_row).model_copy(update={"staff_emails": []}),
            mode=ScanMode(scan.mode),
            authorisation=Authorisation(level=AuthLevel(scan.auth_level), basis=scan.auth_basis),
            started_at=_aware(scan.started_at) or _aware(scan.created_at) or utcnow(),
            finished_at=_aware(scan.finished_at),
            modules=list(modules.values()),
            tool_versions=dict(scan.tool_versions or {}),
        )

    # -- current finding state ------------------------------------------------

    def apply_diff(self, scan: Scan, snapshot: ScanSnapshot, diff: ScanDiff) -> None:
        """Update the per-target finding state and record events."""
        now = snapshot.finished_at or utcnow()
        existing = {
            row.fingerprint: row
            for row in self.session.scalars(
                select(FindingRow).where(
                    FindingRow.tenant_id == self.tenant_id,
                    FindingRow.target_id == scan.target_id,
                )
            )
        }
        changed = {c.after.fingerprint for c in diff.changed}
        seen: set[str] = set()
        for finding in snapshot.findings:
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            row = existing.get(finding.fingerprint)
            if row is None:
                self.session.add(
                    FindingRow(
                        tenant_id=self.tenant_id,
                        target_id=scan.target_id,
                        fingerprint=finding.fingerprint,
                        state_hash=finding.state_hash,
                        kind=finding.kind,
                        module=finding.module,
                        category=finding.category.value,
                        severity=int(finding.severity),
                        sensitivity=finding.sensitivity.value,
                        status="open",
                        first_seen=now,
                        last_seen=now,
                        last_scan_id=scan.id,
                        body=finding.model_dump(mode="json"),
                    )
                )
                self._event(scan, finding, "new")
                continue
            if row.status == "resolved":
                self._event(scan, finding, "reopened")
                row.resolved_at = None
            elif finding.fingerprint in changed:
                self._event(scan, finding, "changed")
            if row.status != "accepted":
                row.status = "open"
            row.state_hash = finding.state_hash
            row.severity = int(finding.severity)
            row.last_seen = now
            row.last_scan_id = scan.id
            row.body = finding.model_dump(mode="json")
        for finding in diff.resolved:
            row = existing.get(finding.fingerprint)
            if row is not None and row.status != "resolved":
                row.status = "resolved"
                row.resolved_at = now
                self._event(scan, finding, "resolved")
        for finding in diff.stale:
            row = existing.get(finding.fingerprint)
            if row is not None and row.status == "open":
                row.status = "stale"
        self.session.flush()

    def _event(self, scan: Scan, finding: Finding, event: str) -> None:
        self.session.add(
            FindingEvent(
                tenant_id=self.tenant_id,
                target_id=scan.target_id,
                scan_id=scan.id,
                fingerprint=finding.fingerprint,
                event=event,
                kind=finding.kind,
                severity=int(finding.severity),
            )
        )

    # -- findings, as they stand now ---------------------------------------------

    def list_findings(
        self, target_id: uuid.UUID, statuses: tuple[str, ...] = ("open", "stale")
    ) -> list[FindingRow]:
        return list(
            self.session.scalars(
                select(FindingRow)
                .where(
                    FindingRow.tenant_id == self.tenant_id,
                    FindingRow.target_id == target_id,
                    FindingRow.status.in_(statuses),
                )
                .order_by(FindingRow.severity.desc(), FindingRow.kind, FindingRow.first_seen)
            )
        )

    def get_finding(self, finding_id: uuid.UUID) -> FindingRow | None:
        return self.session.scalars(
            select(FindingRow).where(
                FindingRow.tenant_id == self.tenant_id, FindingRow.id == finding_id
            )
        ).first()

    # -- alert channels ----------------------------------------------------------

    def list_channels(self) -> list[AlertChannel]:
        return list(
            self.session.scalars(
                select(AlertChannel)
                .where(AlertChannel.tenant_id == self.tenant_id)
                .order_by(AlertChannel.created_at)
            )
        )

    def get_channel(self, channel_id: uuid.UUID) -> AlertChannel | None:
        return self.session.scalars(
            select(AlertChannel).where(
                AlertChannel.tenant_id == self.tenant_id, AlertChannel.id == channel_id
            )
        ).first()

    def add_channel(
        self, kind: str, label: str, config: dict[str, Any], min_severity: int
    ) -> AlertChannel:
        channel = AlertChannel(
            tenant_id=self.tenant_id,
            kind=kind,
            label=label,
            config=config,
            min_severity=min_severity,
        )
        self.session.add(channel)
        self.session.flush()
        return channel

    def remove_channel(self, channel_id: uuid.UUID) -> bool:
        channel = self.get_channel(channel_id)
        if channel is None:
            return False
        self.session.delete(channel)
        self.session.flush()
        return True

    def list_deliveries(self, limit: int = 20) -> list[AlertDelivery]:
        return list(
            self.session.scalars(
                select(AlertDelivery)
                .where(AlertDelivery.tenant_id == self.tenant_id)
                .order_by(AlertDelivery.created_at.desc())
                .limit(limit)
            )
        )

    # -- audit ----------------------------------------------------------------

    def audit(
        self,
        action: str,
        *,
        actor: str,
        object_type: str,
        object_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            AuditLog(
                tenant_id=self.tenant_id,
                actor=actor,
                action=action,
                object_type=object_type,
                object_id=object_id,
                ip=ip,
                user_agent=(user_agent or "")[:400] or None,
                meta=meta or {},
            )
        )
        self.session.flush()

    def list_audit(self, limit: int = 200) -> list[AuditLog]:
        return list(
            self.session.scalars(
                select(AuditLog)
                .where(AuditLog.tenant_id == self.tenant_id)
                .order_by(AuditLog.created_at.desc())
                .limit(limit)
            )
        )

    # -- retention ------------------------------------------------------------

    def purge_scans_before(self, cutoff: datetime) -> int:
        """Delete scans older than the cutoff, always keeping each target's latest."""
        removed = 0
        for target in self.list_targets():
            scans = self.list_scans(target.id, limit=10_000)
            keep = next((s.id for s in scans if s.status == "done"), None)
            for scan in scans:
                created = _aware(scan.created_at)
                if scan.id == keep or created is None or created >= cutoff:
                    continue
                self.session.delete(scan)
                removed += 1
        # Findings that were resolved before the cutoff, and statements of
        # authority that ran out before it, have no further use.
        for row in self.session.scalars(
            select(FindingRow).where(
                FindingRow.tenant_id == self.tenant_id,
                FindingRow.status == "resolved",
                FindingRow.resolved_at < cutoff,
            )
        ):
            self.session.delete(row)
        for ack in self.session.scalars(
            select(AuthorisationAck).where(
                AuthorisationAck.tenant_id == self.tenant_id, AuthorisationAck.expires_at < cutoff
            )
        ):
            self.session.delete(ack)
        self.session.flush()
        return removed


class Cache:
    """Small key-value cache for slow public sources. Shared, holds no tenant data."""

    def __init__(self, session: Session) -> None:
        self.session = session

    @staticmethod
    def _key(namespace: str, key: str) -> str:
        return hashlib.sha256(f"{namespace}\x00{key}".encode()).hexdigest()

    def get(self, namespace: str, key: str) -> str | None:
        row = self.session.get(HttpCache, self._key(namespace, key))
        if row is None:
            return None
        expires = _aware(row.expires_at)
        if expires is None or expires <= utcnow():
            return None
        return row.value

    def set(self, namespace: str, key: str, value: str, ttl: timedelta) -> None:
        hashed = self._key(namespace, key)
        row = self.session.get(HttpCache, hashed)
        if row is None:
            self.session.add(HttpCache(key=hashed, value=value, expires_at=utcnow() + ttl))
        else:
            row.value = value
            row.expires_at = utcnow() + ttl
        self.session.flush()

    def purge_expired(self) -> int:
        result = self.session.execute(delete(HttpCache).where(HttpCache.expires_at <= utcnow()))
        return int(result.rowcount or 0)  # type: ignore[attr-defined]
