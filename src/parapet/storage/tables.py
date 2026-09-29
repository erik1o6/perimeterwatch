"""Database schema. Every table except `tenants` and `http_cache` carries tenant_id."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from parapet.core.models import utcnow
from parapet.storage.types import EncryptedJSON, EncryptedStr

JsonCol = JSON().with_variant(JSONB(), "postgresql")
TZDateTime = DateTime(timezone=True)

LOCAL_TENANT_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


def _tenant_fk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class TargetRow(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("tenant_id", "root_domain"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    root_domain: Mapped[str] = mapped_column(String(253))
    # Target settings without staff emails, which are personal data.
    config: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    staff_emails: Mapped[list[str] | None] = mapped_column(EncryptedJSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    next_scan_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    # Hours between scheduled scans. None means scans are only run on request.
    scan_interval_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DomainVerification(Base):
    __tablename__ = "domain_verifications"
    __table_args__ = (UniqueConstraint("tenant_id", "target_id"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    token: Mapped[str] = mapped_column(EncryptedStr)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_result: Mapped[str | None] = mapped_column(String(200), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)


class AuthorisationAck(Base):
    __tablename__ = "authorisation_acks"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    full_name: Mapped[str] = mapped_column(EncryptedStr)
    organisation: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(200))
    statement: Mapped[str] = mapped_column(Text)
    os_user: Mapped[str] = mapped_column(String(200))
    hostname: Mapped[str] = mapped_column(String(253))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)
    mac: Mapped[str] = mapped_column(String(64))


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_target_finished", "target_id", "finished_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    mode: Mapped[str] = mapped_column(String(20))
    auth_level: Mapped[str] = mapped_column(String(20), default="none")
    auth_basis: Mapped[str] = mapped_column(Text, default="")
    only_modules: Mapped[list[str] | None] = mapped_column(JsonCol, nullable=True)
    skip_modules: Mapped[list[str] | None] = mapped_column(JsonCol, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(200), default="cli")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class ModuleRun(Base):
    __tablename__ = "module_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    module: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))
    skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[list[str]] = mapped_column(JsonCol, default=list)
    stats: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    started_at: Mapped[datetime] = mapped_column(TZDateTime)
    finished_at: Mapped[datetime] = mapped_column(TZDateTime)


class ScanAsset(Base):
    """Assets as one scan saw them. The per-scan snapshot used for diffing."""

    __tablename__ = "scan_assets"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    state_hash: Mapped[str] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(32))
    key: Mapped[str] = mapped_column(String(512))
    source_module: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    state: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    facets: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)


class ScanFinding(Base):
    """Findings as one scan saw them. Bodies are always encrypted."""

    __tablename__ = "scan_findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    state_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(100))
    module: Mapped[str] = mapped_column(String(64))
    severity: Mapped[int] = mapped_column(Integer)
    sensitivity: Mapped[str] = mapped_column(String(20))
    body: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON)


class FindingRow(Base):
    """Current state of each finding for a target, across scans."""

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("tenant_id", "target_id", "fingerprint"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    state_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(100))
    module: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[int] = mapped_column(Integer)
    sensitivity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_scan_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    body: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON)


class FindingEvent(Base):
    __tablename__ = "finding_events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    event: Mapped[str] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(100))
    severity: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100), index=True)
    object_type: Mapped[str] = mapped_column(String(50))
    object_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    meta: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)


class HttpCache(Base):
    """Responses from slow public sources such as crt.sh. Holds no tenant data."""

    __tablename__ = "http_cache"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, index=True)


# --- hosted service: identity, sessions, alerts ---------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(20), default="owner")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class LoginToken(Base):
    """A sign-in link. Only the hash of the token is stored."""

    __tablename__ = "login_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)
    used_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class WebSession(Base):
    """A signed-in browser. Only the hash of the cookie value is stored."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)


class AlertChannel(Base):
    __tablename__ = "alert_channels"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    kind: Mapped[str] = mapped_column(String(20))  # email | slack | discord | telegram
    label: Mapped[str] = mapped_column(String(100))
    # Webhook addresses and bot tokens are credentials.
    config: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON)
    min_severity: Mapped[int] = mapped_column(Integer, default=2)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    channel_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alert_channels.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    subject: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
