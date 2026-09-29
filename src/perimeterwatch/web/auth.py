"""Sign-in by emailed link. No passwords exist anywhere in the service.

Tokens and session cookies are random values. Only their hashes are stored, so
a copy of the database does not let anyone sign in.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from perimeterwatch.config import Settings
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import utcnow
from perimeterwatch.safety.domains import validate_email
from perimeterwatch.storage.repo import _aware
from perimeterwatch.storage.tables import (
    AuditLog,
    LoginToken,
    Membership,
    Tenant,
    User,
    WebSession,
)

LINK_VALID_FOR = timedelta(minutes=15)
SESSION_IDLE = timedelta(hours=12)
SESSION_MAX = timedelta(days=7)
LINKS_PER_EMAIL_PER_HOUR = 5
LINKS_PER_IP_PER_HOUR = 20


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def normalise_email(raw: str) -> str:
    return validate_email(raw)


@dataclass(frozen=True)
class SignedIn:
    cookie: str
    session: WebSession
    user: User
    first_login: bool


def request_link(
    db: Session, settings: Settings, raw_email: str, ip: str | None
) -> tuple[str, str] | None:
    """Create a sign-in link. Returns (email, token), or None if nothing should be sent.

    The caller shows the same message either way, so the page does not reveal
    which addresses have accounts or when a limit was reached.
    """
    try:
        email = normalise_email(raw_email)
    except ValidationError:
        return None
    since = utcnow() - timedelta(hours=1)
    by_email = db.scalar(
        select(func.count())
        .select_from(LoginToken)
        .where(LoginToken.email == email, LoginToken.created_at >= since)
    )
    if (by_email or 0) >= LINKS_PER_EMAIL_PER_HOUR:
        return None
    if ip:
        by_ip = db.scalar(
            select(func.count())
            .select_from(LoginToken)
            .where(LoginToken.ip == ip, LoginToken.created_at >= since)
        )
        if (by_ip or 0) >= LINKS_PER_IP_PER_HOUR:
            return None
    known = db.scalar(select(User).where(User.email == email))
    if known is None and not settings.signup_open:
        return None
    token = secrets.token_urlsafe(32)
    db.add(
        LoginToken(
            email=email,
            token_hash=hash_token(token),
            expires_at=utcnow() + LINK_VALID_FOR,
            ip=ip,
        )
    )
    db.flush()
    return email, token


def link_is_usable(db: Session, raw_token: str) -> bool:
    row = db.scalar(select(LoginToken).where(LoginToken.token_hash == hash_token(raw_token)))
    expires = _aware(row.expires_at) if row else None
    return bool(row and row.used_at is None and expires and expires > utcnow())


def sign_in(db: Session, raw_token: str, ip: str | None, user_agent: str | None) -> SignedIn | None:
    """Exchange a sign-in link for a session. A link works once."""
    row = db.scalar(
        select(LoginToken).where(LoginToken.token_hash == hash_token(raw_token)).with_for_update()
    )
    now = utcnow()
    expires = _aware(row.expires_at) if row else None
    if row is None or row.used_at is not None or expires is None or expires <= now:
        return None
    row.used_at = now

    user = db.scalar(select(User).where(User.email == row.email))
    first = user is None
    if user is None:
        user = User(email=row.email)
        db.add(user)
        db.flush()
    user.last_login_at = now

    membership = db.scalar(
        select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at)
    )
    if membership is None:
        tenant = Tenant(id=uuid.uuid4(), name=row.email.split("@")[1])
        db.add(tenant)
        db.flush()
        membership = Membership(tenant_id=tenant.id, user_id=user.id, role="owner")
        db.add(membership)
        db.flush()

    cookie = secrets.token_urlsafe(32)
    session = WebSession(
        tenant_id=membership.tenant_id,
        user_id=user.id,
        token_hash=hash_token(cookie),
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now + SESSION_MAX,
        ip=ip,
        user_agent=(user_agent or "")[:400] or None,
    )
    db.add(session)
    db.add(
        AuditLog(
            tenant_id=membership.tenant_id,
            actor=user.email,
            action="auth.signed_in",
            object_type="user",
            object_id=str(user.id),
            ip=ip,
            user_agent=(user_agent or "")[:400] or None,
            meta={"first_login": first},
        )
    )
    db.flush()
    return SignedIn(cookie=cookie, session=session, user=user, first_login=first)


def load_session(db: Session, cookie: str | None) -> tuple[WebSession, User, Membership] | None:
    if not cookie or len(cookie) > 200:
        return None
    session = db.scalar(select(WebSession).where(WebSession.token_hash == hash_token(cookie)))
    if session is None:
        return None
    now = utcnow()
    expires = _aware(session.expires_at)
    seen = _aware(session.last_seen_at)
    if expires is None or seen is None or expires <= now or now - seen > SESSION_IDLE:
        db.delete(session)
        db.flush()
        return None
    user = db.get(User, session.user_id)
    # Membership is re-checked on every request, so removing someone takes effect at once.
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == session.user_id, Membership.tenant_id == session.tenant_id
        )
    )
    if user is None or membership is None:
        db.delete(session)
        db.flush()
        return None
    if now - seen > timedelta(minutes=1):
        session.last_seen_at = now
    return session, user, membership


def sign_out(db: Session, session: WebSession) -> None:
    db.delete(session)
    db.flush()


def purge_expired(db: Session) -> None:
    now = utcnow()
    for token in db.scalars(
        select(LoginToken).where(LoginToken.expires_at < now - timedelta(days=1))
    ):
        db.delete(token)
    for session in db.scalars(select(WebSession).where(WebSession.expires_at < now)):
        db.delete(session)
    db.flush()
