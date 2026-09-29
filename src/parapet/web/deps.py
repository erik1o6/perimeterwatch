"""Request-scoped dependencies: database session, signed-in user, tenant, CSRF."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from parapet.config import Settings
from parapet.storage.db import Database
from parapet.storage.repo import TenantRepo
from parapet.storage.tables import Membership, User, WebSession
from parapet.web import auth

ANON_CSRF_COOKIE = "parapet_csrf"


def session_cookie_name(settings: Settings) -> str:
    # The __Host- prefix makes browsers refuse the cookie unless it is Secure,
    # has no Domain, and has Path=/. Plain HTTP in development cannot use it.
    return "parapet_session" if settings.env == "dev" else "__Host-parapet_session"


def get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def get_database(request: Request) -> Database:
    return request.app.state.database  # type: ignore[no-any-return]


def get_db(request: Request) -> Iterator[Session]:
    database: Database = request.app.state.database
    with database.session() as session:
        yield session


def client_ip(request: Request) -> str | None:
    settings: Settings = request.app.state.settings
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # The last entry is the one added by our own proxy.
            return forwarded.split(",")[-1].strip()[:64] or None
    return request.client.host[:64] if request.client else None


class NotSignedIn(Exception):
    pass


@dataclass
class Auth:
    session: WebSession
    user: User
    membership: Membership
    repo: TenantRepo
    ip: str | None
    user_agent: str | None

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.session.tenant_id

    @property
    def csrf(self) -> str:
        return self.session.csrf_token

    @property
    def can_edit(self) -> bool:
        return self.membership.role in ("owner", "member")

    def audit(
        self, action: str, object_type: str, object_id: str | None = None, **meta: object
    ) -> None:
        self.repo.audit(
            action,
            actor=self.user.email,
            object_type=object_type,
            object_id=object_id,
            ip=self.ip,
            user_agent=self.user_agent,
            meta=dict(meta),
        )


def require_auth(request: Request, db: Session = Depends(get_db)) -> Auth:
    settings: Settings = request.app.state.settings
    found = auth.load_session(db, request.cookies.get(session_cookie_name(settings)))
    if found is None:
        raise NotSignedIn
    session, user, membership = found
    # The tenant comes from the session and nowhere else. No route reads it
    # from the address or the form.
    return Auth(
        session=session,
        user=user,
        membership=membership,
        repo=TenantRepo(db, session.tenant_id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


async def require_csrf(request: Request, who: Auth = Depends(require_auth)) -> Auth:
    form = await request.form()
    sent = form.get("csrf")
    if not isinstance(sent, str) or not secrets.compare_digest(sent, who.csrf):
        raise HTTPException(403, "This form has expired. Go back, reload the page and try again.")
    return who


async def require_editor(who: Auth = Depends(require_csrf)) -> Auth:
    if not who.can_edit:
        raise HTTPException(403, "Your account can view this organisation but not change it.")
    return who


async def require_anon_csrf(request: Request) -> None:
    """For forms shown before sign-in: the cookie and the form field must match."""
    form = await request.form()
    sent = form.get("csrf")
    cookie = request.cookies.get(ANON_CSRF_COOKIE)
    if (
        not isinstance(sent, str)
        or not cookie
        or len(cookie) < 20
        or not secrets.compare_digest(sent, cookie)
    ):
        raise HTTPException(403, "This form has expired. Reload the page and try again.")


def parse_uuid(raw: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except ValueError:
        raise HTTPException(404, "Not found.") from None
