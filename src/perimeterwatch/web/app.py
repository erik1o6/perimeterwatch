"""The hosted service. Server-rendered pages, no JavaScript."""

from __future__ import annotations

import secrets
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from starlette.exceptions import HTTPException as StarletteHTTPException

from perimeterwatch import __version__
from perimeterwatch.branding import PRODUCT_NAME
from perimeterwatch.config import Settings
from perimeterwatch.report.render_html import _label, _ucfirst, _value, _when
from perimeterwatch.storage.db import Database
from perimeterwatch.web.deps import ANON_CSRF_COOKIE, NotSignedIn

PAGE_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
MAX_BODY_BYTES = 1_200_000


def make_templates() -> Jinja2Templates:
    env = Environment(
        loader=PackageLoader("perimeterwatch.web", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(when=_when, label=_label, value=_value, ucfirst=_ucfirst)
    env.globals.update(product=PRODUCT_NAME, version=__version__)
    return Jinja2Templates(env=env)


def site_context(request: Request) -> dict[str, Any]:
    """What the shared header and footer need on every page."""
    settings: Settings = request.app.state.settings
    return {
        "abuse_email": settings.abuse_email,
        "security_email": settings.security_email,
        "contact_email": settings.contact_email,
        "signup_open": settings.signup_open,
    }


def create_app(settings: Settings, database: Database) -> FastAPI:
    app = FastAPI(
        title=PRODUCT_NAME,
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.templates = make_templates()
    secure = settings.env != "dev"

    static_dir = Path(str(resources.files("perimeterwatch.web").joinpath("static")))
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return Response("Request is too large.", status_code=413)
        # Decided before the page is built, so a first visit gets a working form.
        anon_csrf = request.cookies.get(ANON_CSRF_COOKIE) or secrets.token_urlsafe(32)
        request.state.anon_csrf = anon_csrf
        response: Response = await call_next(request)
        headers = response.headers
        headers.setdefault("Content-Security-Policy", PAGE_CSP)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"
        )
        if not request.url.path.startswith("/static/"):
            headers.setdefault("Cache-Control", "no-store")
        if secure:
            headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        if ANON_CSRF_COOKIE not in request.cookies:
            response.set_cookie(
                ANON_CSRF_COOKIE,
                anon_csrf,
                httponly=True,
                secure=secure,
                samesite="strict",
                max_age=86400,
                path="/",
            )
        return response

    def error_page(request: Request, status: int, message: str) -> HTMLResponse:
        return app.state.templates.TemplateResponse(  # type: ignore[no-any-return]
            request, "error.html",
            {"status": status, "message": message, "who": None,
             "csrf": getattr(request.state, "anon_csrf", ""), **site_context(request)},
            status_code=status,
        )  # fmt: skip

    @app.exception_handler(NotSignedIn)
    async def not_signed_in(request: Request, exc: NotSignedIn) -> Response:
        if request.method == "GET":
            return RedirectResponse("/login", status_code=303)
        return error_page(request, 401, "You are signed out. Sign in and try again.")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        message = str(exc.detail) if exc.status_code != 404 else "That page does not exist."
        return error_page(request, exc.status_code, message)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> Response:
        return error_page(request, 400, "The form was incomplete. Go back and try again.")

    @app.exception_handler(Exception)
    async def crashed(request: Request, exc: Exception) -> Response:
        # Details go to the log. The page says nothing about what went wrong inside.
        from perimeterwatch.logging import get_logger, scrub

        get_logger("web").error(
            "request failed", path=request.url.path, error=scrub(f"{type(exc).__name__}: {exc}")
        )
        return error_page(request, 500, "Something went wrong on our side. Please try again.")

    from perimeterwatch.web.routes import router

    app.include_router(router)
    return app
