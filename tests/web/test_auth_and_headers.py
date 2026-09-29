from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from parapet.core.models import utcnow
from parapet.storage.tables import LoginToken, User, WebSession
from parapet.web import auth
from tests.conftest import ROOT
from tests.web.conftest import Browser


class TestSignIn:
    def test_link_signs_in_once(self, browser: Any, outbox: list[dict[str, str]]) -> None:
        b: Browser = browser()
        assert b.get("/targets").status_code == 303, "signed out: sent to the sign-in page"
        token = b.request_link()
        assert token and outbox[-1]["to"] == f"ana@{ROOT}"
        assert "http://testserver/auth/" in outbox[-1]["body"]

        b.get(f"/auth/{token}")
        assert b.post(f"/auth/{token}").status_code == 303
        assert b.get("/targets").status_code == 200

        other: Browser = browser()
        assert other.get(f"/auth/{token}").status_code == 400
        other.get("/login")
        assert other.post(f"/auth/{token}").status_code == 400
        assert other.get("/targets").status_code == 303

    def test_opening_the_link_does_not_use_it_up(self, browser: Any) -> None:
        # Mail scanners fetch links in messages before the person sees them.
        b: Browser = browser()
        token = b.request_link()
        for _ in range(3):
            assert b.client.get(f"/auth/{token}").status_code == 200
        assert b.post(f"/auth/{token}").status_code == 303

    def test_expired_link(self, browser: Any, database: Any) -> None:
        b: Browser = browser()
        token = b.request_link()
        with database.session() as db:
            row = db.scalars(select(LoginToken)).one()
            row.expires_at = utcnow() - timedelta(seconds=1)
        assert b.get(f"/auth/{token}").status_code == 400
        b.get("/login")
        assert b.post(f"/auth/{token}").status_code == 400

    @pytest.mark.parametrize("token", ["nope", "a" * 43, "../../etc/passwd", "x" * 500])
    def test_made_up_links(self, browser: Any, token: str) -> None:
        b: Browser = browser()
        b.get("/login")
        assert b.client.get(f"/auth/{token}").status_code in (400, 404)
        assert b.post(f"/auth/{token}").status_code in (400, 404)

    def test_response_does_not_reveal_who_has_an_account(
        self, browser: Any, outbox: list[dict[str, str]], alice: Browser
    ) -> None:
        b: Browser = browser()
        b.get("/login")
        known = b.post("/login", {"email": alice.email})
        unknown = b.post("/login", {"email": "nobody@nowhere-at-all.xyz"})
        invalid = b.post("/login", {"email": "not an address"})
        assert known.status_code == unknown.status_code == invalid.status_code == 200
        strip = lambda r: re.sub(r'value="[^"]+"', "", r.text)  # noqa: E731
        assert strip(known) == strip(unknown) == strip(invalid)

    def test_link_requests_are_limited(self, browser: Any, outbox: list[dict[str, str]]) -> None:
        b: Browser = browser()
        sent = [b.request_link() for _ in range(auth.LINKS_PER_EMAIL_PER_HOUR + 3)]
        assert sum(1 for t in sent if t) == auth.LINKS_PER_EMAIL_PER_HOUR

    def test_closed_signup(self, browser: Any, settings: Any, alice: Browser) -> None:
        settings.signup_open = False
        assert browser("stranger@elsewhere.xyz").request_link() is None
        assert browser(alice.email).request_link(), "existing accounts can still sign in"

    def test_only_hashes_are_stored(self, alice: Browser, database: Any) -> None:
        cookie = alice.client.cookies.get("parapet_session")
        assert cookie
        with database.session() as db:
            session = db.scalars(select(WebSession)).one()
            token = db.scalars(select(LoginToken)).one()
            assert cookie not in (session.token_hash, session.csrf_token)
            assert session.token_hash == auth.hash_token(cookie)
            assert len(token.token_hash) == 64

    def test_email_is_normalised(self, browser: Any, database: Any) -> None:
        browser(f"  Ana@{ROOT.upper()} ").sign_in()
        browser(f"ana@{ROOT}").sign_in()
        with database.session() as db:
            assert [u.email for u in db.scalars(select(User))] == [f"ana@{ROOT}"]

    def test_sign_out(self, alice: Browser) -> None:
        cookie = alice.client.cookies.get("parapet_session")
        assert alice.post("/logout").status_code == 303
        assert alice.get("/targets").status_code == 303
        # The old cookie is dead on the server, not just removed from the browser.
        alice.client.cookies.set("parapet_session", cookie)
        assert alice.get("/targets").status_code == 303

    def test_idle_session_expires(self, alice: Browser, database: Any) -> None:
        with database.session() as db:
            session = db.scalars(select(WebSession)).one()
            session.last_seen_at = utcnow() - auth.SESSION_IDLE - timedelta(minutes=1)
        assert alice.get("/targets").status_code == 303

    def test_session_has_a_hard_limit(self, alice: Browser, database: Any) -> None:
        with database.session() as db:
            session = db.scalars(select(WebSession)).one()
            session.expires_at = utcnow() - timedelta(seconds=1)
        assert alice.get("/targets").status_code == 303

    def test_removing_membership_ends_access_at_once(self, alice: Browser, database: Any) -> None:
        from parapet.storage.tables import Membership

        with database.session() as db:
            db.delete(db.scalars(select(Membership)).one())
        assert alice.get("/targets").status_code == 303

    @pytest.mark.parametrize("cookie", ["", "x", "a" * 43, "a" * 5000, "' OR 1=1 --"])
    def test_forged_cookies(self, browser: Any, cookie: str) -> None:
        b: Browser = browser()
        b.client.cookies.set("parapet_session", cookie)
        assert b.client.get("/targets").status_code == 303


class TestCsrf:
    def test_posts_need_the_token(self, alice: Browser) -> None:
        for token in ("", "wrong", alice.csrf[:-1] + "x"):
            response = alice.post("/targets", {"domain": ROOT}, csrf=token)
            assert response.status_code == 403
        assert 'href="/targets/' not in alice.get("/targets").text, "nothing was added"

    def test_token_from_another_session_is_refused(self, alice: Browser, mallory: Browser) -> None:
        assert alice.post("/targets", {"domain": ROOT}, csrf=mallory.csrf).status_code == 403

    def test_sign_in_form_needs_the_token(self, browser: Any, outbox: list[dict[str, str]]) -> None:
        b: Browser = browser()
        b.get("/login")
        assert b.post("/login", {"email": b.email}, csrf="forged").status_code == 403
        assert outbox == []

    def test_every_form_carries_the_token(self, alice: Browser) -> None:
        target_id = alice.add_target()
        for path in ("/targets", f"/targets/{target_id}", "/alerts"):
            html = alice.get(path).text
            forms = re.findall(r"<form\b.*?</form>", html, flags=re.S)
            assert forms, path
            for form in forms:
                assert 'name="csrf"' in form, f"{path}: a form has no CSRF field"
                assert 'method="post"' in form


class TestHeaders:
    def test_security_headers(self, alice: Browser) -> None:
        for path in ("/targets", "/login", "/healthz", "/nonexistent"):
            h = alice.client.get(path).headers
            csp = h["content-security-policy"]
            assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp, path
            assert "script-src" not in csp and "unsafe-inline" not in csp, path
            assert h["x-content-type-options"] == "nosniff"
            assert h["referrer-policy"] == "no-referrer"
            assert h["x-frame-options"] == "DENY"
            assert h["cache-control"] == "no-store"

    def test_pages_contain_no_script_or_inline_style(self, alice: Browser) -> None:
        target_id = alice.add_target()
        for path in ("/login", "/targets", f"/targets/{target_id}", "/alerts", "/audit"):
            html = alice.get(path).text.lower()
            assert "<script" not in html, path
            assert "<style" not in html and "style=" not in html, path
            assert "javascript:" not in html, path
            assert not re.search(r"\son[a-z]+\s*=", html), path

    def test_session_cookie_flags(self, browser: Any, settings: Any) -> None:
        b: Browser = browser()
        token = b.request_link()
        b.get(f"/auth/{token}")
        cookie = b.post(f"/auth/{token}").headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie

    def test_production_cookies_are_secure_and_host_bound(
        self, settings: Any, database: Any, outbox: Any
    ) -> None:
        from parapet.web.app import create_app

        settings.env = "production"
        b = Browser(create_app(settings, database), outbox, f"ana@{ROOT}")
        b.client.base_url = "https://testserver"
        response = b.client.get("/login")
        assert "max-age=63072000" in response.headers["strict-transport-security"]
        assert "secure" in response.headers["set-cookie"].lower()
        token = b.request_link()
        b.get(f"/auth/{token}")
        cookie = b.post(f"/auth/{token}").headers["set-cookie"]
        assert cookie.startswith("__Host-parapet_session=")
        assert "secure" in cookie.lower() and "domain=" not in cookie.lower()

    def test_oversized_requests_are_refused(self, alice: Browser) -> None:
        response = alice.client.post(
            "/targets", content=b"x" * 10, headers={"content-length": "5000000"}
        )
        assert response.status_code == 413

    def test_errors_reveal_nothing_internal(self, alice: Browser) -> None:
        response = alice.get("/targets/not-a-uuid")
        assert response.status_code == 404
        assert "Traceback" not in response.text and "sqlalchemy" not in response.text.lower()

    def test_api_documentation_is_not_served(self, alice: Browser) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert alice.client.get(path).status_code == 404
