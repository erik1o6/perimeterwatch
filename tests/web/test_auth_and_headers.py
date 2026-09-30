from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from perimeterwatch.core.models import utcnow
from perimeterwatch.storage.tables import LoginToken, User, WebSession
from perimeterwatch.web import auth
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
        cookie = alice.client.cookies.get("pw_session")
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
        cookie = alice.client.cookies.get("pw_session")
        assert alice.post("/logout").status_code == 303
        assert alice.get("/targets").status_code == 303
        # The old cookie is dead on the server, not just removed from the browser.
        alice.client.cookies.set("pw_session", cookie)
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
        from perimeterwatch.storage.tables import Membership

        with database.session() as db:
            db.delete(db.scalars(select(Membership)).one())
        assert alice.get("/targets").status_code == 303

    @pytest.mark.parametrize("cookie", ["", "x", "a" * 43, "a" * 5000, "' OR 1=1 --"])
    def test_forged_cookies(self, browser: Any, cookie: str) -> None:
        b: Browser = browser()
        b.client.cookies.set("pw_session", cookie)
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
        from perimeterwatch.web.app import create_app

        settings.env = "production"
        b = Browser(create_app(settings, database), outbox, f"ana@{ROOT}")
        b.client.base_url = "https://testserver"
        response = b.client.get("/login")
        assert "max-age=63072000" in response.headers["strict-transport-security"]
        assert "secure" in response.headers["set-cookie"].lower()
        token = b.request_link()
        b.get(f"/auth/{token}")
        cookie = b.post(f"/auth/{token}").headers["set-cookie"]
        assert cookie.startswith("__Host-pw_session=")
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


class TestPublicPage:
    def test_signed_out_visitors_get_the_public_page(self, browser: Any) -> None:
        b: Browser = browser()
        response = b.get("/")
        assert response.status_code == 200
        body = response.text
        assert "What it checks today" in body
        assert "Coming soon" in body
        assert "Breach and malware-log alerts" in body
        assert "Breach exposure" not in body, "the paid check is not listed as available"
        assert 'href="/login"' in body
        assert 'content="index, follow"' in body
        assert "font-src 'self'" in response.headers["Content-Security-Policy"]
        assert "<script" not in body
        assert "style=" not in body, "inline styles are blocked by the policy"

    def test_every_check_but_breach_is_listed_once(self, browser: Any) -> None:
        from perimeterwatch.core.module import all_modules
        from perimeterwatch.web.routes import public_checks

        body = browser().get("/").text
        for module in all_modules().values():
            spec = module.spec
            assert (spec.title in body) == (spec.category.value != "breach"), spec.name
        listed = [title for _, _, items in public_checks() for title, _ in items]
        expected = [m for m in all_modules().values() if m.spec.category.value != "breach"]
        assert len(listed) == len(set(listed)) == len(expected)

    def test_signed_in_visitors_go_to_their_domains(self, alice: Browser) -> None:
        response = alice.get("/")
        assert response.status_code == 303
        assert response.headers["location"] == "/targets"

    def test_scan_sources_and_contacts_are_shown_when_set(self, browser: Any, app: Any) -> None:
        app.state.settings.scan_sources = ["203.0.113.7", "2001:db8::7"]
        app.state.settings.abuse_email = "abuse@acme-protocol.xyz"
        app.state.settings.contact_email = "hello@acme-protocol.xyz"
        body = browser().get("/").text
        assert "203.0.113.7" in body and "2001:db8::7" in body
        assert "mailto:abuse@acme-protocol.xyz" in body
        assert "mailto:hello@acme-protocol.xyz" in body

    def test_other_pages_stay_out_of_search_engines(self, browser: Any) -> None:
        for path in ("/login", "/legal", "/legal/privacy-policy"):
            assert 'content="noindex, nofollow"' in browser().get(path).text, path


class TestLegalPages:
    def test_the_index_lists_every_document(self, browser: Any) -> None:
        from perimeterwatch.web import legal

        body = browser().get("/legal").text
        for document in legal.DOCUMENTS:
            assert f'href="/legal/{document.slug}"' in body
        assert "not yet reviewed by a lawyer" in body

    def test_every_packaged_file_is_a_page_and_carries_the_banner(self) -> None:
        from importlib import resources

        from perimeterwatch.web import legal

        folder = resources.files("perimeterwatch").joinpath("legal")
        files = sorted(item.name for item in folder.iterdir() if item.name.endswith(".md"))
        assert files == sorted(f"{document.slug}.md" for document in legal.DOCUMENTS)
        for name in files:
            first = folder.joinpath(name).read_text("utf-8").splitlines()[0]
            assert legal.BANNER in first, name

    def test_each_document_renders_with_its_open_points_marked(self, browser: Any) -> None:
        from perimeterwatch.web import legal

        b: Browser = browser()
        for document in legal.DOCUMENTS:
            response = b.get(f"/legal/{document.slug}")
            assert response.status_code == 200, document.slug
            body = response.text
            assert f"<h1>{document.title}</h1>" in body
            assert "Not legal advice" in body
            for marker in ("[TO DECIDE", "[TO CONFIRM", "[NOT YET BUILT", "[LAWYER"):
                assert marker not in body, f"{document.slug}: {marker} shown raw"
            relative = re.findall(r'href="(?!https://|mailto:|/|#)[^"]*"', body)
            assert relative == [], f"{document.slug}: links the site cannot follow"

    def test_links_between_documents_point_at_the_site(self) -> None:
        from perimeterwatch.web import legal

        def rewrite(target: str) -> str:
            return legal._HREF_RE.sub(legal._link, f'href="{target}"')

        assert rewrite("privacy-policy.md") == 'href="/legal/privacy-policy"'
        assert rewrite("opt-out.md#3-how") == 'href="/legal/opt-out#3-how"'
        assert rewrite("https://example.org/x") == 'href="https://example.org/x"'
        assert rewrite("mailto:a@b.example") == 'href="mailto:a@b.example"'
        assert rewrite("../../../docs/operations.md") == (
            f'href="{legal.REPOSITORY}/blob/main/docs/operations.md"'
        )
        assert rewrite("../../../../../etc/passwd") == 'href="#"'
        assert rewrite("javascript:alert(1)").startswith(f'href="{legal.REPOSITORY}/blob/main/')

    def test_markers_become_notes(self) -> None:
        from perimeterwatch.web import legal

        html = legal._MARKER_RE.sub(
            legal._marker,
            "<p>Ends on <strong>[TO DECIDE: a date]</strong> and [LAWYER: check].</p>",
        )
        assert "[TO DECIDE" not in html and "[LAWYER" not in html
        assert 'class="open-point op-decide"' in html and "a date" in html
        assert 'class="open-point op-lawyer"' in html and "For legal review" in html

    def test_raw_html_in_a_document_is_not_passed_through(self) -> None:
        from markdown_it import MarkdownIt

        rendered = MarkdownIt("commonmark", {"html": False}).render("<script>alert(1)</script>")
        assert "<script>" not in rendered

    def test_an_unknown_document_is_not_found(self, browser: Any) -> None:
        assert browser().get("/legal/nope").status_code == 404
        assert browser().get("/legal/..%2Fconfig").status_code == 404

    def test_signed_in_people_can_read_them_too(self, alice: Browser) -> None:
        response = alice.get("/legal/terms-of-service")
        assert response.status_code == 200
        assert "Sign out" in response.text


class TestSecurityTxt:
    def test_absent_until_a_contact_is_named(self, browser: Any) -> None:
        assert browser().get("/.well-known/security.txt").status_code == 404

    def test_names_the_contact_and_an_expiry_in_the_future(self, browser: Any, app: Any) -> None:
        from datetime import datetime

        app.state.settings.security_email = "security@acme-protocol.xyz"
        app.state.settings.base_url = "https://watch.acme-protocol.xyz/"
        response = browser().get("/.well-known/security.txt")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        fields = dict(line.split(": ", 1) for line in response.text.strip().splitlines())
        assert fields["Contact"] == "mailto:security@acme-protocol.xyz"
        assert fields["Canonical"] == "https://watch.acme-protocol.xyz/.well-known/security.txt"
        assert fields["Policy"] == "https://watch.acme-protocol.xyz/legal/vulnerability-disclosure"
        expires = datetime.fromisoformat(fields["Expires"].replace("Z", "+00:00"))
        days = (expires - utcnow()).days
        assert 150 <= days <= 190, "RFC 9116 asks for less than a year"
