"""Website scripts, published packages and repository safeguards.

All HTTP is served by local stand-ins. A request to any host a test did not expect
fails that test.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from parapet.core.fingerprint import finding_state_hash
from parapet.core.models import (
    Asset,
    AssetType,
    Category,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
)
from parapet.modules import frontend, packages, repo_scorecard
from parapet.modules.frontend import Frontend, Origin, parse_page, resolve
from parapet.modules.packages import Packages, valid_npm_name, valid_pypi_name, variants
from parapet.modules.repo_scorecard import RepoScorecard, bucket, failing_checks, repo_parts
from tests.conftest import ROOT, fixture_text
from tests.helpers import resolved

HOST = f"www.{ROOT}"
PUBLIC_IP = "93.184.216.34"
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)

GOOD_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
}


def sha(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def by_kind(result: ModuleResult, kind: str) -> list[Finding]:
    return [f for f in result.findings if f.kind == kind]


# --------------------------------------------------------------------------
# frontend
# --------------------------------------------------------------------------


class Site:
    """Stands in for the organisation's web host. Any other host fails the test."""

    def __init__(self, host: str = HOST, scheme: str = "https") -> None:
        self.host = host
        self.scheme = scheme
        self.paths: dict[str, Any] = {}
        self.requests: list[httpx.Request] = []

    def page(self, html: str, headers: dict[str, str] | None = None) -> Site:
        self.paths["/"] = httpx.Response(
            200, content=html.encode(), headers=headers or {"content-type": "text/html"}
        )
        return self

    def file(self, path: str, body: bytes | str, status: int = 200) -> Site:
        content = body.encode() if isinstance(body, str) else body
        self.paths[path] = httpx.Response(status, content=content)
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.url.host == self.host, f"request left the vetted host: {request.url}"
        assert request.url.scheme in ("http", "https")
        assert request.url.port is None, f"request to an unusual port: {request.url}"
        assert request.method == "GET"
        answer = self.paths.get(request.url.path)
        if answer is None:
            return httpx.Response(404, content=b"not found")
        if callable(answer):
            return answer(request)  # type: ignore[no-any-return]
        return httpx.Response(answer.status_code, content=answer.content, headers=answer.headers)

    @property
    def fetched(self) -> list[str]:
        return [r.url.raw_path.decode() for r in self.requests]


def web_ctx(
    make_ctx: Any,
    handler: Any,
    *,
    hosts: dict[str, list[str]] | None = None,
    web: dict[str, bool] | None = None,
) -> Any:
    """A context in which dns_resolve and http_probe have already run."""
    ctx = make_ctx(mode=ScanMode.PROBE, handler=handler)
    ctx.assets.add(resolved(hosts or {HOST: [PUBLIC_IP]}, root=ROOT))
    ctx.assets.add(
        ModuleResult(
            module="http_probe",
            status=ModuleStatus.OK,
            assets=[
                Asset(
                    type=AssetType.DOMAIN if name == ROOT else AssetType.SUBDOMAIN,
                    key=name,
                    source_module="http_probe",
                    state={"web": True, "https": https},
                )
                for name, https in (web or {HOST: True}).items()
            ],
        )
    )
    return ctx


TARGET = Target(root_domain=ROOT)


async def scan_site(make_ctx: Any, site: Site, **kwargs: Any) -> ModuleResult:
    return await Frontend().run(TARGET, web_ctx(make_ctx, site, **kwargs))


def scripts_state(result: ModuleResult) -> list[dict[str, Any]]:
    [finding] = by_kind(result, "frontend.scripts")
    return finding.state["scripts"]  # type: ignore[no-any-return]


def simple_page(*tags: str) -> str:
    return "<!doctype html><html><head>" + "".join(tags) + "</head><body></body></html>"


class TestFrontendNormal:
    def site(self) -> Site:
        return (
            Site()
            .page(fixture_text("frontend", "page.html"))
            .file("/assets/index-BetUtrcO.js", "console.log('app')")
            .file("/vendor/wallet.js", "console.log('wallet')")
        )

    def test_spec(self) -> None:
        spec = Frontend.spec
        assert spec.name == "frontend"
        assert spec.category is Category.SUPPLY_CHAIN
        assert spec.mode is ScanMode.PROBE
        assert spec.depends_on == ("http_probe",)

    async def test_records_every_script(self, make_ctx: Any) -> None:
        site = self.site()
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.OK
        state = scripts_state(result)
        assert {"src": f"https://{HOST}/assets/index-BetUtrcO.js", "sha256": sha("console.log('app')")} in state  # fmt: skip
        assert {"src": f"https://{HOST}/vendor/wallet.js", "sha256": sha("console.log('wallet')")} in state  # fmt: skip
        assert {"src": "https://cdn.example.net/lib/analytics.min.js", "integrity": ""} in state
        pinned = next(e for e in state if e.get("src", "").startswith("https://pinned."))
        assert pinned["integrity"].startswith("sha384-")
        # One inline script. The JSON-LD block is data, not a script.
        assert len([e for e in state if "inline" in e]) == 1
        assert len(state) == 7
        assert state == sorted(state, key=lambda e: json.dumps(e, sort_keys=True))

    async def test_contacts_only_its_own_host(self, make_ctx: Any) -> None:
        site = self.site()
        await scan_site(make_ctx, site)
        assert site.fetched == ["/", "/assets/index-BetUtrcO.js", "/vendor/wallet.js?v=20260901"]
        default_agent = httpx.AsyncClient().headers["user-agent"]
        assert {r.headers["user-agent"] for r in site.requests} == {default_agent}

    async def test_explains_build_hashes(self, make_ctx: Any) -> None:
        result = await scan_site(make_ctx, self.site())
        assert any("build code in file names" in n for n in result.notes)
        [finding] = by_kind(result, "frontend.scripts")
        assert "every release changes this list" in finding.evidence["note"]
        assert finding.severity is Severity.INFO
        assert finding.identity == {}

    async def test_integrity_findings_are_per_origin(self, make_ctx: Any) -> None:
        result = await scan_site(make_ctx, self.site())
        findings = {
            f.identity["origin"]: f for f in by_kind(result, "frontend.script.no_integrity")
        }
        assert set(findings) == {"https://cdn.example.net", f"https://static.{ROOT}"}
        cdn = findings["https://cdn.example.net"]
        assert cdn.severity is Severity.LOW
        assert cdn.evidence["script_count"] == 2
        assert cdn.asset_key == HOST
        own = findings[f"https://static.{ROOT}"]
        assert own.severity is Severity.INFO
        assert "own domain" in (own.severity_note or "")

    async def test_integrity_findings_are_capped(self, make_ctx: Any) -> None:
        tags = [f'<script src="https://cdn{i}.example.net/a.js"></script>' for i in range(40)]
        result = await scan_site(make_ctx, Site().page(simple_page(*tags)))
        found = by_kind(result, "frontend.script.no_integrity")
        assert len(found) == frontend.MAX_INTEGRITY_FINDINGS

    async def test_an_empty_integrity_attribute_does_not_count(self, make_ctx: Any) -> None:
        page = simple_page('<script src="https://cdn.example.net/a.js" integrity=""></script>')
        result = await scan_site(make_ctx, Site().page(page))
        assert len(by_kind(result, "frontend.script.no_integrity")) == 1

    async def test_a_page_without_scripts(self, make_ctx: Any) -> None:
        result = await scan_site(make_ctx, Site().page(simple_page("<title>x</title>")))
        assert scripts_state(result) == []

    async def test_skipped_without_http_probe(self, make_ctx: Any) -> None:
        ctx = make_ctx(mode=ScanMode.PROBE)
        ctx.assets.add(resolved({HOST: [PUBLIC_IP]}, root=ROOT))
        result = await Frontend().run(TARGET, ctx)
        assert result.status is ModuleStatus.SKIPPED

    async def test_hosts_that_are_not_web_servers_are_left_alone(self, make_ctx: Any) -> None:
        ctx = web_ctx(make_ctx, None)
        ctx.assets.get("http_probe").assets[0].state["web"] = False
        result = await Frontend().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []


class TestFrontendHeaders:
    async def test_all_missing_over_https(self, make_ctx: Any) -> None:
        result = await scan_site(make_ctx, Site().page(simple_page()))
        [finding] = by_kind(result, "http.headers.missing")
        assert finding.state == {
            "missing": [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options or frame-ancestors",
            ]
        }
        assert finding.asset_key == HOST
        assert finding.category is Category.SURFACE

    async def test_nothing_missing(self, make_ctx: Any) -> None:
        result = await scan_site(make_ctx, Site().page(simple_page(), GOOD_HEADERS))
        assert by_kind(result, "http.headers.missing") == []

    async def test_plain_http_does_not_need_hsts(self, make_ctx: Any) -> None:
        site = Site(scheme="http").page(simple_page(), {"content-type": "text/html"})
        result = await scan_site(make_ctx, site, web={HOST: False})
        [finding] = by_kind(result, "http.headers.missing")
        assert "Strict-Transport-Security" not in finding.state["missing"]
        assert site.requests[0].url.scheme == "http"

    async def test_x_frame_options_satisfies_framing(self, make_ctx: Any) -> None:
        headers = {
            **GOOD_HEADERS,
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        }
        result = await scan_site(make_ctx, Site().page(simple_page(), headers))
        assert by_kind(result, "http.headers.missing") == []

    async def test_policy_in_a_meta_tag(self, make_ctx: Any) -> None:
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "content-security-policy"}
        meta = (
            '<meta http-equiv="Content-Security-Policy" '
            "content=\"default-src 'self'; frame-ancestors 'none'\">"
        )
        result = await scan_site(make_ctx, Site().page(simple_page(meta), headers))
        [finding] = by_kind(result, "http.headers.missing")
        # Browsers ignore frame-ancestors in a meta tag, so framing is still open.
        assert finding.state == {"missing": ["X-Frame-Options or frame-ancestors"]}

    async def test_report_only_policy_does_not_count(self, make_ctx: Any) -> None:
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "content-security-policy"}
        headers["content-security-policy-report-only"] = "default-src 'self'"
        headers["x-frame-options"] = "DENY"
        result = await scan_site(make_ctx, Site().page(simple_page(), headers))
        [finding] = by_kind(result, "http.headers.missing")
        assert finding.state == {"missing": ["Content-Security-Policy"]}


class TestFrontendChanges:
    PAGE = simple_page(
        '<script src="/app.js?v=1"></script>',
        '<script src="https://cdn.example.net/lib.js"></script>',
        "<script>window.ready = true;</script>",
    )

    async def finding(self, make_ctx: Any, page: str, app: str = "app()") -> Finding:
        site = Site().page(page).file("/app.js", app).file("/extra.js", "extra()")
        [finding] = by_kind(await scan_site(make_ctx, site), "frontend.scripts")
        return finding

    async def test_unchanged_page_gives_identical_state(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        second = await self.finding(make_ctx, self.PAGE)
        assert first.state == second.state
        assert finding_state_hash(first) == finding_state_hash(second)

    async def test_changed_script_body(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        second = await self.finding(make_ctx, self.PAGE, app="app(); drain(wallet)")
        assert finding_state_hash(first) != finding_state_hash(second)
        assert len(first.state["scripts"]) == len(second.state["scripts"])

    async def test_added_script(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        added = self.PAGE.replace("</head>", '<script src="/extra.js"></script></head>')
        second = await self.finding(make_ctx, added)
        assert finding_state_hash(first) != finding_state_hash(second)
        assert len(second.state["scripts"]) == len(first.state["scripts"]) + 1

    async def test_added_script_on_another_origin(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        added = self.PAGE.replace(
            "</head>", '<script src="https://evil.example/drain.js"></script></head>'
        )
        second = await self.finding(make_ctx, added)
        assert finding_state_hash(first) != finding_state_hash(second)

    async def test_removed_script(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        removed = self.PAGE.replace('<script src="/app.js?v=1"></script>', "")
        second = await self.finding(make_ctx, removed)
        assert finding_state_hash(first) != finding_state_hash(second)
        assert len(second.state["scripts"]) == len(first.state["scripts"]) - 1

    async def test_changed_inline_script(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        second = await self.finding(make_ctx, self.PAGE.replace("ready = true", "ready = 1"))
        assert finding_state_hash(first) != finding_state_hash(second)

    async def test_changed_integrity_value(self, make_ctx: Any) -> None:
        one = "sha256-" + "A" * 43 + "="
        two = "sha256-" + "B" * 43 + "="
        page = simple_page(
            f'<script src="https://cdn.example.net/l.js" integrity="{one}"></script>'
        )
        first = await self.finding(make_ctx, page)
        second = await self.finding(make_ctx, page.replace(one, two))
        assert finding_state_hash(first) != finding_state_hash(second)

    async def test_cache_buster_does_not_change_state(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        busted = self.PAGE.replace("/app.js?v=1", "/app.js?v=20260929&t=1790000000").replace(
            "lib.js", "lib.js?cb=42#top"
        )
        second = await self.finding(make_ctx, busted)
        assert first.state == second.state
        assert finding_state_hash(first) == finding_state_hash(second)

    async def test_fingerprint_relevant_identity_is_stable(self, make_ctx: Any) -> None:
        first = await self.finding(make_ctx, self.PAGE)
        second = await self.finding(make_ctx, self.PAGE, app="changed()")
        assert (first.kind, first.asset_key, first.identity) == (
            second.kind,
            second.asset_key,
            second.identity,
        )


HOSTILE_SOURCES = [
    "http://127.0.0.1/a.js",
    "http://localhost:8080/a.js",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/a.js",
    "http://[::1]/a.js",
    "http://[fd00:ec2::254]/a.js",
    "//192.168.1.1/a.js",
    "https://0x7f000001/a.js",
    "https://2130706433/a.js",
    "javascript:alert(1)",
    " JaVaScRiPt:alert(1)",
    "java\nscript:alert(1)",
    "data:text/javascript,alert(1)",
    "data:text/javascript;base64,YWxlcnQoMSk=",
    "file:///etc/passwd",
    "blob:https://evil.example/1234",
    "ftp://evil.example/a.js",
    "gopher://evil.example/a.js",
    "//evil.example/a.js",
    "///evil.example/a.js",
    "\\\\evil.example\\a.js",
    "/\\evil.example/a.js",
    "https:\\\\evil.example/a.js",
    "https:evil.example/a.js",
    "http:/evil.example/a.js",
    "http://evil.example/a.js",
    f"https://{HOST}@evil.example/a.js",
    f"https://{HOST}:pass@evil.example/a.js",
    f"https://evil.example#@{HOST}/a.js",
    f"https://evil.example?@{HOST}/a.js",
    f"https://evil.example\\@{HOST}/a.js",
    f"https://{HOST}.evil.example/a.js",
    f"https://{HOST}%2eevil.example/a.js",
    f"https://{HOST}%00.evil.example/a.js",
    f"https://{HOST}\x00.evil.example/a.js",
    f"https://{HOST}:8443/a.js",
    f"https://{HOST}:99999/a.js",
    f"https://{HOST}./a.js",
    f"http://{HOST}/a.js",
    "https://[not-an-address/a.js",
    "https://evil.example:443:80/a.js",
    "https://\uff45\uff56\uff49\uff4c.example/a.js",  # full-width letters
    "\t//evil.example/a.js",
    "/\t/evil.example/a.js",
    "//evil.example\\@" + HOST + "/a.js",
    "https://" + "a" * 5000 + ".example/a.js",
]


class TestFrontendHostileHtml:
    @pytest.mark.parametrize("source", HOSTILE_SOURCES)
    async def test_hostile_script_address(self, make_ctx: Any, source: str) -> None:
        escaped = source.replace("&", "&amp;").replace('"', "&quot;")
        site = Site().page(simple_page(f'<script src="{escaped}"></script>'))
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.OK
        assert [r.url.host for r in site.requests] == [HOST] * len(site.requests)
        assert len(by_kind(result, "frontend.scripts")) == 1

    async def test_all_hostile_addresses_at_once(self, make_ctx: Any) -> None:
        tags = [f'<script src="{s.replace(chr(34), "")}"></script>' for s in HOSTILE_SOURCES]
        site = Site().page(simple_page(*tags))
        result = await scan_site(make_ctx, site)
        assert {r.url.host for r in site.requests} == {HOST}
        state = scripts_state(result)
        # Private addresses are recorded, because the page really refers to them.
        assert {"src": "http://169.254.169.254/latest/meta-data/", "integrity": ""} in state
        # data: scripts run in a browser, so they are recorded by content.
        assert {"inline": sha("data:text/javascript,alert(1)")} in state
        assert not any("javascript:" in json.dumps(e).lower() for e in state)

    async def test_base_tag_cannot_redirect_fetches(self, make_ctx: Any) -> None:
        page = simple_page(
            '<base href="https://evil.example/assets/">',
            '<base href="/ignored-second-base/">',
            '<script src="app.js"></script>',
            '<script src="/rooted.js"></script>',
            f'<script src="https://{HOST}/mine.js"></script>',
        )
        site = Site().page(page).file("/mine.js", "mine()")
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/", "/mine.js"]
        state = scripts_state(result)
        # A browser would load these from the other host, so that is what is recorded.
        assert {"src": "https://evil.example/assets/app.js", "integrity": ""} in state
        assert {"src": "https://evil.example/rooted.js", "integrity": ""} in state
        assert {"src": f"https://{HOST}/mine.js", "sha256": sha("mine()")} in state
        assert len(by_kind(result, "frontend.script.no_integrity")) == 1

    @pytest.mark.parametrize(
        "base", ["//evil.example/", "\\\\evil.example\\", "http://10.0.0.1/", "///evil.example/x/"]
    )
    async def test_base_tag_variants(self, make_ctx: Any, base: str) -> None:
        site = Site().page(simple_page(f'<base href="{base}">', '<script src="a.js"></script>'))
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/"]
        [entry] = scripts_state(result)
        assert HOST not in entry["src"]

    async def test_base_with_a_script_scheme_is_ignored(self, make_ctx: Any) -> None:
        page = simple_page('<base href="javascript:alert(1)">', '<script src="a.js"></script>')
        site = Site().page(page).file("/a.js", "a()")
        assert scripts_state(await scan_site(make_ctx, site)) == [
            {"src": f"https://{HOST}/a.js", "sha256": sha("a()")}
        ]

    async def test_same_host_base_path(self, make_ctx: Any) -> None:
        page = simple_page('<base href="/static/v2/">', '<script src="a.js"></script>')
        site = Site().page(page).file("/static/v2/a.js", "a()")
        await scan_site(make_ctx, site)
        assert site.fetched == ["/", "/static/v2/a.js"]

    async def test_dot_segments_stay_on_the_host(self, make_ctx: Any) -> None:
        page = simple_page('<script src="/a/../../../../etc/passwd"></script>')
        site = Site().page(page)
        result = await scan_site(make_ctx, site)
        assert {r.url.host for r in site.requests} == {HOST}
        assert result.status is ModuleStatus.OK

    async def test_unclosed_tags(self, make_ctx: Any) -> None:
        page = (
            '<html><head><script src="/a.js"><div><script src=/b.js'
            "<p><script>var x = '<scr' + 'ipt src=\"https://evil.example/x.js\">'; never closed"
        )
        site = Site().page(page).file("/a.js", "a()")
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.OK
        assert {r.url.host for r in site.requests} == {HOST}
        assert len(by_kind(result, "frontend.scripts")) == 1

    async def test_unclosed_inline_script_is_still_recorded(self) -> None:
        parsed = parse_page("<script>steal()")
        assert parsed.inline == [sha("steal()")]

    async def test_scripts_in_comments_are_not_scripts(self) -> None:
        parsed = parse_page(
            '<!-- <script src="/old.js"></script> --><script src="/new.js"></script>'
        )
        assert [t.src for t in parsed.external] == ["/new.js"]

    async def test_first_duplicate_attribute_wins(self) -> None:
        parsed = parse_page('<SCRIPT SRC="/first.js" src="https://evil.example/x.js"></SCRIPT>')
        assert [t.src for t in parsed.external] == ["/first.js"]

    async def test_garbage_bytes(self, make_ctx: Any) -> None:
        body = b"\xff\xfe\x00<script src='/a.js'>\x00</script>" + bytes(range(256)) * 20
        site = Site().file("/a.js", "a()")
        site.paths["/"] = httpx.Response(200, content=body, headers={"content-type": "text/html"})
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.OK
        assert {r.url.host for r in site.requests} == {HOST}

    async def test_unknown_charset(self, make_ctx: Any) -> None:
        site = Site().page(simple_page(), {"content-type": "text/html; charset=not-a-charset"})
        assert (await scan_site(make_ctx, site)).status is ModuleStatus.OK

    async def test_huge_document_is_cut_off(self, make_ctx: Any) -> None:
        page = (
            "<html><script src='/early.js'></script>"
            + "<p>filler</p>" * 200_000
            + "<script src='/late.js'></script></html>"
        )
        assert len(page) > frontend.MAX_PAGE_BYTES
        site = Site().page(page).file("/early.js", "e()").file("/late.js", "l()")
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.PARTIAL
        assert site.fetched == ["/", "/early.js"]
        assert any("very large" in n for n in result.notes)

    async def test_too_many_script_tags(self, make_ctx: Any) -> None:
        tags = [f"<script>inline{i}()</script>" for i in range(frontend.MAX_SCRIPT_TAGS + 50)]
        result = await scan_site(make_ctx, Site().page(simple_page(*tags)))
        assert result.status is ModuleStatus.PARTIAL
        assert len(scripts_state(result)) == frontend.MAX_SCRIPT_TAGS

    async def test_long_values_are_capped(self, make_ctx: Any) -> None:
        long_path = "/" + "a" * 5_000 + ".js"
        page = simple_page(
            f'<script src="{long_path}"></script>',
            f'<script src="https://cdn.example.net{long_path}"></script>',
        )
        site = Site().page(page)
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/"]
        for entry in scripts_state(result):
            assert len(entry["src"]) <= frontend.MAX_SHOWN_CHARS
        assert len(result.model_dump_json()) < 20_000

    async def test_not_a_web_page(self, make_ctx: Any) -> None:
        site = Site().page('{"script": "<script src=/a.js>"}', {"content-type": "application/json"})
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/"]
        assert by_kind(result, "frontend.scripts") == []
        assert len(by_kind(result, "http.headers.missing")) == 1


class TestFrontendRedirects:
    async def test_page_redirect_to_another_host_is_not_followed(self, make_ctx: Any) -> None:
        site = Site()
        site.paths["/"] = httpx.Response(302, headers={"location": "https://evil.example/"})
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/"]
        assert result.findings == []
        assert any("not followed" in n for n in result.notes)

    @pytest.mark.parametrize(
        "location",
        [
            "//evil.example/",
            "http://169.254.169.254/",
            f"https://{HOST}@evil.example/",
            f"https://{HOST}:8443/",
            "\\\\evil.example/",
            f"https://app.{ROOT}/",
            "javascript:alert(1)",
        ],
    )
    async def test_redirect_variants(self, make_ctx: Any, location: str) -> None:
        site = Site()
        site.paths["/"] = httpx.Response(301, headers={"location": location})
        result = await scan_site(
            make_ctx, site, hosts={HOST: [PUBLIC_IP], f"app.{ROOT}": [PUBLIC_IP]}
        )
        assert site.fetched == ["/"]
        assert result.findings == []

    async def test_same_host_redirect_is_followed(self, make_ctx: Any) -> None:
        site = Site().file("/app.js", "app()")
        site.paths["/"] = httpx.Response(302, headers={"location": "/en/"})
        site.paths["/en/"] = httpx.Response(
            200,
            content=b'<script src="/app.js"></script>',
            headers={"content-type": "text/html"},
        )
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/", "/en/", "/app.js"]
        assert len(scripts_state(result)) == 1

    async def test_upgrade_to_https_on_the_same_host(self, make_ctx: Any) -> None:
        site = Site()

        def root(request: httpx.Request) -> httpx.Response:
            if request.url.scheme == "http":
                return httpx.Response(301, headers={"location": f"https://{HOST}/"})
            return httpx.Response(200, content=b"<p>hi</p>", headers=GOOD_HEADERS)

        site.paths["/"] = root
        result = await scan_site(make_ctx, site, web={HOST: False})
        assert [str(r.url) for r in site.requests] == [f"http://{HOST}/", f"https://{HOST}/"]
        assert result.status is ModuleStatus.OK
        assert by_kind(result, "http.headers.missing") == []

    async def test_redirect_loop_ends(self, make_ctx: Any) -> None:
        site = Site()
        site.paths["/"] = httpx.Response(302, headers={"location": "/"})
        result = await scan_site(make_ctx, site)
        assert len(site.requests) == frontend.MAX_REDIRECTS + 1
        assert result.status is ModuleStatus.FAILED

    async def test_script_redirect_to_another_host(self, make_ctx: Any) -> None:
        site = Site().page(simple_page('<script src="/app.js"></script>'))
        site.paths["/app.js"] = httpx.Response(
            302, headers={"location": "https://evil.example/drain.js?x=1"}
        )
        result = await scan_site(make_ctx, site)
        assert site.fetched == ["/", "/app.js"]
        assert scripts_state(result) == [
            {
                "src": f"https://{HOST}/app.js",
                "sha256": "",
                "redirects_to": "https://evil.example/drain.js",
            }
        ]


class FakeStream:
    def __init__(self, address: str) -> None:
        self.address = address

    def get_extra_info(self, name: str) -> Any:
        return (self.address, 443) if name == "server_addr" else None


class TestFrontendSafety:
    async def test_other_origins_are_never_fetched(self, make_ctx: Any) -> None:
        page = simple_page(
            '<script src="https://cdn.example.net/a.js"></script>',
            f'<script src="https://static.{ROOT}/b.js"></script>',
            f'<script src="https://{ROOT}/c.js"></script>',
        )
        site = Site().page(page)
        # The sibling hosts are in scope and contactable, and are still not fetched from.
        result = await scan_site(
            make_ctx,
            site,
            hosts={HOST: [PUBLIC_IP], f"static.{ROOT}": [PUBLIC_IP], ROOT: [PUBLIC_IP]},
        )
        assert site.fetched == ["/"]
        assert len(scripts_state(result)) == 3

    @pytest.mark.parametrize("address", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1"])
    async def test_host_with_a_private_address_is_not_contacted(
        self, make_ctx: Any, address: str
    ) -> None:
        ctx = web_ctx(make_ctx, None, hosts={HOST: [PUBLIC_IP, address]})
        result = await Frontend().run(TARGET, ctx)
        assert result.findings == []
        assert any("private or reserved" in n for n in result.notes)

    async def test_host_outside_the_domain_is_not_contacted(self, make_ctx: Any) -> None:
        ctx = web_ctx(
            make_ctx,
            None,
            hosts={"www.elsewhere.example": [PUBLIC_IP]},
            web={"www.elsewhere.example": True},
        )
        result = await Frontend().run(TARGET, ctx)
        assert result.findings == []

    async def test_host_unknown_to_dns_resolve_is_not_contacted(self, make_ctx: Any) -> None:
        ctx = web_ctx(make_ctx, None, web={f"ghost.{ROOT}": True})
        result = await Frontend().run(TARGET, ctx)
        assert result.findings == []

    async def test_do_not_contact_list(self, make_ctx: Any, settings: Any) -> None:
        settings.never_contact = [HOST]
        result = await Frontend().run(TARGET, web_ctx(make_ctx, None))
        assert result.findings == []
        assert any("do-not-contact" in n for n in result.notes)

    async def test_answer_from_a_private_address_is_discarded(self, make_ctx: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b'<script src="/a.js"></script>',
                headers={"content-type": "text/html"},
                extensions={"network_stream": FakeStream("10.1.2.3")},
            )

        result = await Frontend().run(TARGET, web_ctx(make_ctx, handler))
        assert result.status is ModuleStatus.FAILED
        assert result.findings == []
        assert any("non-public address" in n for n in result.notes)

    async def test_answer_from_a_public_address_is_kept(self, make_ctx: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"<p>hello</p>",
                headers=GOOD_HEADERS,
                extensions={"network_stream": FakeStream(PUBLIC_IP)},
            )

        result = await Frontend().run(TARGET, web_ctx(make_ctx, handler))
        assert result.status is ModuleStatus.OK

    async def test_rate_limiter_is_used_for_every_request(self, make_ctx: Any) -> None:
        site = Site().page(simple_page('<script src="/a.js"></script>')).file("/a.js", "a()")
        ctx = web_ctx(make_ctx, site)
        waited: list[str] = []
        original = ctx.limiter.acquire

        async def acquire(host: str) -> None:
            waited.append(host)
            await original(host)

        ctx.limiter.acquire = acquire
        await Frontend().run(TARGET, ctx)
        assert waited == [HOST, HOST]
        assert len(site.requests) == 2


class TestFrontendLimits:
    async def test_large_script_is_hashed_up_to_the_cap(self, make_ctx: Any) -> None:
        body = b"x" * (frontend.MAX_SCRIPT_BYTES + 500_000)
        site = Site().page(simple_page('<script src="/big.js"></script>')).file("/big.js", body)
        result = await scan_site(make_ctx, site)
        assert scripts_state(result) == [
            {
                "src": f"https://{HOST}/big.js",
                "sha256": sha(body[: frontend.MAX_SCRIPT_BYTES]),
                "status": "first part only",
            }
        ]

    async def test_at_most_forty_scripts_are_fetched(self, make_ctx: Any) -> None:
        tags = [f'<script src="/s/{i:03}.js"></script>' for i in range(55)]
        site = Site().page(simple_page(*tags))
        for i in range(55):
            site.file(f"/s/{i:03}.js", f"s{i}()")
        result = await scan_site(make_ctx, site)
        assert len(site.requests) == 1 + frontend.MAX_SCRIPTS_FETCHED == 41
        assert result.status is ModuleStatus.PARTIAL
        state = scripts_state(result)
        assert len(state) == 55
        assert len([e for e in state if e.get("status") == "not read"]) == 15
        assert result.stats["scripts_fetched"] == 40

    async def test_the_same_script_twice_is_fetched_once(self, make_ctx: Any) -> None:
        page = simple_page('<script src="/a.js?1"></script>', '<script src="/a.js?2"></script>')
        site = Site().page(page).file("/a.js", "a()")
        result = await scan_site(make_ctx, site)
        assert len(site.requests) == 2
        assert len(scripts_state(result)) == 1

    async def test_missing_script_is_a_stable_fact(self, make_ctx: Any) -> None:
        site = Site().page(simple_page('<script src="/gone.js"></script>'))
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.OK
        assert scripts_state(result) == [
            {"src": f"https://{HOST}/gone.js", "sha256": "", "status": "not found"}
        ]

    async def test_script_error_does_not_look_like_a_removal(self, make_ctx: Any) -> None:
        site = (
            Site()
            .page(simple_page('<script src="/a.js"></script><script src="/b.js"></script>'))
            .file("/a.js", "a()")
            .file("/b.js", "oops", status=503)
        )
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.PARTIAL
        assert by_kind(result, "frontend.scripts") == []
        assert any("were not recorded" in n for n in result.notes)

    async def test_page_errors(self, make_ctx: Any) -> None:
        site = Site()
        site.paths["/"] = httpx.Response(503, content=b"down")
        result = await scan_site(make_ctx, site)
        assert result.status is ModuleStatus.FAILED
        assert result.findings == []

    async def test_connection_failure(self, make_ctx: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        result = await Frontend().run(TARGET, web_ctx(make_ctx, handler))
        assert result.status is ModuleStatus.FAILED
        assert "could be read" in (result.skip_reason or "")

    async def test_one_bad_host_gives_a_partial_result(self, make_ctx: Any) -> None:
        other = f"app.{ROOT}"

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.host in (HOST, other)
            if request.url.host == other:
                return httpx.Response(500)
            return httpx.Response(200, content=b"<p>ok</p>", headers=GOOD_HEADERS)

        ctx = web_ctx(
            make_ctx,
            handler,
            hosts={HOST: [PUBLIC_IP], other: [PUBLIC_IP]},
            web={HOST: True, other: True},
        )
        result = await Frontend().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert [f.asset_key for f in result.findings] == [HOST]

    async def test_host_cap(self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(frontend, "MAX_HOSTS", 2)
        names = [f"h{i}.{ROOT}" for i in range(4)]
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.host)
            return httpx.Response(200, content=b"<p>ok</p>", headers=GOOD_HEADERS)

        ctx = web_ctx(
            make_ctx,
            handler,
            hosts={n: [PUBLIC_IP] for n in names},
            web=dict.fromkeys(names, True),
        )
        result = await Frontend().run(TARGET, ctx)
        assert sorted(seen) == names[:2]
        assert result.status is ModuleStatus.PARTIAL


class TestResolve:
    PAGE = Origin("https", HOST)

    def test_relative_and_absolute(self) -> None:
        assert resolve(self.PAGE, None, "a.js").address == f"https://{HOST}/a.js"
        assert resolve(self.PAGE, None, "/x/../a.js?v=1#f").address == f"https://{HOST}/a.js"
        assert resolve(self.PAGE, None, f"HTTPS://{HOST.upper()}:443/a.js").kind == "same"

    def test_query_is_kept_for_the_request_only(self) -> None:
        found = resolve(self.PAGE, None, "/a.js?v=1&x=<b>")
        assert found.address == f"https://{HOST}/a.js"
        assert found.query == "v=1&x=%3Cb%3E"

    @pytest.mark.parametrize("source", HOSTILE_SOURCES)
    def test_hostile_sources_never_count_as_the_same_origin_elsewhere(self, source: str) -> None:
        found = resolve(self.PAGE, None, source)
        if found.kind == "same":
            # Requests are rebuilt from the vetted host and this path, nothing else.
            assert found.host == HOST
            assert found.path.startswith("/")
            assert found.path.isascii()
            assert not any(ch in found.path for ch in " \\\t\r\n")


# --------------------------------------------------------------------------
# packages
# --------------------------------------------------------------------------


class Registries:
    """Stands in for npm, its download counts, and PyPI. Unknown names do not exist."""

    HOSTS = ("registry.npmjs.org", "api.npmjs.org", "pypi.org")

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.requests: list[httpx.Request] = []

    def npm(self, name: str, answer: Any) -> Registries:
        self.routes[("registry.npmjs.org", "/" + name.replace("/", "%2f"))] = answer
        return self

    def pypi(self, name: str, answer: Any) -> Registries:
        self.routes[("pypi.org", f"/pypi/{name}/json")] = answer
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.url.host in self.HOSTS, f"unexpected host: {request.url}"
        assert request.url.scheme == "https"
        assert request.method in ("GET", "HEAD")
        path = request.url.raw_path.decode()
        if request.url.host == "api.npmjs.org":
            return self.downloads(path)
        answer = self.routes.get((request.url.host, path))
        if answer is None:
            return httpx.Response(404, json={"error": "Not found"})
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, httpx.Response):
            return answer
        if request.method == "HEAD":
            return httpx.Response(200)
        if isinstance(answer, str):
            return httpx.Response(200, content=answer.encode())
        return httpx.Response(200, json=answer)

    def downloads(self, path: str) -> httpx.Response:
        names = path.removeprefix("/downloads/point/last-week/").split(",")
        rows = {n: {"downloads": 412, "package": n, "start": "a", "end": "b"} for n in names}
        return httpx.Response(200, json=rows[names[0]] if len(names) == 1 else rows)

    def made(self, method: str, host: str) -> list[str]:
        return [
            r.url.raw_path.decode()
            for r in self.requests
            if r.method == method and r.url.host == host
        ]


@pytest.fixture
def registries() -> Registries:
    return Registries()


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(packages, "utcnow", lambda: NOW)


def npm_target(*names: str) -> Target:
    return Target(root_domain=ROOT, npm_packages=list(names))


def pypi_target(*names: str) -> Target:
    return Target(root_domain=ROOT, pypi_packages=list(names))


def no_personal_data(result: ModuleResult) -> None:
    text = result.model_dump_json()
    assert "mail.example" not in text
    assert "private" not in text
    assert "@" not in text.replace("@acme/", "").replace("@acm", "")


class TestPackagesNpm:
    def test_spec(self) -> None:
        spec = Packages.spec
        assert spec.name == "packages"
        assert spec.category is Category.SUPPLY_CHAIN
        assert spec.mode is ScanMode.PASSIVE
        assert spec.requires_target == ()

    async def test_skipped_without_packages(self, make_ctx: Any) -> None:
        result = await Packages().run(Target(root_domain=ROOT), make_ctx())
        assert result.status is ModuleStatus.SKIPPED
        assert "no npm or PyPI packages" in (result.skip_reason or "")
        assert result.hint

    async def test_maintainers(self, make_ctx: Any, registries: Registries) -> None:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "package.maintainers"
        assert finding.asset_type is AssetType.PACKAGE
        assert finding.asset_key == "npm:acme-sdk"
        assert finding.state == {
            "maintainers": ["acme-release-bot", "alice-acme"],
            "latest_version": "1.3.0",
            "source": "accounts",
        }
        assert finding.evidence["first_published"] == "2021-03-14"
        assert finding.severity is Severity.INFO
        assert [a.key for a in result.assets] == ["npm:acme-sdk"]

    async def test_maintainer_emails_never_appear(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        registries.npm("acme_sdk", json.loads(fixture_text("packages", "npm_lookalike.json")))
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert len(result.findings) == 2
        no_personal_data(result)

    async def test_email_in_the_name_field_is_dropped(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        document = json.loads(fixture_text("packages", "npm_acme-sdk.json"))
        document["maintainers"] = [
            {"name": "sneaky.private@mail.example", "email": "x@mail.example"},
            {"name": "alice-acme"},
            {"name": {"nested": "private@mail.example"}},
            "private@mail.example",
            None,
        ]
        registries.npm("acme-sdk", document)
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert by_kind(result, "package.maintainers")[0].state["maintainers"] == ["alice-acme"]
        no_personal_data(result)

    async def test_maintainer_change_changes_state(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        document = json.loads(fixture_text("packages", "npm_acme-sdk.json"))
        registries.npm("acme-sdk", document)
        first = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        same = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        document["maintainers"].append({"name": "new-person", "email": "n@mail.example"})
        second = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        hashes = [finding_state_hash(r.findings[0]) for r in (first, same, second)]
        assert hashes[0] == hashes[1] != hashes[2]

    async def test_scoped_name_is_encoded(self, make_ctx: Any, registries: Registries) -> None:
        registries.npm("@acme/sdk", json.loads(fixture_text("packages", "npm_scoped.json")))
        result = await Packages().run(npm_target("@acme/sdk"), make_ctx(handler=registries))
        assert registries.made("GET", "registry.npmjs.org") == ["/@acme%2fsdk"]
        assert by_kind(result, "package.maintainers")[0].asset_key == "npm:@acme/sdk"
        for path in registries.made("HEAD", "registry.npmjs.org"):
            assert path.count("/") == 1, path

    async def test_missing(self, make_ctx: Any, registries: Registries) -> None:
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "package.missing"
        assert finding.severity is Severity.LOW
        assert finding.asset_key == "npm:acme-sdk"

    async def test_very_long_history_falls_back_to_latest_release(
        self, make_ctx: Any, registries: Registries, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_DOCUMENT_BYTES", 50_000)
        document = json.loads(fixture_text("packages", "npm_acme-sdk.json"))
        document["readme"] = "x" * 100_000
        registries.npm("acme-sdk", document)
        registries.npm(
            "acme-sdk/latest",
            {"name": "acme-sdk", "version": "1.3.0", "maintainers": [{"name": "alice-acme"}]},
        )
        # registered with a real slash, which is how the fallback address is built
        registries.routes[("registry.npmjs.org", "/acme-sdk/latest")] = registries.routes.pop(
            ("registry.npmjs.org", "/acme-sdk%2flatest")
        )
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        [finding] = by_kind(result, "package.maintainers")
        assert finding.state["maintainers"] == ["alice-acme"]
        assert finding.state["latest_version"] == "1.3.0"


class TestPackagesPypi:
    async def test_accounts_with_a_role(self, make_ctx: Any, registries: Registries) -> None:
        registries.pypi("acme-sdk", json.loads(fixture_text("packages", "pypi_acme-sdk.json")))
        result = await Packages().run(pypi_target("Acme_SDK"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.asset_key == "pypi:acme-sdk"
        assert finding.state == {
            "maintainers": ["alice-acme", "bob-acme"],
            "latest_version": "2.4.1",
            "source": "accounts",
        }
        assert finding.evidence["roles"] == {"alice-acme": "Owner", "bob-acme": "Maintainer"}
        assert finding.evidence["first_published"] == "2020-02-14"
        assert any("two-factor" in n for n in result.notes)
        no_personal_data(result)

    async def test_falls_back_to_the_description(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        document = json.loads(fixture_text("packages", "pypi_acme-sdk.json"))
        del document["ownership"]
        registries.pypi("acme-sdk", document)
        result = await Packages().run(pypi_target("acme-sdk"), make_ctx(handler=registries))
        [finding] = result.findings
        assert finding.state["maintainers"] == ["Alice Example", "Bob Example"]
        assert finding.state["source"] == "description"
        assert any("do not prove who can publish" in n for n in result.notes)
        no_personal_data(result)

    async def test_missing(self, make_ctx: Any, registries: Registries) -> None:
        result = await Packages().run(pypi_target("acme-sdk"), make_ctx(handler=registries))
        assert [f.kind for f in result.findings] == ["package.missing"]

    async def test_lookalike(self, make_ctx: Any, registries: Registries) -> None:
        registries.pypi("acme-sdk", json.loads(fixture_text("packages", "pypi_acme-sdk.json")))
        registries.pypi("acmesdk", json.loads(fixture_text("packages", "pypi_lookalike.json")))
        result = await Packages().run(pypi_target("acme-sdk"), make_ctx(handler=registries))
        [finding] = by_kind(result, "package.lookalike")
        assert finding.asset_key == "pypi:acmesdk"
        assert finding.severity is Severity.MEDIUM
        assert finding.evidence["first_published"] == "2019-05-01"
        assert "weekly_downloads" not in finding.evidence
        assert registries.made("GET", "api.npmjs.org") == []
        no_personal_data(result)

    async def test_separator_spellings_are_the_same_package(self) -> None:
        names = variants("pypi", "acme-sdk", {"acme-sdk"})
        assert "acme_sdk" not in names and "acme.sdk" not in names
        assert "acmesdk" in names


class TestPackagesLookalikes:
    async def run(self, make_ctx: Any, registries: Registries, **changes: Any) -> ModuleResult:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        lookalike = json.loads(fixture_text("packages", "npm_lookalike.json"))
        lookalike.update(changes)
        registries.npm("acme_sdk", lookalike)
        return await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))

    async def test_recent_lookalike_is_raised(self, make_ctx: Any, registries: Registries) -> None:
        result = await self.run(make_ctx, registries)
        [finding] = by_kind(result, "package.lookalike")
        assert finding.asset_key == "npm:acme_sdk"
        assert finding.identity == {"registry": "npm", "resembles": "acme-sdk"}
        assert finding.severity is Severity.HIGH
        assert "90 days" in (finding.severity_note or "")
        assert finding.evidence == {
            "registry": "npm",
            "name": "acme_sdk",
            "resembles": "acme-sdk",
            "page": "https://www.npmjs.com/package/acme_sdk",
            "first_published": "2026-09-10",
            "latest_version": "9.9.9",
            "weekly_downloads": 412,
        }
        assert finding.state == {"published_in_last_90_days": True, "shares_a_publisher": False}

    async def test_old_lookalike_keeps_the_default(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        result = await self.run(make_ctx, registries, time={"created": "2019-01-01T00:00:00.000Z"})
        [finding] = by_kind(result, "package.lookalike")
        assert finding.severity is Severity.MEDIUM
        assert finding.severity_note is None

    async def test_your_own_defensive_registration(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        result = await self.run(make_ctx, registries, maintainers=[{"name": "alice-acme"}])
        [finding] = by_kind(result, "package.lookalike")
        assert finding.severity is Severity.LOW
        assert finding.evidence["shared_publishers"] == ["alice-acme"]

    async def test_checks_are_light_and_capped(self, make_ctx: Any, registries: Registries) -> None:
        result = await self.run(make_ctx, registries)
        heads = registries.made("HEAD", "registry.npmjs.org")
        assert 10 < len(heads) <= packages.MAX_VARIANTS
        assert len(set(heads)) == len(heads)
        assert "/acme-sdk" not in heads
        # Full records are read only for the package itself and the one that exists.
        assert registries.made("GET", "registry.npmjs.org") == ["/acme-sdk", "/acme_sdk"]
        assert registries.made("GET", "api.npmjs.org") == ["/downloads/point/last-week/acme_sdk"]
        assert result.stats["similar_names_checked"] == len(heads)
        assert any("close spellings" in n for n in result.notes)

    async def test_own_packages_are_not_lookalikes(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        own = json.loads(fixture_text("packages", "npm_acme-sdk.json"))
        registries.npm("acme-sdk", own).npm("acme_sdk", own).npm("acmesdk", own)
        target = npm_target("acme-sdk", "acme_sdk", "acmesdk")
        result = await Packages().run(target, make_ctx(handler=registries))
        assert by_kind(result, "package.lookalike") == []
        assert len(by_kind(result, "package.maintainers")) == 3

    async def test_absent_names_are_remembered(self, make_ctx: Any, registries: Registries) -> None:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        ctx = make_ctx(handler=registries)
        await Packages().run(npm_target("acme-sdk"), ctx)
        first = len(registries.made("HEAD", "registry.npmjs.org"))
        await Packages().run(npm_target("acme-sdk"), ctx)
        assert first > 0
        assert len(registries.made("HEAD", "registry.npmjs.org")) == first

    async def test_stops_when_the_registry_says_slow_down(
        self, make_ctx: Any, registries: Registries
    ) -> None:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        first = variants("npm", "acme-sdk", {"acme-sdk"})[2]
        registries.npm(first, httpx.Response(429))
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.PARTIAL
        assert len(registries.made("HEAD", "registry.npmjs.org")) == 3
        assert any("stopped early" in n for n in result.notes)
        assert len(by_kind(result, "package.maintainers")) == 1

    async def test_too_many_lookalikes(
        self, make_ctx: Any, registries: Registries, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_LOOKALIKE_FINDINGS", 3)
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        lookalike = json.loads(fixture_text("packages", "npm_lookalike.json"))
        for name in variants("npm", "acme-sdk", {"acme-sdk"})[:8]:
            registries.npm(name, lookalike)
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert len(by_kind(result, "package.lookalike")) == 3
        assert result.status is ModuleStatus.PARTIAL

    async def test_download_counts_are_optional(
        self, make_ctx: Any, registries: Registries, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            Registries, "downloads", lambda self, path: httpx.Response(200, content=b"<html>")
        )
        result = await self.run(make_ctx, registries)
        [finding] = by_kind(result, "package.lookalike")
        assert "weekly_downloads" not in finding.evidence
        assert result.status is ModuleStatus.OK

    @pytest.mark.parametrize(
        "answer",
        [
            {"downloads": "many", "package": "acme_sdk"},
            {"downloads": 5, "package": "something-else"},
            {"downloads": True, "package": "acme_sdk"},
            ["not", "an", "object"],
        ],
    )
    async def test_odd_download_answers(
        self, make_ctx: Any, registries: Registries, monkeypatch: pytest.MonkeyPatch, answer: Any
    ) -> None:
        monkeypatch.setattr(
            Registries, "downloads", lambda self, path: httpx.Response(200, json=answer)
        )
        result = await self.run(make_ctx, registries)
        assert "weekly_downloads" not in by_kind(result, "package.lookalike")[0].evidence


class TestVariants:
    @pytest.mark.parametrize(
        ("registry", "name"),
        [
            ("npm", "acme-sdk"),
            ("npm", "@acme/sdk"),
            ("npm", "a-very-long-package-name-for-the-acme-protocol-sdk"),
            ("npm", "ab"),
            ("pypi", "acme-sdk"),
            ("pypi", "web3"),
        ],
    )
    def test_valid_capped_and_repeatable(self, registry: str, name: str) -> None:
        names = variants(registry, name, {name})
        assert names == variants(registry, name, {name})
        assert 0 < len(names) <= packages.MAX_VARIANTS
        assert len(set(names)) == len(names)
        assert name not in names
        check = valid_npm_name if registry == "npm" else valid_pypi_name
        assert all(check(n) == n for n in names)

    def test_kinds_of_variation(self) -> None:
        names = variants("npm", "acme-sdk", {"acme-sdk"})
        assert "acme-sd" in names  # dropped
        assert "amce-sdk" in names  # swapped
        assert "acmee-sdk" in names  # doubled
        assert "acne-sdk" in names  # replaced
        assert {"acme_sdk", "acme.sdk", "acmesdk"} <= set(names)

    def test_scoped_names(self) -> None:
        names = variants("npm", "@acme/sdk", {"@acme/sdk"})
        # The bare name is not tried: "sdk" is an unrelated package, not an imitation.
        assert "sdk" not in names
        assert {"acme-sdk", "acmesdk", "@acmee/sdk", "@acne/sdk"} <= set(names)
        # Inside the scope only its owner can publish, so those are not tried.
        assert not any(n.startswith("@acme/") for n in names)

    def test_long_names_cover_every_kind(self) -> None:
        name = "acme-protocol-typescript-software-development-kit"
        names = variants("npm", name, {name})
        assert len(names) == packages.MAX_VARIANTS
        assert name.replace("-", "_") in names
        assert name[1:] in names
        assert "a" + name in names


BAD_NAMES = [
    "../../etc/passwd",
    "..",
    ".",
    "acme/../../admin",
    "acme-sdk/../other",
    "acme%2f..%2f..%2fadmin",
    "acme-sdk?write=true",
    "acme-sdk#fragment",
    "acme sdk",
    "acme-sdk\n",
    "acme\r\nHost: evil.example",
    "acme\x00sdk",
    "https://evil.example/pkg",
    "//evil.example/pkg",
    "evil.example/pkg",
    "@evil.example/pkg/extra",
    "@/sdk",
    "@acme/",
    "@acme//sdk",
    "@acme/sdk/latest",
    "acme\\sdk",
    "acme@1.0.0",
    "acme:sdk",
    "_private",
    ".hidden",
    "acmé",
    "\uff41\uff43\uff4d\uff45",  # full-width letters
    "",
    "   ",
    "a" * 300,
]


class TestPackageNames:
    @pytest.mark.parametrize("name", BAD_NAMES)
    def test_bad_names_are_invalid(self, name: str) -> None:
        if name.strip() == "acme-sdk":
            return  # only surrounding space, which is trimmed: see the next test
        assert valid_npm_name(name) is None
        assert valid_pypi_name(name) is None

    def test_surrounding_space_is_trimmed_not_sent(self) -> None:
        assert valid_npm_name("acme-sdk\n") == "acme-sdk"
        assert valid_pypi_name(" acme-sdk ") == "acme-sdk"

    def test_good_names(self) -> None:
        assert valid_npm_name("@acme/sdk") == "@acme/sdk"
        assert valid_npm_name("JSONStream") == "JSONStream"
        assert valid_pypi_name("Acme.SDK_core") == "acme-sdk-core"
        assert valid_npm_name(None) is None
        assert valid_npm_name("evil.example/pkg") is None

    @pytest.mark.parametrize("name", [n for n in BAD_NAMES if n.strip() != "acme-sdk"])
    async def test_refused_before_any_request(self, make_ctx: Any, name: str) -> None:
        # make_ctx without a handler fails the test on any request at all.
        target = Target(root_domain=ROOT, npm_packages=[name], pypi_packages=[name])
        result = await Packages().run(target, make_ctx())
        assert result.status in (ModuleStatus.FAILED, ModuleStatus.SKIPPED)
        assert result.findings == []
        assert "evil.example" not in result.model_dump_json()

    async def test_bad_name_beside_a_good_one(self, make_ctx: Any, registries: Registries) -> None:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        target = npm_target("../../etc/passwd", "acme-sdk")
        result = await Packages().run(target, make_ctx(handler=registries))
        assert result.status is ModuleStatus.PARTIAL
        assert len(by_kind(result, "package.maintainers")) == 1
        assert all(".." not in r.url.raw_path.decode() for r in registries.requests)

    async def test_package_cap(self, make_ctx: Any, registries: Registries) -> None:
        names = [f"acme-package-number-{i}" for i in range(packages.MAX_PACKAGES + 3)]
        result = await Packages().run(npm_target(*names), make_ctx(handler=registries))
        assert result.status is ModuleStatus.PARTIAL
        assert len(by_kind(result, "package.missing")) == packages.MAX_PACKAGES


class TestPackagesBadAnswers:
    @pytest.mark.parametrize(
        "answer",
        [
            "<html>gateway error</html>",
            '{"name": "acme-sdk", "maintainers": [',
            "",
            "[" * 100_000,
            "null",
            "[1, 2, 3]",
            '"just a string"',
        ],
    )
    async def test_malformed_json(self, make_ctx: Any, registries: Registries, answer: str) -> None:
        registries.npm("acme-sdk", answer).pypi("acme-sdk", answer)
        target = Target(root_domain=ROOT, npm_packages=["acme-sdk"], pypi_packages=["acme-sdk"])
        result = await Packages().run(target, make_ctx(handler=registries))
        assert result.status is ModuleStatus.FAILED
        assert result.findings == []
        assert result.skip_reason
        assert "Traceback" not in result.model_dump_json()

    @pytest.mark.parametrize(
        "document",
        [
            {},
            {"maintainers": "alice", "dist-tags": "latest", "time": []},
            {"maintainers": [1, None, [], {"name": 5}], "dist-tags": {"latest": {"x": 1}}},
            {"maintainers": [{"name": "a" * 500}], "time": {"created": "yesterday"}},
            {"dist-tags": {"latest": "1.0.0; rm -rf /"}, "time": {"created": 12345}},
        ],
    )
    async def test_odd_shapes_do_not_crash(
        self, make_ctx: Any, registries: Registries, document: Any
    ) -> None:
        registries.npm("acme-sdk", document)
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.OK
        [finding] = by_kind(result, "package.maintainers")
        assert finding.state["maintainers"] == []
        assert finding.state["latest_version"] == ""

    @pytest.mark.parametrize(
        "document",
        [
            {},
            {"info": "text"},
            {"info": {"version": 3}, "ownership": "x", "releases": "y"},
            {"info": {}, "ownership": {"roles": [1, {"user": None}]}, "releases": {"1": [3]}},
        ],
    )
    async def test_odd_pypi_shapes_do_not_crash(
        self, make_ctx: Any, registries: Registries, document: Any
    ) -> None:
        registries.pypi("acme-sdk", document)
        result = await Packages().run(pypi_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status in (ModuleStatus.OK, ModuleStatus.FAILED)

    @pytest.mark.parametrize("status", [301, 403, 429, 500, 503])
    async def test_error_statuses(self, make_ctx: Any, registries: Registries, status: int) -> None:
        registries.npm(
            "acme-sdk", httpx.Response(status, headers={"location": "https://evil.example/"})
        )
        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.FAILED
        assert f"HTTP {status}" in (result.skip_reason or "")
        assert len(registries.requests) == 1

    async def test_registry_unreachable(self, make_ctx: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("slow")

        result = await Packages().run(npm_target("acme-sdk"), make_ctx(handler=handler))
        assert result.status is ModuleStatus.FAILED
        assert "could not be reached" in (result.skip_reason or "")

    async def test_oversized_answer(
        self, make_ctx: Any, registries: Registries, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_DOCUMENT_BYTES", 10_000)
        registries.pypi("acme-sdk", {"info": {"version": "1"}, "pad": "x" * 50_000})
        result = await Packages().run(pypi_target("acme-sdk"), make_ctx(handler=registries))
        assert result.status is ModuleStatus.FAILED
        assert "sent more than" in (result.skip_reason or "")

    async def test_one_registry_down(self, make_ctx: Any, registries: Registries) -> None:
        registries.npm("acme-sdk", json.loads(fixture_text("packages", "npm_acme-sdk.json")))
        registries.pypi("acme-sdk", httpx.Response(502))
        target = Target(root_domain=ROOT, npm_packages=["acme-sdk"], pypi_packages=["acme-sdk"])
        result = await Packages().run(target, make_ctx(handler=registries))
        assert result.status is ModuleStatus.PARTIAL
        assert [f.kind for f in result.findings] == ["package.maintainers"]


# --------------------------------------------------------------------------
# repo_scorecard
# --------------------------------------------------------------------------

ORG = "acme-protocol"
SCORECARD_HOST = "api.securityscorecards.dev"


class Scorecards:
    """Stands in for the Scorecard API and for GitHub's repository listing."""

    def __init__(self, names: list[str] | None = None) -> None:
        self.names = names
        self.results: dict[str, Any] = {}
        self.requests: list[httpx.Request] = []

    def add(self, full_name: str, answer: Any) -> Scorecards:
        self.results[f"/projects/github.com/{full_name}"] = answer
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.method == "GET"
        assert request.url.scheme == "https"
        if request.url.host == "api.github.com":
            assert request.url.path == f"/orgs/{ORG}/repos"
            if self.names is None:
                return httpx.Response(500)
            return httpx.Response(200, json=[{"full_name": n} for n in self.names])
        assert request.url.host == SCORECARD_HOST, f"unexpected host: {request.url}"
        answer = self.results.get(request.url.path)
        if answer is None:
            return httpx.Response(404, content=b"")
        if isinstance(answer, httpx.Response):
            return answer
        if isinstance(answer, str):
            return httpx.Response(200, content=answer.encode())
        return httpx.Response(200, json=answer)

    @property
    def looked_up(self) -> list[str]:
        return [
            r.url.path.removeprefix("/projects/github.com/")
            for r in self.requests
            if r.url.host == SCORECARD_HOST
        ]


def repo_ctx(
    make_ctx: Any, handler: Any, repos: dict[str, str], *, full_names: bool = False
) -> Any:
    """A context in which github_org has already listed these repositories."""
    ctx = make_ctx(handler=handler)
    assets = [Asset(type=AssetType.GITHUB_ORG, key=ORG, source_module="github_org")]
    for name, pushed in repos.items():
        attributes = {"last_push": pushed, "language": "Solidity"}
        if full_names:
            attributes["full_name"] = name
        assets.append(
            Asset(
                type=AssetType.REPOSITORY,
                key=name.lower(),
                attributes=attributes,
                source_module="github_org",
            )
        )
    ctx.assets.add(ModuleResult(module="github_org", status=ModuleStatus.OK, assets=assets))
    return ctx


ORG_TARGET = Target(root_domain=ROOT, github_org=ORG)
FAILING = json.loads(fixture_text("scorecard", "failing.json"))
PASSING = json.loads(fixture_text("scorecard", "passing.json"))


class TestRepoScorecard:
    def test_spec(self) -> None:
        spec = RepoScorecard.spec
        assert spec.name == "repo_scorecard"
        assert spec.category is Category.SUPPLY_CHAIN
        assert spec.mode is ScanMode.PASSIVE
        assert spec.requires_target == ("github_org",)
        assert spec.depends_on == ("github_org",)

    async def test_failing_checks(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/Core", f"{ORG}/docs"])
        api.add(f"{ORG}/Core", FAILING).add(f"{ORG}/docs", PASSING)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01", f"{ORG}/docs": "2026-08-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "github.repo.scorecard"
        assert finding.asset_type is AssetType.REPOSITORY
        assert finding.asset_key == f"{ORG}/core"
        assert finding.state == {
            "Code-Review": "0-2",
            "Dangerous-Workflow": "0-2",
            "Token-Permissions": "3-4",
        }
        assert finding.identity == {}
        assert finding.evidence["could_not_be_assessed"] == ["Branch-Protection"]
        assert finding.evidence["assessed_on"] == "2026-09-28"
        review = finding.evidence["failing_checks"]["Code-Review"]
        assert review["reason"] == "Found 2/11 approved changesets : score normalized to 2"
        assert review["more"].startswith("https://github.com/ossf/scorecard/")
        assert result.stats == {"repositories": 2, "assessed": 2, "no_data": 0, "failing": 1}

    async def test_dangerous_workflow_raises_severity(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/Core"]).add(f"{ORG}/Core", FAILING)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"})
        [finding] = (await RepoScorecard().run(ORG_TARGET, ctx)).findings
        assert finding.severity is Severity.MEDIUM
        assert finding.severity_note

    async def test_default_severity_without_dangerous_workflow(self, make_ctx: Any) -> None:
        document = json.loads(json.dumps(FAILING))
        for check in document["checks"]:
            if check["name"] == "Dangerous-Workflow":
                check["score"] = 10
        api = Scorecards([f"{ORG}/Core"]).add(f"{ORG}/Core", document)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"})
        [finding] = (await RepoScorecard().run(ORG_TARGET, ctx)).findings
        assert finding.severity is Severity.LOW
        assert "Dangerous-Workflow" not in finding.state

    async def test_overall_score_is_never_shown(self, make_ctx: Any) -> None:
        document = json.loads(json.dumps(FAILING))
        document["score"] = 4.123
        api = Scorecards([f"{ORG}/Core"]).add(f"{ORG}/Core", document)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        text = result.model_dump_json()
        assert "4.123" not in text
        assert "grade" not in text.lower()
        assert "overall" not in text.lower()
        # Checks outside the five that matter are not reported either.
        assert "Signed-Releases" not in text and "CII-Best-Practices" not in text

    async def test_capital_letters_are_recovered_from_github(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/Core", f"{ORG}/unrelated"]).add(f"{ORG}/Core", FAILING)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"})
        await RepoScorecard().run(ORG_TARGET, ctx)
        assert api.looked_up == [f"{ORG}/Core"]

    async def test_no_github_request_when_names_are_known(self, make_ctx: Any) -> None:
        api = Scorecards(None).add(f"{ORG}/Core", FAILING)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"}, full_names=True)
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert [r.url.host for r in api.requests] == [SCORECARD_HOST]
        assert len(result.findings) == 1

    async def test_github_failure_is_explained(self, make_ctx: Any) -> None:
        api = Scorecards(None).add(f"{ORG}/core", PASSING)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/core": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert api.looked_up == [f"{ORG}/core"]
        assert any("capital letters" in n for n in result.notes)

    async def test_no_data_is_not_a_failure(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/core"])
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/core": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert any(f"holds no result for: {ORG}/core" in n for n in result.notes)
        assert result.stats["no_data"] == 1

    async def test_passing_repository_gives_no_finding(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/docs"]).add(f"{ORG}/docs", PASSING)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/docs": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []

    async def test_most_recent_twenty(self, make_ctx: Any) -> None:
        repos = {f"{ORG}/repo-{i:02}": f"2026-01-{i + 1:02}" for i in range(25)}
        api = Scorecards(list(repos))
        result = await RepoScorecard().run(ORG_TARGET, repo_ctx(make_ctx, api, repos))
        assert api.looked_up == [f"{ORG}/repo-{i:02}" for i in range(24, 4, -1)]
        assert result.status is ModuleStatus.PARTIAL
        assert any("20 most recently updated" in n for n in result.notes)

    async def test_small_score_changes_do_not_change_state(self, make_ctx: Any) -> None:
        hashes = []
        for score in (0, 1, 2, 3):
            document = json.loads(json.dumps(FAILING))
            for check in document["checks"]:
                if check["name"] == "Code-Review":
                    check["score"] = score
                    check["reason"] = f"Found {score}/11 approved changesets"
            document["date"] = f"2026-09-{score + 1:02}"
            api = Scorecards([f"{ORG}/Core"]).add(f"{ORG}/Core", document)
            ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"})
            [finding] = (await RepoScorecard().run(ORG_TARGET, ctx)).findings
            hashes.append(finding_state_hash(finding))
        assert hashes[0] == hashes[1] == hashes[2] != hashes[3]

    async def test_reason_text_is_capped(self, make_ctx: Any) -> None:
        document = json.loads(json.dumps(FAILING))
        for check in document["checks"]:
            check["reason"] = "very long " * 10_000
            check["documentation"] = {"url": "https://evil.example/" + "a" * 5_000}
        api = Scorecards([f"{ORG}/Core"]).add(f"{ORG}/Core", document)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/Core": "2026-09-01"})
        [finding] = (await RepoScorecard().run(ORG_TARGET, ctx)).findings
        for entry in finding.evidence["failing_checks"].values():
            assert len(entry["reason"]) <= repo_scorecard.MAX_REASON_CHARS
            assert entry["more"] == ""
        assert "evil.example" not in finding.model_dump_json()

    @pytest.mark.parametrize(
        "answer",
        [
            "<html>bad gateway</html>",
            '{"checks": [',
            "",
            "null",
            "[]",
            '{"checks": "none"}',
            "[" * 100_000,
        ],
    )
    async def test_malformed_answers(self, make_ctx: Any, answer: str) -> None:
        api = Scorecards([f"{ORG}/core"]).add(f"{ORG}/core", answer)
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/core": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert result.skip_reason
        assert result.findings == []

    @pytest.mark.parametrize(
        "checks",
        [
            [None, 1, "x", [], {}],
            [{"name": "Code-Review"}],
            [{"name": "Code-Review", "score": "0"}],
            [{"name": "Code-Review", "score": True}],
            [{"name": "Code-Review", "score": None, "reason": {"a": 1}}],
            [{"name": ["Code-Review"], "score": 0}],
            [{"name": "Code-Review", "score": 99}],
            [{"name": "Code-Review", "score": float("nan")}],
        ],
    )
    def test_odd_checks_are_not_failures(self, checks: Any) -> None:
        state, evidence, _ = failing_checks({"checks": checks})
        assert state == {} and evidence == {}

    async def test_server_error(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/core"]).add(f"{ORG}/core", httpx.Response(503))
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/core": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert "HTTP 503" in (result.skip_reason or "")

    async def test_redirect_is_not_followed(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/core"]).add(
            f"{ORG}/core", httpx.Response(302, headers={"location": "https://evil.example/"})
        )
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/core": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert len(api.looked_up) == 1

    async def test_partial_when_some_fail(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/a", f"{ORG}/b"])
        api.add(f"{ORG}/a", FAILING).add(f"{ORG}/b", httpx.Response(500))
        ctx = repo_ctx(make_ctx, api, {f"{ORG}/a": "2026-09-02", f"{ORG}/b": "2026-09-01"})
        result = await RepoScorecard().run(ORG_TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert [f.asset_key for f in result.findings] == [f"{ORG}/a"]

    async def test_stops_at_the_request_limit(self, make_ctx: Any) -> None:
        api = Scorecards([f"{ORG}/a", f"{ORG}/b", f"{ORG}/c"])
        api.add(f"{ORG}/a", PASSING).add(f"{ORG}/b", httpx.Response(429))
        repos = {f"{ORG}/a": "2026-09-03", f"{ORG}/b": "2026-09-02", f"{ORG}/c": "2026-09-01"}
        result = await RepoScorecard().run(ORG_TARGET, repo_ctx(make_ctx, api, repos))
        assert api.looked_up == [f"{ORG}/a", f"{ORG}/b"]
        assert result.status is ModuleStatus.PARTIAL

    async def test_hostile_repository_names_are_refused(self, make_ctx: Any) -> None:
        repos = {
            f"{ORG}/../../admin": "2026-09-09",
            f"{ORG}/..": "2026-09-09",
            f"{ORG}/a?x=1": "2026-09-09",
            f"{ORG}/a#b": "2026-09-09",
            f"{ORG}/a b": "2026-09-09",
            f"{ORG}/a%2f..%2fb": "2026-09-09",
            "evil-org/core": "2026-09-09",
            f"{ORG}": "2026-09-09",
            f"{ORG}/good": "2026-09-01",
        }
        api = Scorecards([f"{ORG}/good", "evil-org/core", f"{ORG}/../x"])
        await RepoScorecard().run(ORG_TARGET, repo_ctx(make_ctx, api, repos))
        assert api.looked_up == [f"{ORG}/good"]

    async def test_skipped_when_repositories_were_not_listed(self, make_ctx: Any) -> None:
        result = await RepoScorecard().run(ORG_TARGET, make_ctx())
        assert result.status is ModuleStatus.SKIPPED

    async def test_no_repositories(self, make_ctx: Any) -> None:
        result = await RepoScorecard().run(ORG_TARGET, repo_ctx(make_ctx, None, {}))
        assert result.status is ModuleStatus.OK
        assert result.findings == []

    def test_buckets(self) -> None:
        assert [bucket(s) for s in (0, 1, 2, 2.9)] == ["0-2"] * 4
        assert [bucket(s) for s in (3, 4, 4.9)] == ["3-4"] * 3
        assert [bucket(s) for s in (5, 10, -1, None, "3", True)] == [None] * 6

    def test_repo_parts(self) -> None:
        assert repo_parts("acme/Core.js") == ("acme", "Core.js")
        for bad in ("acme", "acme/a/b", "acme/..", "acme/.", "-acme/x", "acme/", "/x", 5, None):
            assert repo_parts(bad) is None
