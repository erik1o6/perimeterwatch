"""The security.txt check.

All HTTP is served by a local stand-in. Nothing here touches the network.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from perimeterwatch.core.fingerprint import finding_fingerprint, finding_state_hash
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Sensitivity,
    Severity,
    Target,
)
from perimeterwatch.core.severity import change_severity
from perimeterwatch.modules import security_contact as module
from perimeterwatch.modules.security_contact import (
    LEGACY,
    WELL_KNOWN,
    SecurityContact,
    is_role_address,
    mail_address,
    parse_expiry,
    parse_file,
    strip_signature,
    web_address,
)
from tests.conftest import ROOT, fixture_text
from tests.helpers import resolved

TARGET = Target(root_domain=ROOT)
WWW = f"www.{ROOT}"
PUBLIC_IP = "93.184.216.34"
KEY = b"k" * 32

SCRIPT = "<script>alert(1)</script>"
FUTURE = "2099-01-01T00:00:00Z"
PAST = "2001-01-01T00:00:00Z"


class FakeStream:
    def __init__(self, address: str) -> None:
        self.address = address

    def get_extra_info(self, name: str) -> Any:
        return (self.address, 443) if name == "server_addr" else None


class Site:
    """Serves files by host and path, and records every request."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.requests: list[httpx.Request] = []

    def add(self, path: str, answer: Any, *, host: str = ROOT) -> Site:
        self.routes[(host, path)] = answer
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get((request.url.host, request.url.path))
        if answer is None:
            return httpx.Response(404, text="Not Found", headers={"content-type": "text/plain"})
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, httpx.Response):
            return answer
        return plain(answer)

    def asked(self) -> list[tuple[str, str]]:
        return [(r.url.host, r.url.path) for r in self.requests]


def plain(body: str | bytes, content_type: str = "text/plain; charset=utf-8") -> httpx.Response:
    return httpx.Response(200, content=body, headers={"content-type": content_type})


def redirect(location: str, status: int = 301) -> httpx.Response:
    return httpx.Response(status, headers={"location": location})


def file_with(*lines: str) -> str:
    return "".join(f"{line}\n" for line in lines)


def web_ctx(make_ctx: Any, handler: Any, hosts: dict[str, list[str]] | None = None) -> Any:
    ctx = make_ctx(mode=ScanMode.PROBE, handler=handler)
    if hosts is None:
        hosts = {ROOT: [PUBLIC_IP], WWW: [PUBLIC_IP]}
    ctx.assets.add(resolved(hosts, root=ROOT))
    return ctx


async def scan(make_ctx: Any, handler: Any, **kwargs: Any) -> ModuleResult:
    return await SecurityContact().run(TARGET, web_ctx(make_ctx, handler, **kwargs))


def kinds(result: ModuleResult) -> list[str]:
    return sorted(f.kind for f in result.findings)


def details(result: ModuleResult) -> Finding:
    [finding] = [f for f in result.findings if f.kind == "security.contact.details"]
    return finding


class TestSpec:
    def test_spec(self) -> None:
        spec = SecurityContact.spec
        assert spec.name == "security_contact"
        assert spec.category is Category.SURFACE
        assert spec.mode is ScanMode.PROBE
        assert spec.depends_on == ("dns_resolve",)
        assert not spec.requires_verification
        assert not spec.requires_keys
        assert not spec.requires_binaries
        assert spec.contacts

    def test_a_change_of_details_raises_an_alert(self) -> None:
        assert change_severity("security.contact.details", Severity.INFO) is Severity.MEDIUM


class TestFileFound:
    async def test_valid_file(self, make_ctx: Any) -> None:
        site = Site().add(WELL_KNOWN, fixture_text("security_txt", "valid.txt"))
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        assert kinds(result) == ["security.contact.details"]
        finding = details(result)
        assert finding.severity is Severity.INFO
        assert finding.category is Category.SURFACE
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.sensitivity is Sensitivity.NORMAL
        assert finding.asset_type is AssetType.DOMAIN
        assert finding.asset_key == ROOT
        assert finding.identity == {}
        assert finding.state == {
            "contacts": [
                f"https://bounty.{ROOT}/report",
                f"mailto:abuse@{ROOT}",
                f"mailto:security@{ROOT}",
            ],
            "policy": [f"https://{ROOT}/security/policy"],
            "canonical": [f"https://{ROOT}/.well-known/security.txt"],
        }
        evidence = finding.evidence
        assert evidence["contacts_in_order_of_preference"] == [
            f"https://bounty.{ROOT}/report",
            f"mailto:security@{ROOT}",
            f"mailto:abuse@{ROOT}",
        ]
        assert evidence["policy"] == finding.state["policy"]
        assert evidence["canonical"] == finding.state["canonical"]
        assert evidence["expires"] == "2099-04-01"
        assert evidence["encryption_key"] == [f"https://{ROOT}/.well-known/pgp-key.txt"]
        assert evidence["preferred_languages"] == ["en", "de-ch"]
        assert evidence["location_used"] == WELL_KNOWN
        assert evidence["address"] == f"https://{ROOT}{WELL_KNOWN}"
        assert "signed" not in evidence
        assert site.asked() == [(ROOT, WELL_KNOWN)]

    async def test_one_plain_get_and_nothing_else(self, make_ctx: Any) -> None:
        site = Site().add(WELL_KNOWN, fixture_text("security_txt", "valid.txt"))
        await scan(make_ctx, site)
        [request] = site.requests
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.query == b""
        assert request.content == b""

    async def test_rate_limiter_is_used_for_every_request(self, make_ctx: Any) -> None:
        site = Site().add(LEGACY, file_with(f"Contact: mailto:security@{ROOT}"))
        ctx = web_ctx(make_ctx, site)
        waited: list[str] = []
        original = ctx.limiter.acquire

        async def acquire(host: str) -> None:
            waited.append(host)
            await original(host)

        ctx.limiter.acquire = acquire
        await SecurityContact().run(TARGET, ctx)
        assert waited == [ROOT, ROOT]
        assert len(site.requests) == 2

    async def test_signed_file(self, make_ctx: Any) -> None:
        site = Site().add(WELL_KNOWN, fixture_text("security_txt", "signed.txt"))
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        finding = details(result)
        # Lines inside the signature block are not read as part of the file.
        assert finding.state["contacts"] == [f"mailto:psirt@{ROOT}"]
        assert finding.evidence["expires"] == "2099-12-31"
        assert "signature was not verified" in finding.evidence["signed"]
        assert "attacker" not in result.model_dump_json()

    async def test_field_names_in_any_case_and_comments(self, make_ctx: Any) -> None:
        body = file_with(
            "\ufeff# Contact: mailto:hidden@elsewhere.net",
            "   # Expires: 2001-01-01T00:00:00Z",
            f"CONTACT: mailto:security@{ROOT}",
            f"expires : {FUTURE}",
            f"pOlIcY:https://{ROOT}/policy",
            "X-Unknown-Field: kept out",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body.replace("\n", "\r\n")))
        assert kinds(result) == ["security.contact.details"]
        finding = details(result)
        assert finding.state["contacts"] == [f"mailto:security@{ROOT}"]
        assert finding.state["policy"] == [f"https://{ROOT}/policy"]
        assert "hidden" not in result.model_dump_json()
        assert "kept out" not in result.model_dump_json()

    async def test_several_contact_lines(self, make_ctx: Any) -> None:
        body = file_with(
            f"Contact: mailto:security@{ROOT}",
            "Contact: tel:+44-20-7946-0000",
            f"Contact: https://{ROOT}/report",
            f"Contact: mailto:security@{ROOT}",
            "Contact: http://plain.example.net/report",
            "Contact: ftp://files.example.net/",
            "Contact: security at acme dot xyz",
            f"Contact: javascript:alert(1)//{ROOT}",
            f"Contact: https://user:secret@{ROOT}/report",
            "Contact: https://203.0.113.7/report",
            f"Contact: mailto:{SCRIPT}@{ROOT}",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        finding = details(result)
        assert finding.evidence["contacts_in_order_of_preference"] == [
            f"mailto:security@{ROOT}",
            "tel:+44-20-7946-0000",
            f"https://{ROOT}/report",
        ]
        assert finding.state["contacts"] == sorted(
            finding.evidence["contacts_in_order_of_preference"]
        )
        assert finding.evidence["lines_that_could_not_be_read"] == 7
        text = result.model_dump_json()
        for bad in ("<", "javascript", "secret", "203.0.113.7", "ftp:", "http://"):
            assert bad not in text

    async def test_contact_lines_are_capped(
        self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(module, "MAX_CONTACTS", 3)
        lines = [f"Contact: https://{ROOT}/report/{i}" for i in range(9)]
        result = await scan(
            make_ctx, Site().add(WELL_KNOWN, file_with(*lines, f"Expires: {FUTURE}"))
        )
        assert len(details(result).state["contacts"]) == 3

    async def test_expired(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {PAST}")
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert result.status is ModuleStatus.OK
        assert kinds(result) == ["security.contact.details", "security.contact.expired"]
        [expired] = [f for f in result.findings if f.kind == "security.contact.expired"]
        assert expired.severity is Severity.LOW
        assert expired.evidence["expired_on"] == "2001-01-01"
        assert "2001-01-01" in expired.title
        # Nothing that changes from day to day is part of what is compared.
        assert expired.state == {}
        assert details(result).evidence["expires"] == "2001-01-01"

    async def test_expiry_is_compared_with_the_time_of_the_scan(
        self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", "Expires: 2030-06-01T12:00:00+02:00")
        site = Site().add(WELL_KNOWN, body)
        monkeypatch.setattr(module, "utcnow", lambda: datetime(2030, 6, 1, 9, 59, tzinfo=UTC))
        assert kinds(await scan(make_ctx, site)) == ["security.contact.details"]
        monkeypatch.setattr(module, "utcnow", lambda: datetime(2030, 6, 1, 10, 1, tzinfo=UTC))
        assert "security.contact.expired" in kinds(await scan(make_ctx, site))

    async def test_several_expires_lines(self, make_ctx: Any) -> None:
        body = file_with(
            f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}", f"Expires: {PAST}"
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert kinds(result) == ["security.contact.details"]
        assert any("2 Expires lines" in n for n in result.notes)


class TestFileMissingOrInvalid:
    async def test_missing_at_both_locations(self, make_ctx: Any) -> None:
        site = Site()
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "security.contact.missing"
        assert finding.severity is Severity.LOW
        assert finding.asset_key == ROOT
        assert finding.evidence["locations_tried"] == [
            {"location": WELL_KNOWN, "answer": "HTTP 404"},
            {"location": LEGACY, "answer": "HTTP 404"},
        ]
        assert site.asked() == [(ROOT, WELL_KNOWN), (ROOT, LEGACY)]

    async def test_gone_counts_as_missing(self, make_ctx: Any) -> None:
        site = Site()
        site.add(WELL_KNOWN, httpx.Response(410)).add(LEGACY, httpx.Response(410))
        assert kinds(await scan(make_ctx, site)) == ["security.contact.missing"]

    @pytest.mark.parametrize(
        "content_type", ["text/html; charset=utf-8", "text/plain", "application/octet-stream", ""]
    )
    async def test_web_page_served_at_the_path(self, make_ctx: Any, content_type: str) -> None:
        page = fixture_text("security_txt", "page.html")
        site = Site().add(WELL_KNOWN, lambda _r: plain(page, content_type))
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "security.contact.missing"
        assert "web page" in finding.evidence["what_was_found"]
        # The older location is asked for only after a 404.
        assert site.asked() == [(ROOT, WELL_KNOWN)]
        assert "<" not in result.model_dump_json()

    async def test_web_page_without_markup_at_the_start(self, make_ctx: Any) -> None:
        site = Site().add(WELL_KNOWN, plain("Welcome to Acme <b>Protocol</b>", "text/html"))
        assert kinds(await scan(make_ctx, site)) == ["security.contact.missing"]

    async def test_the_file_served_with_the_wrong_type_is_still_read(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")
        site = Site().add(WELL_KNOWN, plain(body, "text/html"))
        assert kinds(await scan(make_ctx, site)) == ["security.contact.details"]

    async def test_missing_contact(self, make_ctx: Any) -> None:
        body = file_with(f"Expires: {FUTURE}", f"Policy: https://{ROOT}/policy")
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "security.contact.invalid"
        assert finding.severity is Severity.LOW
        assert finding.state == {"missing": ["Contact"]}
        assert "Contact" in finding.title
        assert "Expires" not in finding.title

    async def test_missing_expires(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}")
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        [finding] = result.findings
        assert finding.kind == "security.contact.invalid"
        assert finding.state == {"missing": ["Expires"]}
        assert finding.evidence["contact_lines_read"] == 1

    async def test_empty_file(self, make_ctx: Any) -> None:
        result = await scan(make_ctx, Site().add(WELL_KNOWN, ""))
        [finding] = result.findings
        assert finding.kind == "security.contact.invalid"
        assert finding.state == {"missing": ["Contact", "Expires"]}

    @pytest.mark.parametrize(
        "value",
        [
            "tomorrow",
            "2099-01-01",
            "2099-01-01T00:00:00",
            "2099-13-01T00:00:00Z",
            "2099-02-30T00:00:00Z",
            "2099-01-01T25:00:00Z",
            "2099-01-01T00:00:00+99:00",
            "01/01/2099",
            "4102444800",
            "2099-01-01T00:00:00Z; drop table",
            "9" * 400,
            SCRIPT,
            "",
        ],
    )
    async def test_malformed_dates(self, make_ctx: Any, value: str) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {value}")
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "security.contact.invalid"
        assert finding.state == {"missing": ["Expires"]}
        assert finding.evidence["expires_lines_found"] == 1
        assert "<" not in result.model_dump_json()
        assert "drop table" not in result.model_dump_json()

    async def test_very_long_lines(self, make_ctx: Any) -> None:
        body = file_with(
            "Contact: mailto:" + "a" * 100_000 + f"@{ROOT}",
            f"Contact: https://{ROOT}/" + "b" * 600,
            "c" * 20_000,
            f"Contact: mailto:security@{ROOT}",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert result.status is ModuleStatus.PARTIAL  # larger than the 32 KB that is read
        assert result.findings == []
        assert "a" * 50 not in result.model_dump_json()

        body = file_with(
            "Contact: mailto:" + "a" * 3_000 + f"@{ROOT}",
            f"Contact: https://{ROOT}/" + "b" * 600,
            "c" * 5_000,
            f"Contact: mailto:security@{ROOT}",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert result.status is ModuleStatus.OK
        assert details(result).state["contacts"] == [f"mailto:security@{ROOT}"]
        assert details(result).evidence["lines_that_could_not_be_read"] == 3
        for bad in ("a" * 50, "b" * 50, "c" * 50):
            assert bad not in result.model_dump_json()

    async def test_large_file_is_read_in_part(self, make_ctx: Any) -> None:
        body = file_with(
            f"Contact: mailto:security@{ROOT}",
            f"Expires: {FUTURE}",
            *("# padding " + "x" * 80 for _ in range(1_000)),
            f"Contact: mailto:late@{ROOT}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert result.status is ModuleStatus.PARTIAL
        assert details(result).state["contacts"] == [f"mailto:security@{ROOT}"]
        assert details(result).evidence["read_in_part"] is True
        assert any("32 KB" in n for n in result.notes)

    async def test_too_many_lines(self, make_ctx: Any) -> None:
        body = file_with(
            *("junk" for _ in range(1_500)),
            f"Contact: mailto:security@{ROOT}",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert kinds(result) == ["security.contact.invalid"]

    @pytest.mark.parametrize(
        "body",
        [
            b"\x00\x01\x02\xff\xfe" * 500,
            b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 20,
            b"\x1f\x8b\x08\x00" + b"\xff" * 2_000,
            b"Contact: mailto:\xff\xfe@acme-protocol.xyz\nExpires: \x00\n",
        ],
    )
    async def test_binary_content(self, make_ctx: Any, body: bytes) -> None:
        site = Site().add(WELL_KNOWN, plain(body, "application/octet-stream"))
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "security.contact.invalid"
        assert finding.evidence["is_plain_text"] is False
        text = result.model_dump_json()
        assert "\\u0000" not in text
        assert "\ufffd" not in text
        assert "PNG" not in text


class TestLocations:
    async def test_legacy_location(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")
        site = Site().add(LEGACY, body)
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        finding = details(result)
        assert "older location" in finding.evidence["location_used"]
        assert finding.evidence["address"] == f"https://{ROOT}{LEGACY}"
        assert any("older location" in n for n in result.notes)
        assert site.asked() == [(ROOT, WELL_KNOWN), (ROOT, LEGACY)]

    @pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
    async def test_legacy_location_is_used_only_after_a_404(
        self, make_ctx: Any, status: int
    ) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")
        site = Site().add(WELL_KNOWN, httpx.Response(status)).add(LEGACY, body)
        result = await scan(make_ctx, site)
        # Not knowing is not the same as the file being absent.
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert any(f"HTTP {status}" in n and "not re-checked" in n for n in result.notes)
        assert site.asked() == [(ROOT, WELL_KNOWN)]

    async def test_unreachable(self, make_ctx: Any) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        result = await scan(make_ctx, Site().add(WELL_KNOWN, down))
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert any("ConnectError" in n for n in result.notes)

    @pytest.mark.parametrize(
        "location",
        [
            "https://evil-host.net/.well-known/security.txt",
            "//evil-host.net/security.txt",
            f"https://{ROOT}.evil-host.net/security.txt",
            f"https://www.{ROOT}.evil-host.net/security.txt",
            f"https://wwww.{ROOT}/security.txt",
            f"https://docs.{ROOT}/security.txt",
            f"http://{ROOT}/.well-known/security.txt",
            f"http://www.{ROOT}/.well-known/security.txt",
            f"https://www.{ROOT}:8443/.well-known/security.txt",
            f"https://{ROOT}@evil-host.net/security.txt",
            "https://169.254.169.254/latest/meta-data/",
        ],
    )
    async def test_redirect_to_another_host_is_not_followed(
        self, make_ctx: Any, location: str
    ) -> None:
        site = Site().add(WELL_KNOWN, redirect(location))
        hosts = {ROOT: [PUBLIC_IP], WWW: [PUBLIC_IP], f"docs.{ROOT}": [PUBLIC_IP]}
        result = await scan(make_ctx, site, hosts=hosts)
        assert site.asked() == [(ROOT, WELL_KNOWN)]
        assert all(r.url.scheme == "https" and r.url.port is None for r in site.requests)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert any("redirects to another host are not followed" in n for n in result.notes)

    @pytest.mark.parametrize("status", [301, 302, 307, 308])
    async def test_redirect_to_www_of_the_same_domain_is_followed(
        self, make_ctx: Any, status: int
    ) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")
        site = Site()
        site.add(WELL_KNOWN, redirect(f"https://{WWW}{WELL_KNOWN}", status))
        site.add(WELL_KNOWN, body, host=WWW)
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.OK
        assert site.asked() == [(ROOT, WELL_KNOWN), (WWW, WELL_KNOWN)]
        finding = details(result)
        assert finding.asset_key == ROOT
        assert finding.evidence["address"] == f"https://{WWW}{WELL_KNOWN}"

    async def test_redirect_to_www_is_not_followed_when_www_did_not_qualify(
        self, make_ctx: Any
    ) -> None:
        site = Site().add(WELL_KNOWN, redirect(f"https://{WWW}{WELL_KNOWN}"))
        for hosts in ({ROOT: [PUBLIC_IP]}, {ROOT: [PUBLIC_IP], WWW: ["10.0.0.5"]}):
            result = await scan(make_ctx, site, hosts=hosts)
            assert result.status is ModuleStatus.PARTIAL
            assert result.findings == []
        assert site.asked() == [(ROOT, WELL_KNOWN), (ROOT, WELL_KNOWN)]

    async def test_redirect_from_www_onward_is_not_followed(self, make_ctx: Any) -> None:
        site = Site()
        site.add(WELL_KNOWN, redirect(f"https://{WWW}{WELL_KNOWN}"))
        site.add(WELL_KNOWN, redirect("https://evil-host.net/security.txt"), host=WWW)
        result = await scan(make_ctx, site)
        assert site.asked() == [(ROOT, WELL_KNOWN), (WWW, WELL_KNOWN)]
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_redirect_on_the_same_host_is_followed(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")
        site = Site()
        site.add(WELL_KNOWN, redirect("/static/security/security.txt", 302))
        site.add("/static/security/security.txt", body)
        result = await scan(make_ctx, site)
        assert kinds(result) == ["security.contact.details"]
        assert details(result).evidence["address"] == (
            f"https://{ROOT}/static/security/security.txt"
        )

    async def test_endless_redirects_stop(self, make_ctx: Any) -> None:
        site = Site().add(WELL_KNOWN, redirect(WELL_KNOWN))
        result = await scan(make_ctx, site)
        assert result.status is ModuleStatus.PARTIAL
        assert len(site.requests) == 4
        assert any("too many times" in n for n in result.notes)


class TestSafety:
    async def test_without_the_dns_check_nothing_is_asked(self, make_ctx: Any) -> None:
        result = await SecurityContact().run(TARGET, make_ctx(mode=ScanMode.PROBE))
        assert result.status is ModuleStatus.SKIPPED

    @pytest.mark.parametrize(
        "hosts",
        [
            {},
            {ROOT: []},
            {WWW: [PUBLIC_IP]},
            {ROOT: ["10.0.0.5"]},
            {ROOT: [PUBLIC_IP, "127.0.0.1"]},
            {ROOT: ["169.254.169.254"]},
            {ROOT: ["::1"]},
        ],
    )
    async def test_host_not_contactable(self, make_ctx: Any, hosts: dict[str, list[str]]) -> None:
        # No handler: any request at all fails the test.
        result = await scan(make_ctx, None, hosts=hosts)
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        [note] = result.notes
        assert "was not asked" in note
        assert result.stats == {"requests": 0}

    @pytest.mark.parametrize("entry", [ROOT, "xyz", PUBLIC_IP, "93.184.216.0/24"])
    async def test_host_on_the_do_not_contact_list(
        self, make_ctx: Any, settings: Any, entry: str
    ) -> None:
        settings.never_contact = [entry]
        result = await scan(make_ctx, None)
        assert result.findings == []
        assert any("do-not-contact" in n for n in result.notes)

    async def test_www_on_the_do_not_contact_list_is_not_followed_to(
        self, make_ctx: Any, settings: Any
    ) -> None:
        settings.never_contact = [WWW]
        site = Site().add(WELL_KNOWN, redirect(f"https://{WWW}{WELL_KNOWN}"))
        result = await scan(make_ctx, site)
        assert site.asked() == [(ROOT, WELL_KNOWN)]
        assert result.findings == []

    @pytest.mark.parametrize("address", ["10.1.2.3", "127.0.0.1", "169.254.169.254", "::1"])
    async def test_answer_from_a_private_address_is_discarded(
        self, make_ctx: Any, address: str
    ) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=body,
                headers={"content-type": "text/plain"},
                extensions={"network_stream": FakeStream(address)},
            )

        result = await scan(make_ctx, handler)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert any("non-public address" in n for n in result.notes)

    async def test_missing_answer_from_a_private_address_is_discarded(self, make_ctx: Any) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, extensions={"network_stream": FakeStream("10.1.2.3")})

        result = await scan(make_ctx, handler)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_answer_from_a_public_address_is_kept(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=body, extensions={"network_stream": FakeStream(PUBLIC_IP)}
            )

        assert kinds(await scan(make_ctx, handler)) == ["security.contact.details"]

    async def test_hostile_values_never_reach_findings(self, make_ctx: Any) -> None:
        body = file_with(
            f"Contact: mailto:security@{ROOT}",
            f"Contact: https://{ROOT}/report?next={SCRIPT}",
            f'Contact: https://{ROOT}/"onmouseover="alert(1)',
            f"Contact: https://{ROOT}/report\x1b[31m",
            f"Policy: https://{ROOT}/policy'--",
            f"Canonical: https://{SCRIPT}.{ROOT}/",
            "Canonical: https://-leading-dash.example.net/",
            f"Encryption: {SCRIPT}",
            "Encryption: openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F",
            f"Preferred-Languages: en, {SCRIPT}, fr, " + "x" * 300,
            f"{SCRIPT}: mailto:security@{ROOT}",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        finding = details(result)
        assert finding.state == {
            "contacts": [f"mailto:security@{ROOT}"],
            "policy": [],
            "canonical": [],
        }
        assert finding.evidence["encryption_key"] == [
            "openpgp4fpr:5F2DE5521C63A801AB59CCB603D49DE44B29100F"
        ]
        assert finding.evidence["preferred_languages"] == ["en", "fr"]
        text = result.model_dump_json()
        for bad in ("<", "alert", "onmouseover", "\\u001b", "--", "leading-dash", "xxxx"):
            assert bad not in text


class TestPeople:
    @pytest.mark.parametrize(
        "local",
        [
            "security",
            "Security",
            "abuse",
            "psirt",
            "cert",
            "soc",
            "bugs",
            "bugbounty",
            "disclosure",
            "vuln",
            "infosec",
            "hello",
            "contact",
            "admin",
            "support",
            "security-team",
            "security.reports",
            "vuln-reports",
            "security+bounty",
            "security2",
            "it-security",
        ],
    )
    def test_role_addresses(self, local: str) -> None:
        assert is_role_address(local)

    @pytest.mark.parametrize(
        "local",
        [
            "jane.doe",
            "jdoe",
            "j.doe+security",
            "jane.security",
            "security.jane",
            "securityjane",
            "team",
            "reports",
            "ceo",
            "secure",
            "12345",
            "",
        ],
    )
    def test_addresses_that_may_name_a_person(self, local: str) -> None:
        assert not is_role_address(local)

    async def test_role_contacts_are_not_personal(self, make_ctx: Any) -> None:
        body = file_with(
            f"Contact: mailto:security@{ROOT}",
            f"Contact: mailto:bugbounty@{ROOT}",
            f"Contact: https://{ROOT}/people/jane-doe",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert details(result).sensitivity is Sensitivity.NORMAL

    async def test_personal_contact_is_kept_and_marked(self, make_ctx: Any) -> None:
        body = file_with(
            f"Contact: mailto:security@{ROOT}",
            f"Contact: mailto:Jane.Doe@{ROOT}?subject=Report",
            f"Expires: {FUTURE}",
        )
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        finding = details(result)
        # The address is kept as published, and marked so that lists mask it.
        assert finding.sensitivity is Sensitivity.PERSONAL
        assert finding.state["contacts"] == [f"mailto:Jane.Doe@{ROOT}", f"mailto:security@{ROOT}"]

    async def test_only_the_finding_that_shows_contacts_is_personal(self, make_ctx: Any) -> None:
        body = file_with(f"Contact: mailto:jane.doe@{ROOT}", f"Expires: {PAST}")
        result = await scan(make_ctx, Site().add(WELL_KNOWN, body))
        assert details(result).sensitivity is Sensitivity.PERSONAL
        [expired] = [f for f in result.findings if f.kind == "security.contact.expired"]
        assert expired.sensitivity is Sensitivity.NORMAL
        assert "jane" not in expired.model_dump_json()

        result = await scan(
            make_ctx, Site().add(WELL_KNOWN, file_with(f"Contact: mailto:jane.doe@{ROOT}"))
        )
        [invalid] = result.findings
        assert invalid.sensitivity is Sensitivity.NORMAL
        assert "jane" not in invalid.model_dump_json()


class TestChanges:
    async def details_for(self, make_ctx: Any, *lines: str) -> Finding:
        result = await scan(make_ctx, Site().add(WELL_KNOWN, file_with(*lines)))
        return details(result)

    async def test_changed_contact_changes_state_but_not_identity(self, make_ctx: Any) -> None:
        before = await self.details_for(
            make_ctx, f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}"
        )
        after = await self.details_for(
            make_ctx, "Contact: mailto:security@evil-host.net", f"Expires: {FUTURE}"
        )
        assert finding_fingerprint(ROOT, before, KEY) == finding_fingerprint(ROOT, after, KEY)
        assert finding_state_hash(before) != finding_state_hash(after)

    @pytest.mark.parametrize(
        "changed",
        [
            "Contact: https://evil-host.net/report",
            "Policy: https://evil-host.net/policy",
            "Canonical: https://evil-host.net/.well-known/security.txt",
        ],
    )
    async def test_added_contact_policy_or_canonical_changes_state(
        self, make_ctx: Any, changed: str
    ) -> None:
        lines = [f"Contact: mailto:security@{ROOT}", f"Expires: {FUTURE}"]
        before = await self.details_for(make_ctx, *lines)
        after = await self.details_for(make_ctx, *lines, changed)
        assert finding_fingerprint(ROOT, before, KEY) == finding_fingerprint(ROOT, after, KEY)
        assert finding_state_hash(before) != finding_state_hash(after)

    async def test_what_does_not_matter_leaves_state_alone(self, make_ctx: Any) -> None:
        before = await self.details_for(
            make_ctx,
            f"Contact: mailto:security@{ROOT}",
            f"Contact: https://{ROOT}/report",
            f"Expires: {FUTURE}",
        )
        later = (datetime.now(UTC) + timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        after = await self.details_for(
            make_ctx,
            "# Renewed, reordered, and with more about how to write to us.",
            f"expires: {later}",
            f"Contact: https://{ROOT}/report",
            f"Contact: mailto:security@{ROOT}",
            "Preferred-Languages: en",
            f"Encryption: https://{ROOT}/key.txt",
        )
        assert finding_state_hash(before) == finding_state_hash(after)
        assert finding_fingerprint(ROOT, before, KEY) == finding_fingerprint(ROOT, after, KEY)


class TestParsing:
    def test_signature_is_stripped_and_dashes_restored(self) -> None:
        text, signed = strip_signature(fixture_text("security_txt", "signed.txt"))
        assert signed
        assert "PGP" not in text
        assert "Hash:" not in text
        assert "-----------------------------------------" in text.splitlines()
        assert "attacker" not in text

    def test_unsigned_text_is_left_alone(self) -> None:
        assert strip_signature("Contact: mailto:a@b.net\n") == ("Contact: mailto:a@b.net\n", False)

    def test_signature_that_never_ends(self) -> None:
        parsed = parse_file(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            f"Contact: mailto:security@{ROOT}\nExpires: {FUTURE}\n"
        )
        assert parsed.signed
        assert parsed.contacts == [f"mailto:security@{ROOT}"]
        assert parsed.missing == []

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2030-01-02T03:04:05Z", datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)),
            ("2030-01-02t03:04:05z", datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)),
            ("2030-01-02T03:04:05.123Z", datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)),
            ("2030-01-02T03:04:05+02:00", datetime(2030, 1, 2, 1, 4, 5, tzinfo=UTC)),
            ("2030-01-02T03:04:05-08:00", datetime(2030, 1, 2, 11, 4, 5, tzinfo=UTC)),
        ],
    )
    def test_dates(self, value: str, expected: datetime) -> None:
        assert parse_expiry(value) == expected

    def test_addresses(self) -> None:
        assert web_address(f"https://{ROOT}/a?b=c#d") == f"https://{ROOT}/a?b=c#d"
        assert web_address(f"HTTPS://{ROOT}/") is None
        assert web_address(f"https://{ROOT}:99999/") is None
        assert web_address("https://[::1]/") is None
        assert web_address("https:///nohost") is None
        assert mail_address(f"MAILTO:psirt@{ROOT}.") == (f"mailto:psirt@{ROOT}", "psirt")
        assert mail_address(f"mailto:a@b@{ROOT}") is None
        assert mail_address("mailto:security@localhost") is None
        assert mail_address(f"mailto:.dot@{ROOT}") is None
        assert mail_address(f"security@{ROOT}") is None
