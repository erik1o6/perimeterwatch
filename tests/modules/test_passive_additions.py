"""Domain registration, SPF chain, phishing blocklists and web archives.

All HTTP is served by a local stand-in, and DNS by a table. Nothing here
touches the network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
)
from perimeterwatch.core.module import ScanModule
from perimeterwatch.modules import domain_registration as registration_module
from perimeterwatch.modules import phishing_lists as phishing_module
from perimeterwatch.modules import web_archive as archive_module
from perimeterwatch.modules.domain_registration import (
    DomainRegistration,
    clean_registrar,
    expiry_bucket,
    parse_bootstrap,
    parse_record,
)
from perimeterwatch.modules.phishing_lists import PhishingLists
from perimeterwatch.modules.spf_chain import SpfChain, parse_terms, spf_records
from perimeterwatch.modules.web_archive import WebArchive, group_for, shown_path, split_address
from tests.conftest import ROOT, FakeDns, fixture_text

TARGET = Target(root_domain=ROOT)

IANA = "data.iana.org"
REGISTRY = "rdap.centralnic.com"
RECORD_PATH = f"/xyz/domain/{ROOT}"
GITHUB_RAW = "raw.githubusercontent.com"
LIST_PATH = "/MetaMask/eth-phishing-detect/main/src/config.json"
ARCHIVE = "web.archive.org"
ARCHIVE_PATH = "/cdx/search/cdx"

SCRIPT = "<script>alert(1)</script>"
LONG = "a" * 5000


class Router:
    """Routes requests by host and path, and records them."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.requests: list[httpx.Request] = []

    def add(self, host: str, path: str, answer: Any) -> None:
        self.routes[(host, path)] = answer

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get((request.url.host, request.url.path))
        if answer is None:
            return httpx.Response(404, json={"message": "Not Found"})
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)

    def hosts(self) -> set[str]:
        return {r.url.host for r in self.requests}


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr("asyncio.sleep", instant)


def dump(result: ModuleResult) -> str:
    """Everything a result holds, as text, for checking what must never appear."""
    return result.model_dump_json()


# --------------------------------------------------------------------------
# All four modules
# --------------------------------------------------------------------------


class TestSpecs:
    @pytest.mark.parametrize(
        ("module", "name", "category", "depends_on"),
        [
            (DomainRegistration, "domain_registration", Category.SURFACE, ()),
            (SpfChain, "spf_chain", Category.EMAIL, ()),
            (PhishingLists, "phishing_lists", Category.LOOKALIKE, ("lookalikes",)),
            (WebArchive, "web_archive", Category.SURFACE, ()),
        ],
    )
    def test_passive_and_needs_no_key_tool_or_verification(
        self,
        module: type[ScanModule],
        name: str,
        category: Category,
        depends_on: tuple[str, ...],
    ) -> None:
        spec = module.spec
        assert spec.name == name
        assert spec.category is category
        assert spec.mode is ScanMode.PASSIVE
        assert spec.depends_on == depends_on
        assert not spec.requires_verification
        assert not spec.requires_keys
        assert not spec.requires_binaries
        assert spec.contacts

    def test_the_blocklist_licence_is_stated(self) -> None:
        assert "DBAD" in (phishing_module.__doc__ or "")
        assert any("DBAD" in c for c in PhishingLists.spec.contacts)


# --------------------------------------------------------------------------
# domain_registration
# --------------------------------------------------------------------------

PERSONAL = (
    "Jane Roe",
    "jane.roe@private-mail.org",
    "+44.2079460000",
    "12 Harbour Lane",
    "Bristol",
    "BS1 5TT",
    "Roe Holdings",
)


def person(role: str) -> dict[str, Any]:
    return {
        "objectClassName": "entity",
        "handle": "P-JANE-ROE-1",
        "roles": [role],
        "vcardArray": [
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Jane Roe"],
                ["org", {}, "text", "Roe Holdings"],
                ["email", {}, "text", "jane.roe@private-mail.org"],
                ["tel", {"type": "voice"}, "uri", "tel:+44.2079460000"],
                ["adr", {}, "text", ["", "", "12 Harbour Lane", "Bristol", "", "BS1 5TT", "GB"]],
            ],
        ],
    }


def record(
    *,
    name: str = ROOT,
    expires_in_days: float | None = 300,
    status: Any = ("client transfer prohibited", "client delete prohibited"),
    registrar: Any = "Example Registrar Ltd",
    nameservers: Any = ("NS2.DNS-HOST.NET", "ns1.dns-host.net"),
    extra_entities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    events = [{"eventAction": "registration", "eventDate": "2021-03-04T10:00:00Z"}]
    if expires_in_days is not None:
        moment = now + timedelta(days=expires_in_days)
        events.append(
            {"eventAction": "expiration", "eventDate": moment.strftime("%Y-%m-%dT%H:%M:%SZ")}
        )
    events.append({"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"})
    return {
        "objectClassName": "domain",
        "handle": "D123-CNIC",
        "ldhName": name.upper(),
        "status": list(status) if isinstance(status, tuple) else status,
        "entities": [
            *(extra_entities or []),
            {
                "objectClassName": "entity",
                "handle": "81",
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "81"}],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]],
                ],
                "entities": [person("abuse")],
            },
        ],
        "events": events,
        "nameservers": [{"objectClassName": "nameserver", "ldhName": n} for n in nameservers]
        if isinstance(nameservers, tuple)
        else nameservers,
    }


def rdap(router: Router, answer: Any) -> Router:
    router.add(IANA, "/rdap/dns.json", json.loads(fixture_text("rdap", "bootstrap.json")))
    router.add(REGISTRY, RECORD_PATH, answer)
    return router


def kinds(result: ModuleResult) -> list[str]:
    return sorted(f.kind for f in result.findings)


class TestDomainRegistration:
    async def test_healthy_domain_reports_details_only(self, make_ctx: Any, router: Router) -> None:
        result = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, record())))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "domain.registration.details"
        assert finding.severity is Severity.INFO
        assert finding.asset_type is AssetType.DOMAIN
        assert finding.asset_key == ROOT
        assert finding.identity == {}
        assert finding.state == {
            "registrar": "Example Registrar Ltd",
            "nameservers": ["ns1.dns-host.net", "ns2.dns-host.net"],
            "status": ["client delete prohibited", "client transfer prohibited"],
        }
        assert finding.evidence["registered_on"] == "2021-03-04"
        assert finding.evidence["expires_on"]
        assert finding.evidence["registrar_iana_id"] == "81"

    async def test_asks_only_iana_and_the_listed_registry(
        self, make_ctx: Any, router: Router
    ) -> None:
        await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, record())))
        assert [(r.url.host, r.url.path) for r in router.requests] == [
            (IANA, "/rdap/dns.json"),
            (REGISTRY, RECORD_PATH),
        ]
        assert all(r.url.scheme == "https" and r.method == "GET" for r in router.requests)

    async def test_real_record_shape(self, make_ctx: Any, router: Router) -> None:
        router.add(IANA, "/rdap/dns.json", json.loads(fixture_text("rdap", "bootstrap.json")))
        router.add(
            "rdap.verisign.com",
            "/com/v1/domain/acme-registry.com",
            json.loads(fixture_text("rdap", "acme-registry.com.json")),
        )
        ctx = make_ctx(root="acme-registry.com", handler=router)
        result = await DomainRegistration().run(Target(root_domain="acme-registry.com"), ctx)
        details = next(f for f in result.findings if f.kind == "domain.registration.details")
        assert details.state == {
            "registrar": "Example Registrar Ltd",
            "nameservers": ["ns1.dnshost-example.net", "ns2.dnshost-example.net"],
            "status": ["client transfer prohibited"],
        }
        assert details.evidence["expires_on"] == "2027-05-01"
        assert "domain.registration.unlocked" not in kinds(result)
        # The registrar's own abuse contact is not read either.
        assert "abuse@" not in dump(result)

    def test_second_real_record_parses(self) -> None:
        parsed = parse_record(fixture_text("rdap", "acme-labs.com.json"), "acme-labs.com")
        assert parsed.registrar == "Example Registrar Ltd"
        assert len(parsed.nameservers) == 4
        assert parsed.expires == datetime(2027, 6, 1, 10, 0, 0, tzinfo=UTC)

    async def test_subdomain_target_looks_up_the_registrable_domain(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(root=f"app.{ROOT}", handler=rdap(router, record()))
        result = await DomainRegistration().run(Target(root_domain=f"app.{ROOT}"), ctx)
        assert result.status is ModuleStatus.OK
        assert router.requests[-1].url.path == RECORD_PATH
        assert result.findings[0].asset_key == ROOT

    @pytest.mark.parametrize(
        ("days", "bucket", "severity"),
        [
            (59, "60d", Severity.MEDIUM),
            (29, "30d", Severity.MEDIUM),
            (13, "14d", Severity.HIGH),
            (3, "7d", Severity.HIGH),
        ],
    )
    async def test_expiring(
        self, make_ctx: Any, router: Router, days: int, bucket: str, severity: Severity
    ) -> None:
        ctx = make_ctx(handler=rdap(router, record(expires_in_days=days)))
        result = await DomainRegistration().run(TARGET, ctx)
        assert kinds(result) == ["domain.registration.details", "domain.registration.expiring"]
        finding = next(f for f in result.findings if f.kind.endswith("expiring"))
        assert finding.state == {"bucket": bucket}
        assert finding.identity == {}
        assert finding.severity is severity
        assert (finding.severity_note is not None) == (severity is Severity.HIGH)
        assert f"within {bucket[:-1]} days" in finding.title

    async def test_nothing_that_drifts_is_in_identity_or_state(
        self, make_ctx: Any, router: Router
    ) -> None:
        first = await DomainRegistration().run(
            TARGET, make_ctx(handler=rdap(Router(), record(expires_in_days=29)))
        )
        second = await DomainRegistration().run(
            TARGET, make_ctx(handler=rdap(router, record(expires_in_days=20)))
        )
        for a, b in zip(first.findings, second.findings, strict=True):
            assert (a.kind, a.identity, a.state, a.severity) == (
                b.kind,
                b.identity,
                b.state,
                b.severity,
            )

    async def test_expired(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=rdap(router, record(expires_in_days=-2)))
        result = await DomainRegistration().run(TARGET, ctx)
        assert kinds(result) == ["domain.registration.details", "domain.registration.expired"]
        finding = next(f for f in result.findings if f.kind.endswith("expired"))
        assert finding.severity is Severity.CRITICAL
        assert finding.state == {}
        assert "expired_on" in finding.evidence

    def test_buckets(self) -> None:
        now = datetime(2026, 9, 29, tzinfo=UTC)
        assert expiry_bucket(now + timedelta(days=61), now) is None
        assert expiry_bucket(now + timedelta(days=60), now) == "60d"
        assert expiry_bucket(now + timedelta(days=30), now) == "30d"
        assert expiry_bucket(now + timedelta(days=14), now) == "14d"
        assert expiry_bucket(now + timedelta(days=7), now) == "7d"
        assert expiry_bucket(now - timedelta(seconds=1), now) == "expired"

    @pytest.mark.parametrize(
        "status",
        [("active",), ("client delete prohibited", "client update prohibited")],
    )
    async def test_unlocked(self, make_ctx: Any, router: Router, status: tuple[str, ...]) -> None:
        ctx = make_ctx(handler=rdap(router, record(status=status)))
        result = await DomainRegistration().run(TARGET, ctx)
        assert kinds(result) == ["domain.registration.details", "domain.registration.unlocked"]
        finding = next(f for f in result.findings if f.kind.endswith("unlocked"))
        assert finding.severity is Severity.MEDIUM
        assert finding.evidence["status"] == sorted(status)

    @pytest.mark.parametrize(
        "status", [("server transfer prohibited",), ("Client Transfer Prohibited",)]
    )
    async def test_either_lock_counts(
        self, make_ctx: Any, router: Router, status: tuple[str, ...]
    ) -> None:
        ctx = make_ctx(handler=rdap(router, record(status=status)))
        result = await DomainRegistration().run(TARGET, ctx)
        assert kinds(result) == ["domain.registration.details"]

    async def test_no_status_published_is_not_called_unlocked(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(handler=rdap(router, record(status=())))
        result = await DomainRegistration().run(TARGET, ctx)
        assert kinds(result) == ["domain.registration.details"]
        assert any("transfer lock could not be checked" in n for n in result.notes)

    async def test_no_expiry_date_published(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=rdap(router, record(expires_in_days=None)))
        result = await DomainRegistration().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert kinds(result) == ["domain.registration.details"]
        assert any("expiry" in n for n in result.notes)

    async def test_registrar_or_nameserver_change_changes_state(
        self, make_ctx: Any, router: Router
    ) -> None:
        before = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(Router(), record())))
        moved = record(registrar="Shady Registrar Ltd", nameservers=("ns1.attacker-dns.com",))
        after = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, moved)))
        assert before.findings[0].identity == after.findings[0].identity
        assert before.findings[0].state != after.findings[0].state
        assert after.findings[0].state["nameservers"] == ["ns1.attacker-dns.com"]

    async def test_personal_data_never_appears(self, make_ctx: Any, router: Router) -> None:
        people = [person("registrant"), person("administrative"), person("technical")]
        # A contact that also claims another role is still a person.
        people.append({**person("registrant"), "roles": ["registrant", "billing"]})
        ctx = make_ctx(handler=rdap(router, record(extra_entities=people, expires_in_days=10)))
        result = await DomainRegistration().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        text = dump(result)
        for value in (*PERSONAL, "P-JANE-ROE-1", "private-mail"):
            assert value not in text
        assert result.findings[0].state["registrar"] == "Example Registrar Ltd"
        # Nor is any of it kept in the cache.
        assert all(value not in cached for cached in ctx.cache.data.values() for value in PERSONAL)

    async def test_tld_without_rdap_is_a_skip(self, make_ctx: Any, router: Router) -> None:
        rdap(router, record())
        ctx = make_ctx(root="acme-protocol.de", handler=router)
        result = await DomainRegistration().run(Target(root_domain="acme-protocol.de"), ctx)
        assert result.status is ModuleStatus.SKIPPED
        assert ".de" in (result.skip_reason or "")
        assert result.hint
        assert router.hosts() == {IANA}

    async def test_unencrypted_registry_is_not_asked(self, make_ctx: Any, router: Router) -> None:
        rdap(router, record())
        ctx = make_ctx(root="acme-protocol.kg", handler=router)
        result = await DomainRegistration().run(Target(root_domain="acme-protocol.kg"), ctx)
        assert result.status is ModuleStatus.SKIPPED
        assert router.hosts() == {IANA}

    async def test_bootstrap_is_cached(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=rdap(router, record()))
        await DomainRegistration().run(TARGET, ctx)
        await DomainRegistration().run(TARGET, ctx)
        assert [r.url.host for r in router.requests] == [IANA, REGISTRY, REGISTRY]

    async def test_damaged_cache_entry_is_replaced(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=rdap(router, record()))
        ctx.cache_set("rdap", "bootstrap", "{not json", timedelta(days=1))
        result = await DomainRegistration().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert IANA in router.hosts()
        assert json.loads(ctx.cache_get("rdap", "bootstrap"))["services"]

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(200, text="<html>maintenance</html>"),
            httpx.Response(200, text='{"services": '),
            httpx.Response(200, json={"services": "none"}),
            httpx.Response(200, json=["services"]),
            httpx.Response(200, json={"services": []}),
            httpx.Response(200, json={"services": [[["xyz"]], "junk", [1, 2], [["xyz"], "x"]]}),
            httpx.Response(200, text=""),
            httpx.Response(503, text="unavailable"),
            httpx.Response(200, text=" " * 2_100_000),
        ],
    )
    async def test_bad_bootstrap_fails_plainly(
        self, make_ctx: Any, router: Router, answer: httpx.Response
    ) -> None:
        router.add(IANA, "/rdap/dns.json", answer)
        ctx = make_ctx(handler=router)
        result = await DomainRegistration().run(TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert result.skip_reason
        assert router.hosts() == {IANA}
        assert ctx.cache_get("rdap", "bootstrap") is None

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(200, text="<html>maintenance</html>"),
            httpx.Response(200, text='{"objectClassName": "domain", '),
            httpx.Response(200, text=""),
            httpx.Response(200, json=[]),
            httpx.Response(200, json={}),
            httpx.Response(200, json={"objectClassName": "entity", "ldhName": ROOT}),
            httpx.Response(200, json={"errorCode": 404, "title": "Not Found"}),
            httpx.Response(200, text=json.dumps(record()) + " " * 1_100_000),
            httpx.Response(403, text="forbidden"),
            httpx.Response(404, json={"errorCode": 404}),
            httpx.Response(429, text="slow down"),
        ],
    )
    async def test_bad_record_fails_plainly(
        self, make_ctx: Any, router: Router, answer: httpx.Response
    ) -> None:
        result = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, answer)))
        assert result.status is ModuleStatus.FAILED
        assert result.skip_reason
        assert not result.findings
        assert "Traceback" not in result.skip_reason

    async def test_server_error_is_retried_once(
        self, make_ctx: Any, router: Router, no_sleep: None
    ) -> None:
        result = await DomainRegistration().run(
            TARGET, make_ctx(handler=rdap(router, httpx.Response(502, text="bad gateway")))
        )
        assert result.status is ModuleStatus.FAILED
        assert "HTTP 502" in (result.skip_reason or "")
        assert [r.url.host for r in router.requests] == [IANA, REGISTRY, REGISTRY]

    async def test_unreachable_registry(
        self, make_ctx: Any, router: Router, no_sleep: None
    ) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out", request=request)

        result = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, down)))
        assert result.status is ModuleStatus.FAILED
        assert "could not be reached" in (result.skip_reason or "")

    async def test_record_with_odd_field_types(self, make_ctx: Any, router: Router) -> None:
        odd = record(status="active", nameservers={"ldhName": "ns1.dns-host.net"})
        odd["entities"] = {"roles": ["registrar"]}
        odd["events"] = [None, "soon", {"eventAction": "expiration", "eventDate": 20270101}]
        result = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, odd)))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.state == {"registrar": None, "nameservers": [], "status": []}

    async def test_answer_about_another_domain_is_discarded(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(handler=rdap(router, record(name="someone-else.xyz")))
        result = await DomainRegistration().run(TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert "different domain" in (result.skip_reason or "")
        assert "someone-else" not in dump(result)

    async def test_hostile_values_are_dropped_or_cleaned(
        self, make_ctx: Any, router: Router
    ) -> None:
        hostile = record(
            registrar=f"Evil {SCRIPT} Registrar\x00\n" + LONG,
            status=("client transfer prohibited", SCRIPT, "../../etc/passwd", LONG, 7),
            nameservers=(
                "ns1.dns-host.net",
                SCRIPT,
                f"{SCRIPT}.dns-host.net",
                "../../etc/passwd",
                "ns1.dns-host.net/../admin",
                "10.0.0.1",
                LONG + ".net",
                "javascript:alert(1)",
            ),
        )
        hostile["events"].append({"eventAction": "expiration", "eventDate": SCRIPT})
        hostile["handle"] = SCRIPT
        result = await DomainRegistration().run(TARGET, make_ctx(handler=rdap(router, hostile)))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.state["nameservers"] == ["ns1.dns-host.net"]
        assert finding.state["status"] == ["client transfer prohibited"]
        assert len(finding.state["registrar"]) <= 100
        assert finding.state["registrar"].startswith("Evil scriptalert(1)/script Registrar")
        text = dump(result)
        for bad in ("<", ">", "etc/passwd", "javascript:", "\\u0000", "a" * 200):
            assert bad not in text

    def test_registrar_names_keep_ordinary_punctuation(self) -> None:
        assert clean_registrar("GoDaddy.com, LLC") == "GoDaddy.com, LLC"
        assert clean_registrar("1&1 IONOS SE") == "1&1 IONOS SE"
        assert clean_registrar("  Key-Systems   GmbH ") == "Key-Systems GmbH"
        assert clean_registrar("<>\"'`") is None
        assert clean_registrar(None) is None
        assert clean_registrar(["Example"]) is None

    async def test_redirect_to_a_listed_server_is_followed(
        self, make_ctx: Any, router: Router
    ) -> None:
        onward = f"https://rdap.verisign.com/com/v1/domain/{ROOT}"
        rdap(router, httpx.Response(302, headers={"location": onward}))
        router.add("rdap.verisign.com", f"/com/v1/domain/{ROOT}", record())
        result = await DomainRegistration().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.OK
        assert [r.url.host for r in router.requests] == [IANA, REGISTRY, "rdap.verisign.com"]

    @pytest.mark.parametrize(
        "location",
        [
            f"https://rdap.evil-registry.net/domain/{ROOT}",
            f"https://{ROOT}/rdap/domain/{ROOT}",
            f"http://rdap.verisign.com/com/v1/domain/{ROOT}",
            f"https://rdap.verisign.com:8443/com/v1/domain/{ROOT}",
            f"https://user:pw@rdap.verisign.com/com/v1/domain/{ROOT}",
            f"https://rdap.verisign.com.evil.net/domain/{ROOT}",
            "https://169.254.169.254/latest/meta-data/",
            "//evil.net/x",
            "https://" + LONG + ".net/",
            "",
        ],
    )
    async def test_redirect_elsewhere_is_refused(
        self, make_ctx: Any, router: Router, location: str
    ) -> None:
        rdap(router, httpx.Response(301, headers={"location": location}))
        result = await DomainRegistration().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "redirected" in (result.skip_reason or "")
        assert router.hosts() == {IANA, REGISTRY}

    async def test_redirect_loop_ends(self, make_ctx: Any, router: Router) -> None:
        rdap(router, httpx.Response(302, headers={"location": RECORD_PATH}))
        result = await DomainRegistration().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "too many times" in (result.skip_reason or "")
        assert len(router.requests) == 1 + 4

    def test_bootstrap_ignores_unusable_servers(self) -> None:
        payload = json.dumps(
            {
                "services": [
                    [["one"], ["http://rdap.plain.net/"]],
                    [["two"], ["https://user:pw@rdap.creds.net/"]],
                    [["three"], ["https://10.0.0.1/"]],
                    [["four"], ["https://rdap.ok.net/../../admin/"]],
                    [["five"], [f"https://{SCRIPT}.net/"]],
                    [["six"], ["https://rdap.ok.net:8443/"]],
                    [["seven"], ["http://rdap.plain.net/", "https://rdap.good.net/v1"]],
                    [[SCRIPT, "../x", 7], ["https://rdap.other.net/"]],
                    [["co.uk"], ["https://rdap.second-level.net/"]],
                ]
            }
        )
        parsed = parse_bootstrap(payload)
        assert parsed.hosts == {"rdap.good.net", "rdap.other.net", "rdap.second-level.net"}
        assert parsed.servers_for("acme.seven") == ("https://rdap.good.net/v1/",)
        assert parsed.servers_for("acme.co.uk") == ("https://rdap.second-level.net/",)
        for ending in ("one", "two", "three", "four", "five", "six"):
            assert parsed.servers_for(f"acme.{ending}") == ()
        assert set(parsed.servers) == {
            "one", "two", "three", "four", "five", "six", "seven", "co.uk"
        }  # fmt: skip


# --------------------------------------------------------------------------
# spf_chain
# --------------------------------------------------------------------------

MAILER = "spf.mailer-service.net"
GONE = "spf.old-newsletter.io"


def spf_dns(dns: FakeDns, record_text: str) -> FakeDns:
    dns.add(ROOT, "TXT", ["google-site-verification=abc", record_text])
    return dns


def existing(dns: FakeDns, name: str, spf: str | None = None) -> None:
    owner = ".".join(name.split(".")[-2:])
    dns.add(owner, "NS", ["ns1.dns-host.net"])
    if spf is not None:
        dns.add(name, "TXT", [spf])
    else:
        dns.nodata.add(name)


class TestSpfChain:
    async def test_healthy_record(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 ip4:192.0.2.0/24 include:{MAILER} a mx -all")
        existing(dns, MAILER, "v=spf1 ip4:198.51.100.0/24 -all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert result.stats == {"domains_checked": 1, "lookups": 3, "missing": 0}

    async def test_makes_no_http_request(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 include:{GONE} -all")
        # make_ctx without a handler fails the test on any request.
        result = await SpfChain().run(TARGET, make_ctx())
        assert len(result.findings) == 1

    async def test_unregistered_domain_is_raised_one_step(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        spf_dns(dns, f"v=spf1 include:{GONE} -all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "email.spf.dangling_include"
        assert finding.category is Category.EMAIL
        assert finding.severity is Severity.CRITICAL
        assert finding.confidence is Confidence.LIKELY
        assert "anyone could register it" in (finding.severity_note or "")
        assert finding.asset_key == ROOT
        assert finding.identity == {"domain": GONE}
        assert finding.state == {"registrable_domain_unregistered": True}
        assert finding.evidence["term"] == f"include:{GONE}"
        assert finding.evidence["registrable_domain"] == "old-newsletter.io"
        assert ("old-newsletter.io", "NS") in dns.queries

    async def test_missing_name_under_a_registered_domain_is_a_candidate(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        spf_dns(dns, f"v=spf1 include:{GONE} -all")
        dns.add("old-newsletter.io", "NS", ["ns1.dns-host.net"])
        result = await SpfChain().run(TARGET, make_ctx())
        [finding] = result.findings
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.CANDIDATE
        assert finding.severity_note is None
        assert finding.state == {"registrable_domain_unregistered": False}

    @pytest.mark.parametrize(
        ("term", "shown"),
        [
            (f"redirect={GONE}", f"redirect={GONE}"),
            (f"a:{GONE}", f"a:{GONE}"),
            (f"a:{GONE}/24", f"a:{GONE}"),
            (f"+mx:{GONE}//64", f"mx:{GONE}"),
            (f"exists:{GONE}", f"exists:{GONE}"),
            (f"?INCLUDE:{GONE.upper()}.", f"include:{GONE}"),
        ],
    )
    async def test_every_mechanism_that_names_a_domain(
        self, make_ctx: Any, dns: FakeDns, term: str, shown: str
    ) -> None:
        spf_dns(dns, f"v=spf1 {term} -all")
        result = await SpfChain().run(TARGET, make_ctx())
        [finding] = result.findings
        assert finding.identity == {"domain": GONE}
        assert finding.evidence["term"] == shown

    async def test_follows_includes_recursively(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 include:{MAILER} -all")
        existing(dns, MAILER, "v=spf1 include:eu.mailer-service.net -all")
        existing(dns, "eu.mailer-service.net", f"v=spf1 include:{GONE} ~all")
        result = await SpfChain().run(TARGET, make_ctx())
        [finding] = result.findings
        assert finding.identity == {"domain": GONE}
        assert finding.evidence["found_in_record_of"] == "eu.mailer-service.net"
        assert finding.evidence["reached_through"] == [ROOT, MAILER, "eu.mailer-service.net"]

    async def test_same_domain_named_twice_is_one_finding(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        spf_dns(dns, f"v=spf1 include:{GONE} a:{GONE} include:{MAILER} -all")
        existing(dns, MAILER, f"v=spf1 include:{GONE} -all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert [f.identity for f in result.findings] == [{"domain": GONE}]

    async def test_loops_end(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 include:{MAILER} -all")
        existing(dns, MAILER, "v=spf1 include:loop.mailer-service.net -all")
        existing(dns, "loop.mailer-service.net", f"v=spf1 include:{MAILER} include:{ROOT} -all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        txt = [name for name, rdtype in dns.queries if rdtype == "TXT"]
        assert txt.count("loop.mailer-service.net") == 1
        assert len(dns.queries) < 10

    async def test_stops_at_ten_lookups(self, make_ctx: Any, dns: FakeDns) -> None:
        names = [f"s{i}.mailer-service.net" for i in range(14)]
        spf_dns(dns, "v=spf1 " + " ".join(f"include:{n}" for n in names) + " -all")
        for name in names[:12]:
            existing(dns, name, "v=spf1 ip4:192.0.2.1 -all")
        # names[12] and names[13] do not exist, but lie beyond the limit.
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert result.stats["lookups"] == 10
        assert any("more than 10 lookups" in n for n in result.notes)
        assert (names[10], "TXT") not in dns.queries

    async def test_nested_lookups_count_towards_the_limit(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        inner = [f"i{i}.mailer-service.net" for i in range(9)]
        spf_dns(dns, f"v=spf1 include:{MAILER} include:{GONE} -all")
        existing(dns, MAILER, "v=spf1 " + " ".join(f"include:{n}" for n in inner) + " -all")
        for name in inner:
            existing(dns, name, "v=spf1 -all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.PARTIAL
        assert result.stats["lookups"] == 10
        assert (GONE, "TXT") not in dns.queries

    async def test_dns_error_is_not_absence(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 include:{GONE} include:{MAILER} -all")
        existing(dns, MAILER, "v=spf1 -all")
        dns.errors.add(GONE)
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert any("DNS errors" in n for n in result.notes)
        # The rest of the record was still followed.
        assert (MAILER, "TXT") in dns.queries

    async def test_dns_error_on_the_parent_is_not_absence(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        spf_dns(dns, f"v=spf1 include:{GONE} -all")
        dns.errors.add("old-newsletter.io")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_dns_error_on_the_record_itself(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.errors.add(ROOT)
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.FAILED
        assert "DNS error" in (result.skip_reason or "")
        assert result.findings == []

    @pytest.mark.parametrize("records", [[], ["google-site-verification=abc"], ["v=spf10 -all"]])
    async def test_no_spf_record(self, make_ctx: Any, dns: FakeDns, records: list[str]) -> None:
        if records:
            dns.add(ROOT, "TXT", records)
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert any("no SPF record" in n for n in result.notes)

    async def test_two_spf_records(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.add(ROOT, "TXT", [f"v=spf1 include:{GONE} -all", "v=spf1 -all"])
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.findings == []
        assert any("2 SPF records" in n for n in result.notes)
        assert dns.queries == [(ROOT, "TXT")]

    async def test_macros_are_skipped_and_said_so(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(
            dns,
            "v=spf1 exists:%{i}._spf.%{d}.checker.net include:%{d2}.mailer.net "
            f"redirect=%{{d}}.{GONE}",
        )
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert dns.queries == [(ROOT, "TXT")]
        assert any("macro" in n and "exists" in n for n in result.notes)
        assert "%{" not in dump(result)

    async def test_own_domain_mechanisms_need_no_check(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 a mx/24 ptr a:{ROOT} ip6:2001:db8::/32 exp=why.{GONE} all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.findings == []
        assert dns.queries == [(ROOT, "TXT")]
        assert result.stats["lookups"] == 4

    async def test_hostile_terms_never_reach_dns_or_findings(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        spf_dns(
            dns,
            f"v=spf1 include:{SCRIPT}.net include:../../etc/passwd include:{LONG}.net "
            "include:10.0.0.1 a:evil.net;rm redirect=https://evil.net/x include:nodots -all",
        )
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.findings == []
        assert dns.queries == [(ROOT, "TXT")]
        text = dump(result)
        for bad in ("<script", "etc/passwd", "a" * 100, "evil.net"):
            assert bad not in text
        assert any("does not name a valid domain" in n for n in result.notes)

    async def test_hostile_record_of_another_domain(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, f"v=spf1 include:{MAILER} -all")
        existing(dns, MAILER, f"v=spf1 include:{SCRIPT} include:{GONE} " + "x" * 9000)
        result = await SpfChain().run(TARGET, make_ctx())
        assert [f.identity for f in result.findings] == [{"domain": GONE}]
        assert "<" not in dump(result)

    async def test_name_under_unknown_ending_is_skipped(self, make_ctx: Any, dns: FakeDns) -> None:
        spf_dns(dns, "v=spf1 include:mail.notarealending -all")
        result = await SpfChain().run(TARGET, make_ctx())
        assert result.findings == []
        assert any("recognised public ending" in n for n in result.notes)

    def test_parse_terms(self) -> None:
        terms = parse_terms("v=spf1 ip4:192.0.2.1 include:A.example.net ~all")
        assert [(t.mechanism, t.domain) for t in terms] == [("include", "a.example.net")]
        assert spf_records(('"v=spf1 -all"', "V=SPF1 mx", "v=spf1x")) == ["v=spf1 -all", "V=SPF1 mx"]  # fmt: skip


# --------------------------------------------------------------------------
# phishing_lists
# --------------------------------------------------------------------------


def lookalikes_result(
    *names: str, status: ModuleStatus = ModuleStatus.OK, extra: list[Asset] | None = None
) -> ModuleResult:
    assets = [
        Asset(type=AssetType.LOOKALIKE_DOMAIN, key=name, source_module="lookalikes")
        for name in names
    ]
    return ModuleResult(module="lookalikes", status=status, assets=[*assets, *(extra or [])])


def blocklist(router: Router, answer: Any = None) -> Router:
    if answer is None:
        answer = json.loads(fixture_text("phishing", "config.json"))
    router.add(GITHUB_RAW, LIST_PATH, answer)
    return router


def keys(result: ModuleResult) -> list[str]:
    return [f.asset_key for f in result.findings]


class TestPhishingLists:
    async def test_listed_lookalike_and_name_matches(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=blocklist(router))
        ctx.assets.add(
            lookalikes_result("acme-protoco1.xyz", "acme-protocol.app", "acme-protocol.co")
        )
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert {f.kind for f in result.findings} == {"lookalike.reported_phishing"}
        assert keys(result) == [
            "acme-protoco1.xyz",
            "acme-protocol.app",
            "acme-protocol-airdrop.com",
            "acme-protocol.pages.dev",
            "login.acme-protocol-rewards.net",
        ]
        listed = result.findings[0]
        assert listed.severity is Severity.HIGH
        assert listed.confidence is Confidence.LIKELY
        assert listed.asset_type is AssetType.LOOKALIKE_DOMAIN
        assert listed.identity == {}
        assert listed.state == {"lists": ["MetaMask eth-phishing-detect"]}
        assert listed.evidence["also_a_registered_variation"] is True
        assert "MetaMask" in (listed.attribution or "")
        # A listed name under a lookalike is reported against the lookalike.
        assert result.findings[1].evidence["listed_names"] == ["claim.acme-protocol.app"]
        by_name = result.findings[2]
        assert by_name.confidence is Confidence.CANDIDATE
        assert by_name.evidence["also_a_registered_variation"] is False
        assert result.stats == {
            "blocklist_names": 10,
            "lookalikes_compared": 3,
            "lookalikes_listed": 2,
            "name_matches": 3,
        }

    async def test_only_the_list_publisher_is_contacted(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(handler=blocklist(router))
        ctx.assets.add(lookalikes_result("acme-protoco1.xyz"))
        await PhishingLists().run(TARGET, ctx)
        [request] = router.requests
        assert (request.url.host, request.url.path) == (GITHUB_RAW, LIST_PATH)
        assert request.method == "GET"
        assert request.url.query == b""
        # The organisation's name is not sent anywhere.
        assert "acme" not in str(request.url)
        assert "acme" not in str(request.headers)

    async def test_own_and_allowed_names_are_not_reported(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(handler=blocklist(router))
        ctx.assets.add(lookalikes_result("acme-protocol-docs.org", ROOT, f"app.{ROOT}"))
        result = await PhishingLists().run(TARGET, ctx)
        assert "acme-protocol-docs.org" not in keys(result)
        assert not any(ctx.in_scope(k) for k in keys(result))
        assert result.stats["lookalikes_compared"] == 1

    async def test_brand_scan_runs_without_the_lookalikes_module(
        self, make_ctx: Any, router: Router
    ) -> None:
        result = await PhishingLists().run(TARGET, make_ctx(handler=blocklist(router)))
        assert result.status is ModuleStatus.PARTIAL
        assert keys(result) == [
            "acme-protocol-airdrop.com",
            "acme-protocol.pages.dev",
            "claim.acme-protocol.app",
            "login.acme-protocol-rewards.net",
        ]
        assert any("lookalike search did not finish" in n for n in result.notes)

    async def test_failed_or_partial_lookalikes(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=blocklist(router))
        ctx.assets.add(lookalikes_result("acme-protoco1.xyz", status=ModuleStatus.FAILED))
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert "acme-protoco1.xyz" not in keys(result)

        ctx = make_ctx(handler=blocklist(router))
        ctx.assets.add(lookalikes_result("acme-protoco1.xyz", status=ModuleStatus.PARTIAL))
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert "acme-protoco1.xyz" in keys(result)

    async def test_short_name_is_not_searched_for(self, make_ctx: Any, router: Router) -> None:
        blocklist(router, {"blacklist": ["acme-airdrop.com", "acmee.xyz"], "whitelist": []})
        ctx = make_ctx(root="acme.xyz", handler=router)
        ctx.assets.add(lookalikes_result("acmee.xyz"))
        result = await PhishingLists().run(Target(root_domain="acme.xyz"), ctx)
        assert result.status is ModuleStatus.OK
        assert keys(result) == ["acmee.xyz"]
        assert any("too short" in n for n in result.notes)

    async def test_nothing_to_check_makes_no_request(self, make_ctx: Any) -> None:
        ctx = make_ctx(root="acme.xyz")
        ctx.assets.add(lookalikes_result())
        result = await PhishingLists().run(Target(root_domain="acme.xyz"), ctx)
        assert result.status is ModuleStatus.SKIPPED
        assert "too short" in (result.skip_reason or "")

    async def test_brand_must_be_part_of_the_name_not_of_a_longer_label(
        self, make_ctx: Any, router: Router
    ) -> None:
        blocklist(
            router,
            {
                "blacklist": [
                    "xacme-protocolx.shared-host.com",
                    "acme-protocol.shared-host.com",
                    "myacme-protocol.com",
                ]
            },
        )
        ctx = make_ctx(handler=router)
        ctx.assets.add(lookalikes_result())
        result = await PhishingLists().run(TARGET, ctx)
        assert keys(result) == ["acme-protocol.shared-host.com", "myacme-protocol.com"]

    async def test_name_matches_are_capped_at_fifty(self, make_ctx: Any, router: Router) -> None:
        names = [f"acme-protocol-{i:03d}.com" for i in range(80)]
        blocklist(router, {"blacklist": names, "whitelist": []})
        ctx = make_ctx(handler=router)
        ctx.assets.add(lookalikes_result("acme-protocol-079.com"))
        result = await PhishingLists().run(TARGET, ctx)
        assert len(result.findings) == 1 + 50
        assert keys(result)[0] == "acme-protocol-079.com"
        assert keys(result)[1:] == names[:50]
        assert any("79 domains on the blocklist" in n for n in result.notes)

    async def test_list_is_cached(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=blocklist(router))
        ctx.assets.add(lookalikes_result("acme-protoco1.xyz"))
        first = await PhishingLists().run(TARGET, ctx)
        second = await PhishingLists().run(TARGET, ctx)
        assert len(router.requests) == 1
        assert keys(first) == keys(second)
        assert first.status is second.status is ModuleStatus.OK
        cached = json.loads(ctx.cache_get("phishing_lists", "metamask"))
        assert set(cached) == {"blacklist", "whitelist", "truncated"}

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(200, text="<html>rate limited</html>"),
            httpx.Response(200, text='{"blacklist": ["a.com"'),
            httpx.Response(200, text=""),
            httpx.Response(200, json=["acme-protoco1.xyz"]),
            httpx.Response(200, json={"whitelist": []}),
            httpx.Response(200, json={"blacklist": "acme-protoco1.xyz"}),
            httpx.Response(200, json={"blacklist": [], "whitelist": {"a": 1}}),
            httpx.Response(404, text="404: Not Found"),
            httpx.Response(429, text="slow down"),
            httpx.Response(500, text="oops"),
            httpx.Response(302, headers={"location": "https://evil.net/config.json"}),
        ],
    )
    async def test_bad_list_fails_plainly(
        self, make_ctx: Any, router: Router, answer: httpx.Response
    ) -> None:
        ctx = make_ctx(handler=blocklist(router, answer))
        ctx.assets.add(lookalikes_result("acme-protoco1.xyz"))
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert "blocklist" in (result.skip_reason or "")
        assert result.findings == []
        assert ctx.cache_get("phishing_lists", "metamask") is None
        assert router.hosts() == {GITHUB_RAW}

    async def test_unreachable_list(self, make_ctx: Any, router: Router) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        ctx = make_ctx(handler=blocklist(router, down))
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert "ReadTimeout" in (result.skip_reason or "")

    async def test_oversized_list_is_not_read(
        self, make_ctx: Any, router: Router, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(phishing_module, "MAX_BYTES", 1000)
        blocklist(router, {"blacklist": [f"acme-protocol-{i}.com" for i in range(200)]})
        result = await PhishingLists().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "larger than expected" in (result.skip_reason or "")

    async def test_overlong_list_is_cut_and_marked_partial(
        self, make_ctx: Any, router: Router, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(phishing_module, "MAX_ENTRIES", 3)
        blocklist(router, {"blacklist": [f"acme-protocol-{i}.com" for i in range(9)]})
        ctx = make_ctx(handler=router)
        ctx.assets.add(lookalikes_result())
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert len(result.findings) == 3
        # The cached copy remembers that it was cut.
        again = await PhishingLists().run(TARGET, ctx)
        assert again.status is ModuleStatus.PARTIAL

    async def test_hostile_entries_never_reach_findings(
        self, make_ctx: Any, router: Router
    ) -> None:
        blocklist(
            router,
            {
                "blacklist": [
                    f"{SCRIPT}.acme-protocol-airdrop.com",
                    "acme-protocol-airdrop.com/../../etc/passwd",
                    "https://acme-protocol-claim.com/login?x=1",
                    "acme-protocol-claim.com:8080",
                    "user@acme-protocol-mail.com",
                    "acme-protocol" + LONG + ".com",
                    "acme-protocol .com",
                    "acme-protocol",
                    "*.acme-protocol-wild.com",
                    None,
                    7,
                    {"name": "acme-protocol-dict.com"},
                    ["acme-protocol-list.com"],
                    "ACME-PROTOCOL-Upper.COM.",
                ],
                "whitelist": [SCRIPT, None],
            },
        )
        ctx = make_ctx(handler=router)
        hostile_asset = Asset(
            type=AssetType.LOOKALIKE_DOMAIN, key=f"{SCRIPT}.xyz", source_module="lookalikes"
        )
        other_type = Asset(
            type=AssetType.SUBDOMAIN, key="acme-protocol-upper.com", source_module="lookalikes"
        )
        ctx.assets.add(lookalikes_result(extra=[hostile_asset, other_type]))
        result = await PhishingLists().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert keys(result) == ["acme-protocol-upper.com"]
        assert result.findings[0].confidence is Confidence.CANDIDATE
        text = dump(result)
        for bad in ("<", "etc/passwd", "https://acme", "login?", "@", "a" * 100, "*", ":8080"):
            assert bad not in text


# --------------------------------------------------------------------------
# web_archive
# --------------------------------------------------------------------------


def archive(router: Router, answer: Any = None) -> Router:
    if answer is None:
        answer = json.loads(fixture_text("wayback", "listing.json"))
    router.add(ARCHIVE, ARCHIVE_PATH, answer)
    return router


def rows(*addresses: Any) -> list[Any]:
    return [["original"], *([a] for a in addresses)]


def by_key(result: ModuleResult) -> dict[tuple[str, str], Any]:
    return {(f.asset_key, f.identity["group"]): f for f in result.findings}


class TestWebArchive:
    async def test_groups_by_host_and_kind(self, make_ctx: Any, router: Router) -> None:
        result = await WebArchive().run(TARGET, make_ctx(handler=archive(router)))
        assert result.status is ModuleStatus.OK
        assert {f.kind for f in result.findings} == {"surface.archive.sensitive_url"}
        found = by_key(result)
        assert sorted(found) == [
            ("acme-protocol.xyz", "backups"),
            ("acme-protocol.xyz", "secrets"),
            ("api.acme-protocol.xyz", "admin_debug"),
            ("api.acme-protocol.xyz", "api_docs"),
            ("api.acme-protocol.xyz", "config"),
            ("app.acme-protocol.xyz", "admin_debug"),
            ("app.acme-protocol.xyz", "secrets"),
        ]
        backups = found[("acme-protocol.xyz", "backups")]
        assert backups.asset_type is AssetType.DOMAIN
        assert backups.evidence["example_paths"] == [
            "/backup/site-2024.sql",
            "/backup/site-2024.sql.gz",
            "/old/db.bak",
        ]
        assert backups.severity is Severity.MEDIUM
        assert backups.severity_note
        assert backups.confidence is Confidence.CANDIDATE
        assert backups.state == {}
        assert backups.identity == {"group": "backups"}
        docs = found[("api.acme-protocol.xyz", "api_docs")]
        assert docs.asset_type is AssetType.SUBDOMAIN
        assert docs.severity is Severity.LOW
        assert docs.severity_note is None
        assert docs.evidence["example_paths"] == [
            "/graphql/playground",
            "/swagger/index.html",
            "/v2/api-docs",
        ]
        assert found[("acme-protocol.xyz", "secrets")].evidence["example_paths"] == [
            "/.env",
            "/.git/config",
        ]
        assert result.stats == {"addresses_read": 19, "sensitive_addresses": 13, "groups": 7}

    async def test_only_the_archive_index_is_asked(self, make_ctx: Any, router: Router) -> None:
        await WebArchive().run(TARGET, make_ctx(handler=archive(router)))
        [request] = router.requests
        assert (request.url.host, request.url.path) == (ARCHIVE, ARCHIVE_PATH)
        assert request.method == "GET"
        assert dict(request.url.params) == {
            "url": f"*.{ROOT}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "5000",
        }

    async def test_query_strings_and_path_parameters_are_stripped(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(handler=archive(router))
        result = await WebArchive().run(TARGET, ctx)
        admin = by_key(result)[("app.acme-protocol.xyz", "admin_debug")]
        assert admin.evidence["example_paths"] == ["/admin/login", "/admin/users"]
        text = dump(result) + "".join(ctx.cache.data.values())
        for secret in ("SECRETTOKEN123", "token=", "session", "abc123", "jsessionid", "?"):
            assert secret not in text

    async def test_out_of_scope_hosts_are_dropped(self, make_ctx: Any, router: Router) -> None:
        result = await WebArchive().run(TARGET, make_ctx(handler=archive(router)))
        text = dump(result)
        assert "evil" not in text
        assert "notacme" not in text
        assert all(f.asset_key == ROOT or f.asset_key.endswith("." + ROOT) for f in result.findings)

    async def test_nothing_recorded(self, make_ctx: Any, router: Router) -> None:
        archive(router, httpx.Response(200, text=fixture_text("wayback", "empty.json")))
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert result.stats == {"addresses_read": 0, "sensitive_addresses": 0, "groups": 0}

    async def test_ordinary_addresses_are_not_reported(self, make_ctx: Any, router: Router) -> None:
        archive(
            router,
            rows(
                f"https://{ROOT}/",
                f"https://{ROOT}/blog/how-we-handle-backups",
                f"https://{ROOT}/docs/administration-guide",
                f"https://{ROOT}/static/app.js",
                f"https://{ROOT}/keynote.pdf",
                f"https://{ROOT}/environment",
                f"https://{ROOT}/api/v1/users",
                f"https://{ROOT}/robots.txt",
            ),
        )
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.findings == []

    @pytest.mark.parametrize(
        ("path", "group"),
        [
            ("/db.sql", "backups"),
            ("/site.bak", "backups"),
            ("/www.zip", "backups"),
            ("/release.tar.gz", "backups"),
            ("/.env", "secrets"),
            ("/app/.env.production", "secrets"),
            ("/.git/HEAD", "secrets"),
            ("/certs/server.pem", "secrets"),
            ("/certs/PRIVATE.KEY", "secrets"),
            ("/admin", "admin_debug"),
            ("/wp-admin/", "admin_debug"),
            ("/debug/vars", "admin_debug"),
            ("/swagger-ui.html", "api_docs"),
            ("/api/swagger.json", "api_docs"),
            ("/graphql/playground", "api_docs"),
            ("/config.yml", "config"),
            ("/wp-config.php.bak", "backups"),
            ("/web.config", "config"),
        ],
    )
    def test_patterns(self, path: str, group: str) -> None:
        found = group_for(path)
        assert found is not None
        assert found.id == group

    async def test_findings_are_capped_at_one_hundred(self, make_ctx: Any, router: Router) -> None:
        archive(router, rows(*(f"https://h{i:03d}.{ROOT}/dump.sql" for i in range(130))))
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert len(result.findings) == 100
        assert any("130 groups" in n for n in result.notes)
        assert result.findings[0].asset_key == f"h000.{ROOT}"

    async def test_examples_are_capped_at_five(self, make_ctx: Any, router: Router) -> None:
        archive(router, rows(*(f"https://{ROOT}/backups/{i:02d}.sql" for i in range(40))))
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        [finding] = result.findings
        assert finding.evidence["example_paths"] == [f"/backups/{i:02d}.sql" for i in range(5)]
        assert finding.evidence["addresses_matched"] == 40
        # Counts drift, so they are display only.
        assert finding.state == {}

    async def test_full_page_of_rows_is_partial(
        self, make_ctx: Any, router: Router, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive_module, "ROW_LIMIT", 10)
        archive(router, rows(*(f"https://{ROOT}/page/{i}" for i in range(30)), f"https://{ROOT}/.env"))  # fmt: skip
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert result.stats["addresses_read"] == 10
        assert any("Only the first 10" in n for n in result.notes)

    async def test_listing_is_cached(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=archive(router))
        first = await WebArchive().run(TARGET, ctx)
        second = await WebArchive().run(TARGET, ctx)
        assert len(router.requests) == 1
        assert [f.model_dump(exclude={"evidence"}) for f in first.findings] == [
            f.model_dump(exclude={"evidence"}) for f in second.findings
        ]
        assert first.findings[0].evidence == second.findings[0].evidence
        assert first.stats == second.stats

    async def test_damaged_cache_entry_is_replaced(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=archive(router))
        ctx.cache_set("web_archive", ROOT, '{"matches": 7}', timedelta(hours=1))
        result = await WebArchive().run(TARGET, ctx)
        assert len(result.findings) == 7
        assert len(router.requests) == 1

    async def test_cached_entries_are_checked_for_scope_again(
        self, make_ctx: Any, router: Router
    ) -> None:
        ctx = make_ctx(handler=router)
        ctx.cache_set(
            "web_archive",
            ROOT,
            json.dumps(
                {
                    "rows": 2,
                    "capped": False,
                    "matches": [["evil.net", "secrets", "/.env"], [ROOT, "nonsense", "/.env"]],
                }
            ),
            timedelta(hours=1),
        )
        result = await WebArchive().run(TARGET, ctx)
        assert result.findings == []
        assert router.requests == []

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(200, text="<html>Wayback Machine is down</html>"),
            httpx.Response(200, text='[["original"],["https://'),
            httpx.Response(200, text=""),
            httpx.Response(200, json={"error": "blocked"}),
            httpx.Response(200, json="nothing"),
            httpx.Response(403, text="forbidden"),
            httpx.Response(404, text="not found"),
            httpx.Response(302, headers={"location": f"https://{ROOT}/cdx"}),
        ],
    )
    async def test_bad_answer_fails_plainly(
        self, make_ctx: Any, router: Router, answer: httpx.Response
    ) -> None:
        ctx = make_ctx(handler=archive(router, answer))
        result = await WebArchive().run(TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert "web archive" in (result.skip_reason or "")
        assert result.findings == []
        assert ctx.cache.data == {}
        assert router.hosts() == {ARCHIVE}

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    async def test_busy_archive_is_retried_once(
        self, make_ctx: Any, router: Router, no_sleep: None, status: int
    ) -> None:
        archive(router, httpx.Response(status, text="busy"))
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert f"HTTP {status}" in (result.skip_reason or "")
        assert len(router.requests) == 2

    async def test_recovers_on_the_second_attempt(
        self, make_ctx: Any, router: Router, no_sleep: None
    ) -> None:
        answers = [httpx.Response(503, text="busy"), httpx.Response(200, json=rows(f"https://{ROOT}/.env"))]  # fmt: skip
        archive(router, lambda _request: answers.pop(0))
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.OK
        assert len(result.findings) == 1

    async def test_unreachable_archive(self, make_ctx: Any, router: Router, no_sleep: None) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        result = await WebArchive().run(TARGET, make_ctx(handler=archive(router, down)))
        assert result.status is ModuleStatus.FAILED
        assert "could not be reached" in (result.skip_reason or "")

    async def test_oversized_answer_is_not_read(
        self, make_ctx: Any, router: Router, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive_module, "MAX_BYTES", 2000)
        archive(router, rows(*(f"https://{ROOT}/backups/{i}.sql" for i in range(200))))
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "larger than expected" in (result.skip_reason or "")

    async def test_hostile_rows_never_reach_findings(self, make_ctx: Any, router: Router) -> None:
        archive(
            router,
            rows(
                f"https://{ROOT}/{SCRIPT}/backup.sql",
                f"https://{ROOT}/backup/<img src=x onerror=alert(1)>.sql",
                f'https://{ROOT}/"onmouseover="alert(1)/.env',
                f"https://{ROOT}/../../etc/passwd.bak",
                f"https://{ROOT}/a/%2e%2e/%2E%2E/secret.key",
                f"https://{ROOT}/" + LONG + ".sql",
                f"https://{SCRIPT}.{ROOT}/.env",
                f"https://{ROOT}.evil.net/.env",
                f"https://evil.net/{ROOT}/.env",
                f"https://evil.net/?{ROOT}/.env",
                f"https://user:hunter2@{ROOT}/private.pem",
                f"https://{ROOT}@evil.net/.env",
                f"javascript://{ROOT}/%0aalert(1)/.env",
                f"file://{ROOT}/etc/shadow.bak",
                "https://[::1/.env",
                f"https://{ROOT}:99999/.env",
                f"https://{ROOT}/line\nbreak/.env",
                f"https://{ROOT}/nul\x00/.env",
                "https://10.0.0.1/.env",
                None,
                7,
                {"original": f"https://{ROOT}/.env"},
                [f"https://{ROOT}/.git/config"],
                [f"https://{ROOT}/.env", "extra column"],
                [],
            ),
        )
        router.routes[(ARCHIVE, ARCHIVE_PATH)].append(f"https://{ROOT}/not-a-row.sql")
        result = await WebArchive().run(TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.asset_key == ROOT
        # Sign-in details in an address are dropped with the rest of the host part.
        assert finding.evidence["example_paths"] == ["/private.pem"]
        text = dump(result)
        for bad in ("<", ">", "onerror", "onmouseover", "..", "%2e", "passwd", "hunter2", "user:",
                    "evil", "javascript", "shadow", "a" * 100, "\\n", "\\u0000"):  # fmt: skip
            assert bad not in text

    def test_split_address(self) -> None:
        assert split_address(f"http://APP.{ROOT}:80/Admin/?a=1#top") == (f"app.{ROOT}", "/Admin/")
        assert split_address(f"https://{ROOT}") == (ROOT, "/")
        assert split_address(f"https://{ROOT}/a;jsessionid=1/b") == (ROOT, "/a")
        assert split_address(f"ftp://{ROOT}/backup.sql") is None
        assert split_address(f"{ROOT}/backup.sql") is None
        assert split_address("") is None

    def test_long_values_and_addresses_of_people_are_removed_from_paths(self) -> None:
        token = "0123456789abcdef0123456789abcdef01234567"
        assert shown_path(f"/admin/reset/{token}") == "/admin/reset/(removed)"
        assert shown_path(f"/backups/{token}.sql") == "/backups/(removed).sql"
        assert shown_path("/admin/users/jane.roe%40private-mail.org") == "/admin/users/(removed)"
        assert shown_path("/admin/login") == "/admin/login"
        assert len(shown_path("/admin/" + "/".join(["segment"] * 100))) <= 200

    async def test_tokens_in_paths_are_not_shown(self, make_ctx: Any, router: Router) -> None:
        token = "0123456789abcdef0123456789abcdef01234567"
        archive(
            router,
            rows(
                f"https://{ROOT}/admin/reset/{token}",
                f"https://{ROOT}/admin/invite/jane.roe%40private-mail.org",
            ),
        )
        ctx = make_ctx(handler=router)
        result = await WebArchive().run(TARGET, ctx)
        [finding] = result.findings
        assert finding.evidence["example_paths"] == [
            "/admin/invite/(removed)",
            "/admin/reset/(removed)",
        ]
        text = dump(result) + "".join(ctx.cache.data.values())
        assert token not in text
        assert "jane" not in text


# --------------------------------------------------------------------------
# The rule shared by all four: no contact with the organisation or lookalikes
# --------------------------------------------------------------------------


class TestNoContactWithTheOrganisation:
    async def test_every_request_goes_to_a_documented_service(
        self, make_ctx: Any, router: Router, dns: FakeDns
    ) -> None:
        rdap(router, record(expires_in_days=5, status=("active",)))
        blocklist(router)
        archive(router)
        spf_dns(dns, f"v=spf1 include:{GONE} -all")
        ctx = make_ctx(handler=router)
        ctx.assets.add(lookalikes_result("acme-protoco1.xyz", "acme-protocol.app"))

        for module in (DomainRegistration(), SpfChain(), PhishingLists(), WebArchive()):
            result = await module.run(TARGET, ctx)
            assert result.status is ModuleStatus.OK
            assert result.findings

        assert router.hosts() == {IANA, REGISTRY, GITHUB_RAW, ARCHIVE}
        for request in router.requests:
            assert request.method == "GET"
            assert request.url.scheme == "https"
            assert not ctx.in_scope(request.url.host)
            assert "acme-protoco1" not in str(request.url)
        # DNS questions are about the SPF chain only, never about lookalikes.
        assert {name for name, _ in dns.queries} == {ROOT, GONE, "old-newsletter.io"}

    def test_modules_are_importable_without_the_registry(self) -> None:
        assert registration_module.DomainRegistration.spec.name == "domain_registration"
