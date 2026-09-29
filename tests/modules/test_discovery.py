"""Subdomain discovery, resolution, takeover candidates and lookalikes."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from parapet.core.models import AssetType, AuthLevel, ModuleStatus, Severity, Target
from parapet.modules import lookalikes as lookalikes_module
from parapet.modules.dns_resolve import DnsResolve, sensitive_label
from parapet.modules.lookalikes import Lookalikes, permutations
from parapet.modules.subdomains import Subdomains
from parapet.modules.takeover import Takeover, claimable_service
from tests.conftest import ROOT

TARGET = Target(root_domain=ROOT)


def crtsh_handler(rows: list[dict[str, Any]] | None = None, status: int = 200) -> Any:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "crt.sh"
        calls.append(request)
        if status != 200:
            return httpx.Response(status, text="upstream error")
        return httpx.Response(200, text=json.dumps(rows or []))

    handler.calls = calls  # type: ignore[attr-defined]
    return handler


CT_ROWS = [
    {
        "name_value": f"app.{ROOT}\n*.{ROOT}",
        "common_name": ROOT,
        "serial_number": "01",
        "issuer_name": "C=US, O=Let's Encrypt",
        "not_before": "2026-08-01",
        "not_after": "2026-10-30",
    },
    {"name_value": f"STAGING.{ROOT}.", "serial_number": "02"},
    # Must all be dropped: out of scope, lookalike suffix, email address, junk.
    {
        "name_value": "evil.net\napp.acme-protocol.xyz.evil.net\nnotacme-protocol.xyz",
        "serial_number": "03",
    },
    {
        "name_value": f"admin@{ROOT}\n<script>alert(1)</script>.{ROOT}\n..{ROOT}",
        "serial_number": "04",
    },
]


class TestSubdomains:
    async def test_keeps_only_valid_names_in_scope(self, make_ctx: Any) -> None:
        result = await Subdomains().run(TARGET, make_ctx(handler=crtsh_handler(CT_ROWS)))
        assert sorted(a.key for a in result.assets) == sorted(
            [ROOT, f"app.{ROOT}", f"staging.{ROOT}"]
        )
        assert result.status is ModuleStatus.OK
        assert any("subfinder is not installed" in n for n in result.notes)
        root = next(a for a in result.assets if a.key == ROOT)
        assert root.type is AssetType.DOMAIN

    async def test_source_failure_is_reported_not_hidden(
        self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import tenacity

        monkeypatch.setattr(tenacity.nap, "sleep", lambda _s: None)

        async def no_sleep(_s: float) -> None:
            return None

        monkeypatch.setattr("asyncio.sleep", no_sleep)
        result = await Subdomains().run(TARGET, make_ctx(handler=crtsh_handler(status=502)))
        assert result.status is ModuleStatus.FAILED
        assert result.assets == []

    async def test_second_lookup_is_served_from_cache(self, make_ctx: Any) -> None:
        handler = crtsh_handler(CT_ROWS)
        ctx = make_ctx(handler=handler)
        await Subdomains().run(TARGET, ctx)
        await Subdomains().run(TARGET, ctx)
        assert len(handler.calls) == 1


async def resolve(make_ctx: Any, names: list[str], **ctx_kwargs: Any) -> tuple[Any, Any]:
    ctx = make_ctx(**ctx_kwargs)
    discovered = await Subdomains().run(
        TARGET,
        make_ctx(handler=crtsh_handler([{"name_value": "\n".join(names), "serial_number": "1"}])),
    )
    ctx.assets.add(discovered)
    result = await DnsResolve().run(TARGET, ctx)
    ctx.assets.add(result)
    return result, ctx


@pytest.fixture
def no_dnssec_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    import checkdmarc

    monkeypatch.setattr(checkdmarc, "check_dnssec", lambda domain, **kw: True)


@pytest.mark.usefixtures("no_dnssec_lookup")
class TestDnsResolve:
    async def test_private_address_is_reported(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        dns.add(ROOT, "CAA", ['0 issue "letsencrypt.org"'])
        dns.add(f"intranet.{ROOT}", "A", ["10.0.0.1"])
        result, _ = await resolve(make_ctx, [f"intranet.{ROOT}"])
        private = next(f for f in result.findings if f.kind == "dns.private_ip")
        assert private.asset_key == f"intranet.{ROOT}"
        assert private.severity is Severity.LOW
        asset = next(a for a in result.assets if a.key == f"intranet.{ROOT}")
        assert asset.attributes["private_ips"] == ["10.0.0.1"]

    async def test_rotating_addresses_are_not_a_state_change(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        first, _ = await resolve(make_ctx, [ROOT])
        dns.add(ROOT, "A", ["104.18.9.9"])
        second, _ = await resolve(make_ctx, [ROOT])
        assert first.assets[0].state == second.assets[0].state
        assert first.assets[0].attributes["ips"] != second.assets[0].attributes["ips"]

    async def test_wildcard_is_detected_and_not_counted_as_hosts(
        self, make_ctx: Any, dns: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        original = dns.query

        async def wildcard(name: str, rdtype: str, **kw: Any) -> Any:
            answer = await original(name, rdtype, **kw)
            if not answer.records and rdtype == "A" and name.endswith("." + ROOT):
                dns.add(name, "A", ["203.0.113.7"])
                return await original(name, rdtype, **kw)
            return answer

        monkeypatch.setattr(dns, "query", wildcard)
        result, _ = await resolve(make_ctx, [f"old-thing.{ROOT}"])
        assert "dns.wildcard" in {f.kind for f in result.findings}
        ghost = next(a for a in result.assets if a.key == f"old-thing.{ROOT}")
        assert ghost.attributes["wildcard_match"] is True
        assert result.stats["resolving"] == 1, "only the root is a real host"

    async def test_missing_caa(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        result, _ = await resolve(make_ctx, [ROOT])
        assert "dns.caa.missing" in {f.kind for f in result.findings}

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            (f"admin.{ROOT}", "admin"),
            (f"staging-api.{ROOT}", "staging"),
            (f"jenkins2.{ROOT}", "jenkins"),
            (f"api.dev.{ROOT}", "dev"),
            (f"app.{ROOT}", None),
            (f"developers.{ROOT}", None),
            (f"devotion.{ROOT}", None),
            (f"latest.{ROOT}", None),
            (ROOT, None),
        ],
    )
    def test_sensitive_names(self, host: str, expected: str | None) -> None:
        assert sensitive_label(host, ROOT) == expected


@pytest.mark.usefixtures("no_dnssec_lookup")
class TestTakeover:
    async def test_dangling_alias_to_a_claimable_service(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        dns.add(ROOT, "NS", ["ns1.dnshost.net."])
        dns.add("ns1.dnshost.net", "A", ["198.41.0.4"])
        dns.add("github.io", "NS", ["ns1.github.io."])
        dns.add(f"docs.{ROOT}", "CNAME", ["acme-old-docs.github.io."])
        _, ctx = await resolve(make_ctx, [f"docs.{ROOT}"])
        result = await Takeover().run(TARGET, ctx)
        [finding] = result.findings
        assert finding.kind == "takeover.cname.dangling"
        assert finding.severity is Severity.HIGH
        assert finding.evidence["service"] == "GitHub Pages"
        assert finding.identity == {"cname": "acme-old-docs.github.io"}

    async def test_alias_to_an_unregistered_domain_is_raised(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        dns.add(f"shop.{ROOT}", "CNAME", ["store.defunct-vendor.io."])
        _, ctx = await resolve(make_ctx, [f"shop.{ROOT}"])
        [finding] = (await Takeover().run(TARGET, ctx)).findings
        assert finding.kind == "takeover.cname.unresolvable"
        assert finding.severity is Severity.HIGH, "raised one step from medium"
        assert finding.state == {"target_domain_unregistered": True}

    async def test_working_alias_is_not_reported(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        dns.add(f"docs.{ROOT}", "CNAME", ["acme.github.io."])
        dns.add("acme.github.io", "A", ["185.199.108.153"])
        _, ctx = await resolve(make_ctx, [f"docs.{ROOT}"])
        assert (await Takeover().run(TARGET, ctx)).findings == []

    async def test_a_dns_error_is_not_mistaken_for_a_missing_target(
        self, make_ctx: Any, dns: Any
    ) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        dns.add(f"docs.{ROOT}", "CNAME", ["acme.github.io."])
        dns.errors.add("acme.github.io")
        _, ctx = await resolve(make_ctx, [f"docs.{ROOT}"])
        assert (await Takeover().run(TARGET, ctx)).findings == []

    async def test_dangling_nameserver(self, make_ctx: Any, dns: Any) -> None:
        dns.add(ROOT, "A", ["104.18.0.1"])
        dns.add(ROOT, "NS", ["ns1.dnshost.net.", "ns2.lapsed-provider.com."])
        dns.add("ns1.dnshost.net", "A", ["198.41.0.4"])
        _, ctx = await resolve(make_ctx, [ROOT])
        [finding] = (await Takeover().run(TARGET, ctx)).findings
        assert finding.kind == "takeover.ns.dangling"
        assert finding.identity == {"nameserver": "ns2.lapsed-provider.com"}

    async def test_needs_resolution_to_have_run(self, make_ctx: Any) -> None:
        result = await Takeover().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.FAILED

    @pytest.mark.parametrize(
        ("target", "service"),
        [
            ("acme.github.io", "GitHub Pages"),
            ("acme-assets.s3.amazonaws.com", "Amazon S3"),
            ("acme.s3-website-us-east-1.amazonaws.com", "Amazon S3"),
            ("acme.s3.eu-west-1.amazonaws.com", "Amazon S3"),
            ("acme.azurewebsites.net.", "Azure App Service"),
            ("ACME.HEROKUAPP.COM", "Heroku"),
            ("github.io.evil.net", None),
            ("notgithub.io", None),
            ("cdn.acme-protocol.xyz", None),
        ],
    )
    def test_service_matching(self, target: str, service: str | None) -> None:
        assert claimable_service(target) == service


class TestLookalikes:
    def test_permutations_are_stable_registrable_and_capped(self) -> None:
        first, total = permutations(ROOT, 150)
        second, _ = permutations(ROOT, 150)
        assert first == second, "a capped list must hold the same names every time"
        assert len(first) == 150 < total
        names = [p["domain"] for p in first]
        assert ROOT not in names
        assert all(n.count(".") == 1 for n in names), "subdomains of other domains are excluded"

    async def test_reports_registered_names_without_contacting_them(
        self, make_ctx: Any, dns: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        candidates = [
            {"domain": "acme-protoco1.xyz", "fuzzer": "homoglyph"},
            {"domain": "acmeprotocol.xyz", "fuzzer": "omission"},
            {"domain": "acme-protocol.xy", "fuzzer": "omission"},
            {"domain": "acme-protocoll.xyz", "fuzzer": "repetition"},
            {"domain": "acme-protokol.xyz", "fuzzer": "replacement"},
        ]
        monkeypatch.setattr(lookalikes_module, "permutations", lambda d, limit: (candidates, 5))
        dns.add("acme-protoco1.xyz", "NS", ["ns1.parking.example."])
        dns.add("acme-protoco1.xyz", "A", ["203.0.113.9"])
        dns.add("acme-protoco1.xyz", "MX", ["10 mx.acme-protoco1.xyz."])
        dns.add("acmeprotocol.xyz", "NS", ["ns1.parking.example."])
        dns.add("acme-protocoll.xyz", "NS", ["ns1.parking.example."])
        dns.add("acme-protocoll.xyz", "MX", ["0 ."])  # null MX: takes no mail
        dns.errors.add("acme-protokol.xyz")

        def brand_search(request: httpx.Request) -> httpx.Response:
            assert request.url.host == "crt.sh", "lookalike domains must never be contacted"
            return httpx.Response(200, text="[]")

        result = await Lookalikes().run(TARGET, make_ctx(handler=brand_search))
        by_name = {f.asset_key: f for f in result.findings}
        assert set(by_name) == {"acme-protoco1.xyz", "acmeprotocol.xyz", "acme-protocoll.xyz"}
        assert by_name["acme-protoco1.xyz"].kind == "lookalike.mail_capable"
        assert by_name["acme-protoco1.xyz"].severity is Severity.MEDIUM
        assert by_name["acmeprotocol.xyz"].kind == "lookalike.registered"
        assert by_name["acme-protocoll.xyz"].kind == "lookalike.registered"
        assert result.stats["registered"] == 3

    async def test_certificate_matches(
        self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(lookalikes_module, "permutations", lambda d, limit: ([], 0))
        rows = [
            {
                "name_value": "claim.acme-protocol-airdrop.com",
                "serial_number": "1",
                "not_before": "2026-09-20",
            },
            {"name_value": f"app.{ROOT}", "serial_number": "2"},  # the organisation's own
            {"name_value": "acme-protocol.vercel.app", "serial_number": "3"},
            {"name_value": "pharmacme-protocolite.com", "serial_number": "4"},
        ]
        result = await Lookalikes().run(TARGET, make_ctx(handler=crtsh_handler(rows)))
        found = {f.asset_key for f in result.findings}
        assert "acme-protocol-airdrop.com" in found
        assert ROOT not in found
        assert all(f.kind == "lookalike.certificate_issued" for f in result.findings)

    async def test_short_names_skip_the_certificate_search(
        self, make_ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(lookalikes_module, "permutations", lambda d, limit: ([], 0))
        ctx = make_ctx(root="aave.com")  # no handler: any request fails the test
        result = await Lookalikes().run(Target(root_domain="aave.com"), ctx)
        assert result.status is ModuleStatus.OK
        assert any("too short" in n for n in result.notes)


def test_auth_level_import_is_used() -> None:
    assert AuthLevel.NONE.rank == 0
