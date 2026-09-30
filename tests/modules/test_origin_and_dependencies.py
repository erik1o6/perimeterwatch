"""Origin exposure and the list of outside services.

Neither module may send a request to any host. Every context here is built
without an HTTP handler, so any HTTP request fails the test.
"""

from __future__ import annotations

import ipaddress
import json
import re
from importlib import resources
from typing import Any

import pytest

from perimeterwatch.core.fingerprint import finding_fingerprint, finding_state_hash
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
)
from perimeterwatch.core.module import skipped
from perimeterwatch.modules.dependencies import (
    ROLES,
    Dependencies,
    issuer_name,
    service_for,
    service_table,
)
from perimeterwatch.modules.frontend import Frontend
from perimeterwatch.modules.http_probe import HttpProbe
from perimeterwatch.modules.origin_exposure import (
    MAX_CANDIDATES,
    OriginExposure,
    cdn_of_address,
    cdn_of_alias,
    classic_label,
    spf_addresses,
)
from perimeterwatch.modules.tls_certs import TlsCerts
from perimeterwatch.safety.domains import registrable_domain, validate_hostname
from tests.conftest import ROOT
from tests.helpers import resolved

TARGET = Target(root_domain=ROOT)
WWW = f"www.{ROOT}"
DIRECT = f"direct.{ROOT}"
CDN_IP = "104.18.0.1"
CDN_IP_2 = "104.18.0.2"
ORIGIN_IP = "45.33.32.156"
OTHER_IP = "5.9.10.20"

_IP_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}|[0-9a-f]{1,4}:[0-9a-f:]+")


# -- stand-ins for the results of earlier modules ------------------------------


def dns(
    hosts: dict[str, list[str]],
    *,
    cnames: dict[str, str] | None = None,
    wildcard: set[str] | None = None,
    nameservers: list[str] | None = None,
) -> ModuleResult:
    result = resolved(hosts, wildcard=wildcard, root=ROOT)
    for asset in result.assets:
        asset.state["cname"] = (cnames or {}).get(asset.key)
    if nameservers is not None:
        result.findings.append(
            Finding(
                kind="dns.nameserver.single_provider",
                module="dns_resolve",
                category=Category.SURFACE,
                title="one provider",
                severity=Severity.LOW,
                asset_type=AssetType.DOMAIN,
                asset_key=ROOT,
                state={"provider": "x"},
                evidence={"nameservers": nameservers},
            )
        )
    return result


def probe(cdn: dict[str, Any]) -> ModuleResult:
    """An http_probe result: host -> the delivery network it reported, or ''."""
    assets = [
        Asset(
            type=AssetType.DOMAIN if host == ROOT else AssetType.SUBDOMAIN,
            key=host,
            source_module="http_probe",
            attributes={"url": f"https://{host}", "cdn": name, "tech": []},
            state={"web": True, "https": True},
        )
        for host, name in cdn.items()
    ]
    return ModuleResult(module="http_probe", status=ModuleStatus.OK, assets=assets)


def tls(
    issuers: dict[str, Any] | None = None,
    *,
    mismatched: dict[str, Any] | None = None,
    names: dict[str, Any] | None = None,
) -> ModuleResult:
    """A tls_certs result. `mismatched` is what the module stores today: the names on a
    certificate that does not match its host. `names` is the attribute proposed for it."""
    hosts = {*(issuers or {}), *(mismatched or {}), *(names or {})}
    assets = []
    for host in sorted(hosts):
        attributes: dict[str, Any] = {
            "cert_expires": "2030-01-01",
            "cert_issuer": (issuers or {}).get(host, "R11"),
        }
        if names and host in names:
            attributes["cert_names"] = names[host]
        assets.append(
            Asset(
                type=AssetType.SUBDOMAIN,
                key=host,
                source_module="tls_certs",
                attributes=attributes,
                state={"tls": True},
            )
        )
    findings = [
        Finding(
            kind="tls.cert.hostname_mismatch",
            module="tls_certs",
            category=Category.SURFACE,
            title="mismatch",
            severity=Severity.MEDIUM,
            asset_type=AssetType.SUBDOMAIN,
            asset_key=host,
            identity={"port": "443", "cert_sha256": "ab" * 32},
            evidence={"certificate_names": listed},
        )
        for host, listed in (mismatched or {}).items()
    ]
    return ModuleResult(
        module="tls_certs", status=ModuleStatus.OK, assets=assets, findings=findings
    )


def email(mx: Any = None, spf: Any = None) -> ModuleResult:
    asset = Asset(
        type=AssetType.DOMAIN,
        key=ROOT,
        source_module="email_posture",
        attributes={"mx": mx if mx is not None else [], "spf_record": spf},
    )
    return ModuleResult(module="email_posture", status=ModuleStatus.OK, assets=[asset])


def spf_chain() -> ModuleResult:
    return ModuleResult(module="spf_chain", status=ModuleStatus.OK)


def registration(nameservers: list[Any]) -> ModuleResult:
    finding = Finding(
        kind="domain.registration.details",
        module="domain_registration",
        category=Category.SURFACE,
        title="registered",
        severity=Severity.INFO,
        asset_type=AssetType.DOMAIN,
        asset_key=ROOT,
        state={"registrar": "Example Registrar", "nameservers": nameservers, "status": []},
    )
    return ModuleResult(module="domain_registration", status=ModuleStatus.OK, findings=[finding])


def frontend(scripts: dict[str, list[Any]]) -> ModuleResult:
    findings = [
        Finding(
            kind="frontend.scripts",
            module="frontend",
            category=Category.SUPPLY_CHAIN,
            title="scripts",
            severity=Severity.INFO,
            asset_type=AssetType.SUBDOMAIN,
            asset_key=host,
            state={"scripts": entries},
        )
        for host, entries in scripts.items()
    ]
    return ModuleResult(module="frontend", status=ModuleStatus.OK, findings=findings)


def context(make_ctx: Any, *results: ModuleResult) -> Any:
    ctx = make_ctx()  # no handler: any HTTP request fails the test
    for result in results:
        ctx.assets.add(result)
    return ctx


def kinds(result: ModuleResult) -> list[str]:
    return [f.kind for f in result.findings]


def text_of(value: Any) -> str:
    return json.dumps(value, default=str)


# -- origin exposure -----------------------------------------------------------


def origin_setup(make_ctx: Any, **overrides: Any) -> Any:
    parts: dict[str, ModuleResult] = {
        "dns": dns({ROOT: [CDN_IP], WWW: [CDN_IP_2], DIRECT: [ORIGIN_IP]}),
        "probe": probe({ROOT: "cloudflare", WWW: "cloudflare", DIRECT: ""}),
        "tls": tls({ROOT: "WE1", WWW: "WE1", DIRECT: "R11"}),
        "email": email(),
        "spf_chain": spf_chain(),
    }
    parts.update(overrides)
    return context(make_ctx, *[p for p in parts.values() if p is not None])


class TestOriginSpec:
    def test_declares_what_it_is(self) -> None:
        spec = OriginExposure.spec
        assert spec.name == "origin_exposure"
        assert spec.category is Category.SURFACE
        assert spec.mode is ScanMode.PASSIVE
        assert spec.depends_on == (
            "dns_resolve",
            "spf_chain",
            "email_posture",
            "http_probe",
            "tls_certs",
        )
        assert spec.requires_binaries == () and spec.requires_keys == ()
        assert all("http" not in c.lower() for c in spec.contacts)


class TestOriginExposure:
    async def test_certificate_naming_the_site_confirms_the_origin(self, make_ctx: Any) -> None:
        ctx = origin_setup(make_ctx, tls=tls(mismatched={DIRECT: [WWW, ROOT]}))
        result = await OriginExposure().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "surface.origin.exposed"
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is Confidence.LIKELY
        assert finding.asset_key == DIRECT
        assert finding.state == {"addresses": [ORIGIN_IP], "sites": [ROOT, WWW]}
        evidence = finding.evidence
        assert DIRECT in evidence["how_it_was_found"][0]
        assert "'direct'" in evidence["how_it_was_found"][0]
        assert "certificate already collected" in evidence["how_it_was_confirmed"]
        assert "wildcard" in evidence["possible_false_alarm"]
        assert "Nothing was sent" in evidence["what_was_sent"]
        assert evidence["content_delivery_network"] == ["cloudflare"]

    async def test_certificate_names_stored_as_an_attribute_also_confirm(
        self, make_ctx: Any
    ) -> None:
        ctx = origin_setup(make_ctx, tls=tls(names={DIRECT: [DIRECT, WWW]}))
        [finding] = (await OriginExposure().run(TARGET, ctx)).findings
        assert finding.kind == "surface.origin.exposed"
        assert finding.state["sites"] == [WWW]

    async def test_wildcard_only_match_is_reported_with_less_weight(self, make_ctx: Any) -> None:
        ctx = origin_setup(make_ctx, tls=tls(names={DIRECT: [f"*.{ROOT}"]}))
        [finding] = (await OriginExposure().run(TARGET, ctx)).findings
        assert finding.kind == "surface.origin.exposed"
        assert finding.state["sites"] == [WWW], "a wildcard does not cover the bare domain"
        assert finding.confidence is Confidence.CANDIDATE
        assert finding.severity is Severity.LOW
        assert finding.evidence["matched_by_wildcard_only"] is True
        assert finding.severity_note and "wildcard" in finding.severity_note

    async def test_unconfirmed_candidate(self, make_ctx: Any) -> None:
        result = await OriginExposure().run(TARGET, origin_setup(make_ctx))
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "surface.origin.candidate"
        assert finding.severity is Severity.INFO
        assert finding.confidence is Confidence.CANDIDATE
        assert finding.asset_key == DIRECT
        assert finding.evidence["how_it_was_confirmed"].startswith("Not confirmed")
        assert "wildcard" in finding.evidence["possible_false_alarm"]

    async def test_certificate_for_an_unrelated_name_confirms_nothing(self, make_ctx: Any) -> None:
        ctx = origin_setup(make_ctx, tls=tls(mismatched={DIRECT: ["shop.other-company.com"]}))
        assert kinds(await OriginExposure().run(TARGET, ctx)) == ["surface.origin.candidate"]

    async def test_spf_ip4_entry_is_a_candidate(self, make_ctx: Any) -> None:
        ctx = origin_setup(
            make_ctx,
            dns=dns({ROOT: [CDN_IP], WWW: [CDN_IP_2]}),
            probe=probe({ROOT: "cloudflare", WWW: "cloudflare"}),
            email=email(spf=f"v=spf1 ip4:{OTHER_IP} ip6:2a01:4f8::1 include:_spf.google.com -all"),
        )
        result = await OriginExposure().run(TARGET, ctx)
        assert kinds(result) == ["surface.origin.candidate"] * 2
        by_key = {f.asset_key: f for f in result.findings}
        assert set(by_key) == {OTHER_IP, "2a01:4f8::1"}
        finding = by_key[OTHER_IP]
        assert finding.asset_type is AssetType.IP
        assert f"ip4:{OTHER_IP}" in finding.evidence["how_it_was_found"][0]
        assert "SPF record" in finding.evidence["how_it_was_found"][0]

    async def test_spf_entry_for_a_known_host_is_merged_and_confirmed(self, make_ctx: Any) -> None:
        ctx = origin_setup(
            make_ctx,
            email=email(spf=f"v=spf1 ip4:{ORIGIN_IP} -all"),
            tls=tls(mismatched={DIRECT: [WWW]}),
        )
        [finding] = (await OriginExposure().run(TARGET, ctx)).findings
        assert finding.kind == "surface.origin.exposed" and finding.asset_key == DIRECT
        assert len(finding.evidence["how_it_was_found"]) == 2

    async def test_spf_entries_that_are_wide_private_or_the_network_are_ignored(
        self, make_ctx: Any
    ) -> None:
        ctx = origin_setup(
            make_ctx,
            dns=dns({ROOT: [CDN_IP]}),
            probe=probe({ROOT: "cloudflare"}),
            email=email(
                spf="v=spf1 ip4:10.0.0.5 ip4:192.168.1.0/24 ip4:127.0.0.1 ip4:203.0.113.9 "
                "ip4:45.0.0.0/8 ip4:104.18.0.0/24 ip6:fd00::1 ip6:::1 ip4:999.1.1.1 "
                "ip4:2a01:4f8::1 ip4: -all"
            ),
        )
        result = await OriginExposure().run(TARGET, ctx)
        assert result.findings == []
        assert any("whole network" in n for n in result.notes)

    async def test_mail_server_inside_the_domain_is_a_candidate(
        self, make_ctx: Any, dns: Any
    ) -> None:
        mail_host = f"mx1.{ROOT}"
        dns_fake = dns
        dns_fake.add(mail_host, "A", [OTHER_IP])
        ctx = origin_setup(
            make_ctx,
            dns=globals()["dns"]({ROOT: [CDN_IP]}),
            probe=probe({ROOT: "cloudflare"}),
            email=email(mx=[mail_host, "aspmx.l.google.com"]),
        )
        result = await OriginExposure().run(TARGET, ctx)
        [finding] = result.findings
        assert finding.asset_key == mail_host
        assert finding.state == {"addresses": [OTHER_IP]}
        assert "MX records" in finding.evidence["how_it_was_found"][0]
        asked = {name for name, _ in dns_fake.queries}
        assert asked == {mail_host}, "only the organisation's own mail server is looked up"

    async def test_no_cdn_in_use(self, make_ctx: Any) -> None:
        ctx = origin_setup(
            make_ctx,
            dns=dns({ROOT: [ORIGIN_IP], DIRECT: [OTHER_IP]}),
            probe=probe({ROOT: "", DIRECT: ""}),
            email=email(spf=f"v=spf1 ip4:{OTHER_IP} -all"),
        )
        result = await OriginExposure().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert any("no hidden server" in n for n in result.notes)

    async def test_every_host_behind_the_cdn(self, make_ctx: Any) -> None:
        ctx = origin_setup(
            make_ctx,
            dns=dns({ROOT: [CDN_IP], WWW: [CDN_IP_2]}),
            probe=probe({ROOT: "cloudflare", WWW: "cloudflare"}),
        )
        result = await OriginExposure().run(TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert result.stats["behind_cdn"] == 2
        assert any("no address outside it" in n for n in result.notes)

    async def test_without_the_web_check_results_are_marked_less_certain(
        self, make_ctx: Any
    ) -> None:
        app = f"app.{ROOT}"
        ctx = origin_setup(
            make_ctx,
            dns=dns(
                {ROOT: [CDN_IP], app: ["13.32.1.1"], DIRECT: [ORIGIN_IP]},
                cnames={app: "d111111abcdef8.cloudfront.net"},
            ),
            probe=skipped(HttpProbe.spec, "probe module, not requested"),
            tls=skipped(TlsCerts.spec, "probe module, not requested"),
        )
        result = await OriginExposure().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert any("less certain" in n for n in result.notes)
        assert any("certificate check did not run" in n for n in result.notes)
        [finding] = result.findings
        assert finding.kind == "surface.origin.candidate" and finding.asset_key == DIRECT
        assert finding.evidence["content_delivery_network"] == ["Amazon CloudFront", "Cloudflare"]
        assert "did not run" in finding.evidence["how_it_was_confirmed"]

    async def test_without_the_web_check_and_no_cdn_recognised(self, make_ctx: Any) -> None:
        ctx = context(make_ctx, dns({ROOT: [ORIGIN_IP]}), email(), tls())
        result = await OriginExposure().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_private_and_reserved_addresses_are_ignored(self, make_ctx: Any) -> None:
        hosts = {
            ROOT: [CDN_IP],
            f"dev.{ROOT}": ["10.0.0.5"],
            f"old.{ROOT}": ["192.168.1.1"],
            f"staging.{ROOT}": ["127.0.0.1"],
            f"ftp.{ROOT}": ["203.0.113.7"],
            f"backend.{ROOT}": ["169.254.169.254"],
            f"origin.{ROOT}": ["100.64.0.1", "fd00::1"],
            f"mixed.{ROOT}": ["10.1.1.1", ORIGIN_IP],
        }
        ctx = origin_setup(
            make_ctx, dns=dns(hosts), probe=probe({ROOT: "cloudflare"}), tls=tls({ROOT: "WE1"})
        )
        result = await OriginExposure().run(TARGET, ctx)
        [finding] = result.findings
        assert finding.asset_key == f"mixed.{ROOT}"
        assert finding.state == {"addresses": [ORIGIN_IP]}
        assert "10." not in text_of(finding.evidence["addresses"])

    async def test_out_of_scope_and_wildcard_hostnames_are_ignored(self, make_ctx: Any) -> None:
        ghost = f"ghost.{ROOT}"
        hosts = {
            ROOT: [CDN_IP],
            "direct.other-company.com": [ORIGIN_IP],
            f"{ROOT}.evil.example": [ORIGIN_IP],
            f"not{ROOT}": [ORIGIN_IP],
            ghost: [OTHER_IP],
        }
        ctx = origin_setup(
            make_ctx,
            dns=dns(hosts, wildcard={ghost}),
            probe=probe({ROOT: "cloudflare", "direct.other-company.com": "cloudflare"}),
            tls=tls(mismatched={"direct.other-company.com": [ROOT]}),
            email=email(mx=["mail.other-company.com"]),
        )
        result = await OriginExposure().run(TARGET, ctx)
        assert result.findings == []
        assert result.stats["behind_cdn"] == 1

    async def test_hosts_on_the_network_are_never_candidates(self, make_ctx: Any) -> None:
        hosts = {
            ROOT: [CDN_IP],
            f"old.{ROOT}": ["172.67.1.1"],  # a Cloudflare address, though not flagged
            f"dev.{ROOT}": [CDN_IP],  # the same address as a fronted host
            f"cdn.{ROOT}": ["13.32.1.1"],
        }
        ctx = origin_setup(
            make_ctx,
            dns=dns(hosts, cnames={f"cdn.{ROOT}": "x.cloudfront.net"}),
            probe=probe({ROOT: "cloudflare", f"old.{ROOT}": "", f"cdn.{ROOT}": ""}),
        )
        assert (await OriginExposure().run(TARGET, ctx)).findings == []

    async def test_cap_on_unconfirmed_candidates(self, make_ctx: Any) -> None:
        hosts = {ROOT: [CDN_IP]}
        hosts.update({f"srv{n:02d}.{ROOT}": [f"45.33.40.{n + 1}"] for n in range(25)})
        hosts[DIRECT] = [ORIGIN_IP]
        ctx = origin_setup(make_ctx, dns=dns(hosts), probe=probe({ROOT: "cloudflare"}))
        result = await OriginExposure().run(TARGET, ctx)
        assert len(result.findings) == MAX_CANDIDATES == 10
        assert result.findings[0].asset_key == DIRECT, "classic names come first"
        assert result.status is ModuleStatus.PARTIAL
        assert any("Only the first 10" in n for n in result.notes)
        again = await OriginExposure().run(TARGET, ctx)
        assert [f.asset_key for f in again.findings] == [f.asset_key for f in result.findings]

    async def test_hostile_values(self, make_ctx: Any) -> None:
        resolved_names = dns({ROOT: [CDN_IP], DIRECT: [ORIGIN_IP]})
        resolved_names.assets.extend(
            [
                Asset(
                    type=AssetType.SUBDOMAIN,
                    key=f"-rf.{ROOT}",
                    attributes={"ips": [ORIGIN_IP]},
                    state={"resolves": True, "cname": None},
                ),
                Asset(
                    type=AssetType.SUBDOMAIN,
                    key=f"a b;curl evil|sh.{ROOT}",
                    attributes={"ips": [ORIGIN_IP]},
                    state={"resolves": True, "cname": None},
                ),
                Asset(
                    type=AssetType.SUBDOMAIN,
                    key=f"odd.{ROOT}",
                    attributes={
                        "ips": ["not-an-ip", 12345, None, "45.33.32.999", "1.2.3.4; id", "x" * 900],
                        "wildcard_match": "yes",
                    },
                    state={"resolves": True, "cname": {"nested": "value"}},
                ),
                Asset(
                    type=AssetType.SUBDOMAIN,
                    key=f"strings.{ROOT}",
                    attributes={"ips": ORIGIN_IP},
                    state={"resolves": True, "cname": "<script>alert(1)</script>"},
                ),
                Asset(
                    type=AssetType.SUBDOMAIN,
                    key=f"{'a' * 300}.{ROOT}",
                    attributes={"ips": [ORIGIN_IP]},
                    state={"resolves": True},
                ),
            ]
        )
        web = probe({ROOT: "<b>cloud\x00flare</b>; DROP TABLE" + "x" * 500})
        web.assets.append(
            Asset(type=AssetType.SUBDOMAIN, key="../../etc/passwd", attributes={"cdn": "evil"})
        )
        certs = tls(
            mismatched={DIRECT: [None, 7, "*.*", "<img src=x>", "a" * 400, {"x": 1}, f" {WWW}. "]},
            names={DIRECT: "not-a-list", f"-x.{ROOT}": [ROOT]},
        )
        mail = email(
            mx=[None, 5, "$(reboot)", f"mx;.{ROOT}", "a" * 500, {"host": ROOT}],
            spf="v=spf1 ip4:$(id) ip4:1.2.3.4/99 ip6:zz::1 ip4:" + "9" * 500 + " -all",
        )
        ctx = context(make_ctx, resolved_names, web, certs, mail, spf_chain())
        result = await OriginExposure().run(TARGET, ctx)
        assert [f.asset_key for f in result.findings] == [DIRECT]
        shown = text_of([f.model_dump() for f in result.findings]) + text_of(result.notes)
        for bad in ("<", ">", "\\u0000", ";", "$(", "DROP TABLE" + "x" * 50, "passwd"):
            assert bad not in shown
        assert result.findings[0].evidence["content_delivery_network"] == [
            ("bcloudflareb DROP TABLE" + "x" * 500)[:40]
        ]
        assert all(len(n) < 600 for n in result.notes)

    async def test_mail_attributes_of_the_wrong_shape(self, make_ctx: Any) -> None:
        mail = email()
        mail.assets[0].attributes = {"mx": "mail.example", "spf_record": ["v=spf1"]}
        ctx = origin_setup(make_ctx, email=mail)
        assert kinds(await OriginExposure().run(TARGET, ctx)) == ["surface.origin.candidate"]

    async def test_fails_without_dns_results(self, make_ctx: Any) -> None:
        result = await OriginExposure().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.FAILED and result.findings == []

    async def test_missing_email_check_is_partial(self, make_ctx: Any) -> None:
        ctx = origin_setup(make_ctx, email=None)
        result = await OriginExposure().run(TARGET, ctx)
        assert result.status is ModuleStatus.PARTIAL
        assert any("email check did not complete" in n for n in result.notes)

    async def test_makes_no_dns_lookups_when_everything_is_known(
        self, make_ctx: Any, dns: Any
    ) -> None:
        ctx = origin_setup(make_ctx, email=email(mx=[DIRECT]))
        await OriginExposure().run(TARGET, ctx)
        assert dns.queries == []

    async def test_no_em_dashes_in_text(self, make_ctx: Any) -> None:
        ctx = origin_setup(make_ctx, tls=tls(mismatched={DIRECT: [WWW]}))
        result = await OriginExposure().run(TARGET, ctx)
        assert "u2014" not in text_of([f.model_dump() for f in result.findings])


class TestOriginHelpers:
    def test_known_networks(self) -> None:
        assert cdn_of_address("104.18.0.1") == "Cloudflare"
        assert cdn_of_address("2606:4700::6810:1") == "Cloudflare"
        assert cdn_of_address("151.101.1.1") == "Fastly"
        assert cdn_of_address(ORIGIN_IP) is None
        assert cdn_of_address("nonsense") is None
        assert cdn_of_alias("acme.cdn.cloudflare.net") == "Cloudflare"
        assert cdn_of_alias("e1234.a.akamaiedge.net") == "Akamai"
        assert cdn_of_alias("notcloudfront.net") is None
        assert cdn_of_alias(None) is None

    @pytest.mark.parametrize(
        ("host", "label"),
        [
            (DIRECT, "direct"),
            (f"origin-www.{ROOT}", "origin"),
            (f"mail2.{ROOT}", "mail"),
            (f"www.staging.{ROOT}", "staging"),
            (f"developers.{ROOT}", None),
            (WWW, None),
            (ROOT, None),
        ],
    )
    def test_classic_names(self, host: str, label: str | None) -> None:
        assert classic_label(host, ROOT) == label

    def test_spf_addresses(self) -> None:
        found = spf_addresses("v=spf1 +ip4:45.33.32.156 IP4:5.9.10.0/24 ip6:2a01:4f8::1/128 -all")
        assert [str(network) for _, network in found] == [
            "2a01:4f8::1/128",
            "45.33.32.156/32",
            "5.9.10.0/24",
        ]
        assert spf_addresses(None) == []
        assert spf_addresses("v=spf1 " + "ip4:45.33.32.1 " * 5000) != []


# -- dependencies --------------------------------------------------------------


def full_set(**overrides: Any) -> list[ModuleResult]:
    parts: dict[str, ModuleResult | None] = {
        "dns": dns(
            {
                ROOT: [CDN_IP],
                f"docs.{ROOT}": ["76.76.21.21"],
                f"status.{ROOT}": ["52.1.2.3"],
                f"alias.{ROOT}": [CDN_IP],
            },
            cnames={
                f"docs.{ROOT}": "cname.vercel-dns.com",
                f"status.{ROOT}": "abc123.stspg-customer.com",
                f"alias.{ROOT}": ROOT,
            },
        ),
        "registration": registration(["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
        "email": email(
            mx=["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
            spf="v=spf1 include:_spf.google.com include:sendgrid.net ip4:45.33.32.156 -all",
        ),
        "probe": probe({ROOT: "cloudflare", f"docs.{ROOT}": ""}),
        "tls": tls({ROOT: "WE1", f"docs.{ROOT}": "R11"}),
        "frontend": frontend(
            {
                ROOT: [
                    {"inline": "ab" * 32},
                    {"src": f"https://{ROOT}/app.js", "sha256": "cd" * 32},
                    {"src": "https://cdn.jsdelivr.net/npm/x/x.js", "integrity": ""},
                    {"src": "https://www.googletagmanager.com/gtag/js", "integrity": ""},
                    {"src": f"https://static.{ROOT}/a.js", "integrity": ""},
                ]
            }
        ),
    }
    parts.update(overrides)
    return [p for p in parts.values() if p is not None]


def services(result: ModuleResult) -> list[dict[str, str]]:
    [finding] = result.findings
    listed: list[dict[str, str]] = finding.state["services"]
    return listed


def stamp(result: ModuleResult) -> tuple[str, str]:
    [finding] = result.findings
    return finding_fingerprint(ROOT, finding, b"k" * 32), finding_state_hash(finding)


class TestDependenciesSpec:
    def test_declares_what_it_is(self) -> None:
        spec = Dependencies.spec
        assert spec.name == "dependencies"
        assert spec.category is Category.SUPPLY_CHAIN
        assert spec.mode is ScanMode.PASSIVE
        assert set(spec.depends_on) == {
            "dns_resolve",
            "domain_registration",
            "email_posture",
            "http_probe",
            "tls_certs",
            "frontend",
        }
        assert spec.contacts == ()


class TestDependencies:
    async def test_each_source_contributes(self, make_ctx: Any, dns: Any) -> None:
        result = await Dependencies().run(TARGET, context(make_ctx, *full_set()))
        assert result.status is ModuleStatus.OK
        assert result.notes == []
        [finding] = result.findings
        assert finding.kind == "supply_chain.dependencies"
        assert finding.severity is Severity.INFO
        assert finding.asset_key == ROOT and finding.asset_type is AssetType.DOMAIN
        assert services(result) == [
            {"service": "Atlassian Statuspage", "role": "hosting"},
            {"service": "Cloudflare", "role": "cdn"},
            {"service": "Cloudflare", "role": "dns"},
            {"service": "Google Tag Manager", "role": "scripts"},
            {"service": "Google Trust Services", "role": "certificates"},
            {"service": "Google Workspace", "role": "mail"},
            {"service": "Google Workspace", "role": "mail_sending"},
            {"service": "jsDelivr", "role": "scripts"},
            {"service": "Let's Encrypt", "role": "certificates"},
            {"service": "SendGrid", "role": "mail_sending"},
            {"service": "Vercel", "role": "hosting"},
        ]
        assert all(entry["role"] in ROLES for entry in services(result))
        assert finding.title == f"{ROOT} relies on 9 outside services"
        assert dns.queries == [], "nothing is looked up"

    async def test_evidence_is_grouped_by_role_and_names_the_record(self, make_ctx: Any) -> None:
        result = await Dependencies().run(TARGET, context(make_ctx, *full_set()))
        evidence = result.findings[0].evidence
        assert evidence["dns"] == [
            {
                "service": "Cloudflare",
                "revealed_by": [
                    "nameserver ada.ns.cloudflare.com in the registration record",
                    "nameserver bob.ns.cloudflare.com in the registration record",
                ],
            }
        ]
        assert evidence["mail"][0]["revealed_by"][0] == (
            "mail server aspmx.l.google.com in your MX records"
        )
        sending = {e["service"]: e["revealed_by"] for e in evidence["mail_sending"]}
        assert sending["SendGrid"] == ["include:sendgrid.net in your SPF record"]
        hosting = {e["service"]: e["revealed_by"] for e in evidence["hosting"]}
        assert hosting["Vercel"] == [f"docs.{ROOT} is an alias for cname.vercel-dns.com"]
        assert evidence["cdn"][0]["revealed_by"] == [f"{ROOT} is served through it"]
        assert evidence["scripts"][1]["revealed_by"] == [
            f"{ROOT} loads a script from cdn.jsdelivr.net"
        ]
        assert "other" not in evidence
        assert evidence["not_read_this_time"] == []

    async def test_nameservers_seen_in_dns_are_used(self, make_ctx: Any) -> None:
        parts = full_set(
            registration=None,
            dns=dns({ROOT: [CDN_IP]}, nameservers=["ns-1.awsdns-12.org.", "NS-2.AWSDNS-40.CO.UK"]),
        )
        result = await Dependencies().run(TARGET, context(make_ctx, *parts))
        assert {"service": "Amazon Route 53", "role": "dns"} in services(result)

    async def test_unknown_domains_are_listed_by_registrable_domain(self, make_ctx: Any) -> None:
        parts = full_set(
            dns=dns(
                {f"shop.{ROOT}": ["45.33.32.1"]},
                cnames={f"shop.{ROOT}": "stores.eu.small-host.co.uk"},
            ),
            registration=registration(["ns1.tiny-dns.example.io"]),
            email=email(mx=["mx.mailhost.de"], spf="v=spf1 redirect=_spf.senders.fr"),
            frontend=frontend({ROOT: [{"src": "https://a.b.widgets.dev/w.js", "integrity": ""}]}),
            tls=tls({ROOT: "Example Corp Issuing CA 7"}),
            probe=probe({ROOT: "somecdn"}),
        )
        result = await Dependencies().run(TARGET, context(make_ctx, *parts))
        assert services(result) == [
            {"service": "Example Corp Issuing CA 7", "role": "certificates"},
            {"service": "example.io", "role": "dns"},
            {"service": "mailhost.de", "role": "mail"},
            {"service": "senders.fr", "role": "mail_sending"},
            {"service": "small-host.co.uk", "role": "other"},
            {"service": "somecdn", "role": "cdn"},
            {"service": "widgets.dev", "role": "scripts"},
        ]

    async def test_the_organisations_own_names_are_not_dependencies(self, make_ctx: Any) -> None:
        parts = full_set(
            dns=dns({f"a.{ROOT}": [CDN_IP]}, cnames={f"a.{ROOT}": f"b.{ROOT}"}),
            registration=registration([f"ns1.{ROOT}"]),
            email=email(mx=[f"mail.{ROOT}"], spf=f"v=spf1 include:spf.{ROOT} a mx -all"),
            frontend=frontend({ROOT: [{"src": f"https://cdn.{ROOT}/x.js", "integrity": ""}]}),
            tls=tls(),
            probe=probe({ROOT: ""}),
        )
        result = await Dependencies().run(TARGET, context(make_ctx, *parts))
        assert result.status is ModuleStatus.OK
        assert services(result) == []
        assert result.findings[0].title == f"{ROOT} relies on 0 outside services"

    async def test_state_holds_no_addresses_and_survives_rotation(self, make_ctx: Any) -> None:
        before = await Dependencies().run(TARGET, context(make_ctx, *full_set()))
        rotated = full_set()
        for asset in rotated[0].assets:
            asset.attributes["ips"] = ["172.67.9.9", "2606:4700::1"]
        after = await Dependencies().run(TARGET, context(make_ctx, *rotated))
        assert stamp(before) == stamp(after)
        state = text_of(before.findings[0].state)
        assert not _IP_RE.search(state)
        for entry in services(before):
            assert set(entry) == {"service", "role"}
            with pytest.raises(ValueError):
                ipaddress.ip_address(entry["service"])

    async def test_rotating_issuer_names_do_not_change_state(self, make_ctx: Any) -> None:
        before = await Dependencies().run(
            TARGET, context(make_ctx, *full_set(tls=tls({ROOT: "R10"})))
        )
        after = await Dependencies().run(
            TARGET, context(make_ctx, *full_set(tls=tls({ROOT: "R11"})))
        )
        assert stamp(before) == stamp(after)

    async def test_added_service_changes_state_but_not_identity(self, make_ctx: Any) -> None:
        before = await Dependencies().run(TARGET, context(make_ctx, *full_set()))
        added = full_set(
            email=email(
                mx=["aspmx.l.google.com"],
                spf="v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org -all",
            )
        )
        after = await Dependencies().run(TARGET, context(make_ctx, *added))
        assert stamp(before)[0] == stamp(after)[0]
        assert stamp(before)[1] != stamp(after)[1]
        new = [e for e in services(after) if e not in services(before)]
        assert new == [{"service": "Mailgun", "role": "mail_sending"}]

    async def test_missing_source_is_partial_and_said_plainly(self, make_ctx: Any) -> None:
        full = await Dependencies().run(TARGET, context(make_ctx, *full_set()))
        parts = full_set(frontend=skipped(Frontend.spec, "probe module, not requested"))
        result = await Dependencies().run(TARGET, context(make_ctx, *parts))
        assert result.status is ModuleStatus.PARTIAL
        [note] = result.notes
        assert "website script check did not run" in note
        assert "does not mean those services are gone" in note
        evidence = result.findings[0].evidence
        assert evidence["not_read_this_time"] == ["the website script check"]
        assert "scripts" not in evidence
        kept = [e for e in services(full) if e["role"] != "scripts"]
        assert services(result) == kept, "everything from the other sources is still listed"
        # The shorter list is a different finding, so comparing scans cannot report
        # the scripts as removed. The full list is carried as not re-checked.
        assert stamp(result)[0] != stamp(full)[0]

    @pytest.mark.parametrize("absent", ["dns", "registration", "email", "probe", "tls", "frontend"])
    async def test_any_missing_source_is_partial(self, make_ctx: Any, absent: str) -> None:
        result = await Dependencies().run(TARGET, context(make_ctx, *full_set(**{absent: None})))
        assert result.status is ModuleStatus.PARTIAL
        assert len(result.notes) == 1 and "did not run" in result.notes[0]
        assert len(result.findings) == 1

    async def test_failed_source_counts_as_missing(self, make_ctx: Any) -> None:
        failed = ModuleResult(module="tls_certs", status=ModuleStatus.FAILED)
        result = await Dependencies().run(TARGET, context(make_ctx, *full_set(tls=failed)))
        assert result.status is ModuleStatus.PARTIAL
        assert all(e["role"] != "certificates" for e in services(result))

    async def test_incomplete_source_is_partial(self, make_ctx: Any) -> None:
        web = probe({ROOT: "cloudflare"})
        web.status = ModuleStatus.PARTIAL
        result = await Dependencies().run(TARGET, context(make_ctx, *full_set(probe=web)))
        assert result.status is ModuleStatus.PARTIAL
        assert any("was incomplete" in n for n in result.notes)
        assert {"service": "Cloudflare", "role": "cdn"} in services(result)

    async def test_nothing_to_read_fails_without_a_finding(self, make_ctx: Any) -> None:
        result = await Dependencies().run(TARGET, make_ctx())
        assert result.status is ModuleStatus.FAILED
        assert result.findings == []

    async def test_hostile_values(self, make_ctx: Any) -> None:
        names = dns(
            {
                f"a.{ROOT}": [CDN_IP],
                f"b.{ROOT}": [CDN_IP],
                f"c.{ROOT}": [CDN_IP],
                f"d.{ROOT}": [CDN_IP],
                "x.other-company.com": [CDN_IP],
            },
            cnames={
                f"a.{ROOT}": "<script>alert(1)</script>.evil.com",
                f"b.{ROOT}": "10.0.0.1",
                f"c.{ROOT}": "host.internal",
                f"d.{ROOT}": "$(reboot).example.io",
                "x.other-company.com": "cname.vercel-dns.com",
            },
        )
        names.assets[0].state["cname"] = {"not": "text"}
        parts = full_set(
            dns=names,
            registration=registration(
                [None, 9, "8.8.8.8", "ns1;rm -rf.example.io", "a" * 600, "-ns.example.io"]
            ),
            email=email(
                mx=["1.2.3.4", None, "mx`id`.example.io", {"a": 1}, "x" * 400],
                spf="v=spf1 include:%{i}.evil.io include:<b>.evil.io include:9.9.9.9 "
                "include:" + "a" * 300 + ".io include: -all",
            ),
            probe=probe({ROOT: "203.0.113.5", f"a.{ROOT}": "<i>x</i>\x00" + "y" * 300}),
            tls=tls({ROOT: "10.1.2.3 CA", f"a.{ROOT}": "<b>Bad\nIssuer</b>;" + "z" * 300}),
            frontend=frontend(
                {
                    ROOT: [
                        "text",
                        None,
                        {"src": 5, "integrity": ""},
                        {"src": "https://[::1]/x.js", "integrity": ""},
                        {"src": "https://192.0.2.1/x.js", "integrity": ""},
                        {"src": "javascript:alert(1)", "integrity": ""},
                        {"src": "https://evil.com\\@good.com/x.js", "integrity": ""},
                        {"src": "https://" + "a" * 5000 + ".com/x.js", "integrity": ""},
                        {"src": "https://[broken/x.js", "integrity": ""},
                    ],
                    "evil.other-company.com": [
                        {"src": "https://cdn.jsdelivr.net/x.js", "integrity": ""}
                    ],
                }
            ),
        )
        result = await Dependencies().run(TARGET, context(make_ctx, *parts))
        listed = services(result)
        shown = text_of(result.findings[0].model_dump()) + text_of(result.notes)
        for bad in ("<", ">", "\\u0000", "\\n", "$(", "`", ";", "@", "evil", "good.com"):
            assert bad not in shown
        assert not _IP_RE.search(text_of(listed))
        assert all(len(e["service"]) <= 60 for e in listed)
        assert {e["role"] for e in listed} == {"cdn", "certificates"}
        assert "Vercel" not in text_of(listed), "out-of-scope hosts contribute nothing"
        assert "jsDelivr" not in text_of(listed)

    async def test_counts_are_capped(self, make_ctx: Any) -> None:
        many = [f"ns{n}.provider-{n}.io" for n in range(2000)]
        result = await Dependencies().run(
            TARGET, context(make_ctx, *full_set(registration=registration(many)))
        )
        assert len(services(result)) <= 150
        assert result.status is ModuleStatus.PARTIAL
        assert any("cut short" in n for n in result.notes)

    async def test_no_em_dashes_in_text(self, make_ctx: Any) -> None:
        parts = full_set(frontend=None)
        result = await Dependencies().run(TARGET, context(make_ctx, *parts))
        assert "u2014" not in text_of(result.model_dump())


class TestServiceNames:
    @pytest.mark.parametrize(
        ("domain", "service"),
        [
            ("cloudflare.com", "Cloudflare"),
            ("cloudflare.net", "Cloudflare"),
            ("google.com", "Google Workspace"),
            ("googlemail.com", "Google Workspace"),
            ("amazonaws.com", "Amazon Web Services"),
            ("vercel-dns.com", "Vercel"),
            ("vercel.app", "Vercel"),
            ("awsdns-07.co.uk", "Amazon Route 53"),
            ("unknown-provider.io", "unknown-provider.io"),
        ],
    )
    def test_mapping(self, domain: str, service: str) -> None:
        assert service_for(domain)[0] == service

    @pytest.mark.parametrize(
        ("issuer", "name"),
        [
            ("R3", "Let's Encrypt"),
            ("E6", "Let's Encrypt"),
            ("WE1", "Google Trust Services"),
            ("GTS CA 1P5", "Google Trust Services"),
            ("Amazon RSA 2048 M02", "Amazon Trust Services"),
            ("DigiCert Global G2 TLS RSA SHA256 2020 CA1", "DigiCert"),
            ("Sectigo RSA Domain Validation Secure Server CA", "Sectigo"),
            ("ZeroSSL ECC Domain Secure Site CA", "ZeroSSL"),
            ("", None),
            (None, None),
            ("192.168.1.1", None),
        ],
    )
    def test_issuers(self, issuer: Any, name: str | None) -> None:
        assert issuer_name(issuer) == name

    def test_every_entry_is_sound(self) -> None:
        raw = resources.files("perimeterwatch.data").joinpath("service_names.json").read_text()
        data = json.loads(raw)
        entries = data["services"]
        assert 80 <= len(entries) <= 120
        domains = [entry["domain"] for entry in entries]
        assert len(domains) == len(set(domains)), "a domain is listed twice"
        for entry in entries:
            assert set(entry) == {"domain", "service", "usual_role"}
            domain = entry["domain"]
            assert isinstance(domain, str) and domain == domain.lower().strip()
            assert validate_hostname(domain) == domain
            assert registrable_domain(domain) == domain, f"{domain} is not registrable"
            service = entry["service"]
            assert isinstance(service, str) and service.strip() == service and service
            assert len(service) <= 60
            assert entry["usual_role"] in ROLES
        # One operator is always spelt the same way.
        spellings: dict[str, set[str]] = {}
        for entry in entries:
            spellings.setdefault(entry["service"].lower(), set()).add(entry["service"])
        assert all(len(found) == 1 for found in spellings.values())
        for entry in data["patterns"]:
            re.compile(entry["pattern"])
            assert entry["service"].strip() and entry["usual_role"] in ROLES
        assert len(service_table().domains) == len(entries)
