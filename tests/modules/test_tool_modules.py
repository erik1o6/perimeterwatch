"""Modules that drive external tools, tested against recorded tool output."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from perimeterwatch.core.models import (
    AuthLevel,
    ModuleStatus,
    ScanMode,
    Sensitivity,
    Severity,
    Target,
)
from perimeterwatch.modules import github_secrets, http_probe, nuclei_safe, ports, tls_certs
from perimeterwatch.modules.github_secrets import GitHubSecrets, parse_result
from perimeterwatch.modules.http_probe import HttpProbe
from perimeterwatch.modules.nuclei_safe import NucleiSafe
from perimeterwatch.modules.ports import Ports
from perimeterwatch.modules.tls_certs import TlsCerts, expiry_bucket, name_matches
from perimeterwatch.safety.targets import contactable_hosts
from tests.conftest import CANARY, FIXTURES, ROOT, fixture_text
from tests.helpers import FakeRunner, install_fake_tools, resolved

APP = f"app.{ROOT}"
PUBLIC_IP = "104.18.0.1"
TARGET = Target(root_domain=ROOT, github_org="acme-protocol")


def as_public(text: str) -> str:
    """Recorded output is from a local test server. Present it as a public host."""
    return (
        text.replace("127.0.0.1:18443", APP).replace('"host":"127.0.0.1"', f'"host":"{APP}"')
        .replace("127.0.0.1", PUBLIC_IP)
    )  # fmt: skip


@pytest.fixture
def tools(tmp_path: Path) -> Path:
    return install_fake_tools(
        tmp_path / "tools", "httpx", "tlsx", "naabu", "nuclei", "nuclei-templates", "trufflehog"
    )


@pytest.fixture
def ctx(make_ctx: Any, tools: Path) -> Any:
    context = make_ctx(mode=ScanMode.ACTIVE, level=AuthLevel.DNS_VERIFIED, tools_dir=tools)
    context.assets.add(
        resolved(
            {
                ROOT: [PUBLIC_IP],
                APP: [PUBLIC_IP],
                f"intranet.{ROOT}": ["10.0.0.5"],
                f"mixed.{ROOT}": ["104.18.0.2", "192.168.1.1"],
                f"gone.{ROOT}": [],
                f"ghost.{ROOT}": ["203.0.113.7"],
                "app.other-company.com": ["104.18.0.9"],
                f"-oops.{ROOT}": ["104.18.0.3"],
            },
            wildcard={f"ghost.{ROOT}"},
            root=ROOT,
        )
    )
    return context


class TestContactableHosts:
    def test_only_public_in_scope_hosts_qualify(self, ctx: Any) -> None:
        targets = contactable_hosts(ctx)
        assert targets.names == [ROOT, APP]
        assert "private" in targets.excluded[f"intranet.{ROOT}"]
        assert "private" in targets.excluded[f"mixed.{ROOT}"], "one private address is enough"
        assert "outside" in targets.excluded["app.other-company.com"]
        assert f"-oops.{ROOT}" in targets.excluded
        assert targets.owner_of(PUBLIC_IP) == [ROOT, APP]

    @pytest.mark.parametrize(
        ("entry", "blocked"),
        [
            (APP, [APP]),
            (ROOT, [ROOT, APP]),
            (PUBLIC_IP, [ROOT, APP]),
            ("104.18.0.0/16", [ROOT, APP]),
            ("  APP.ACME-PROTOCOL.XYZ.  ", [APP]),
            ("other.example", []),
            ("203.0.113.0/24", []),
            ("", []),
        ],
    )
    def test_do_not_contact_list(self, ctx: Any, entry: str, blocked: list[str]) -> None:
        ctx.settings.never_contact = [entry]
        targets = contactable_hosts(ctx)
        assert [h for h in (ROOT, APP) if h not in targets.names] == blocked
        for host in blocked:
            assert targets.excluded[host] == "on the do-not-contact list"

    def test_limit(self, ctx: Any) -> None:
        targets = contactable_hosts(ctx, limit=1)
        assert targets.names == [ROOT] and targets.truncated


class TestHttpProbe:
    async def test_reads_recorded_output(self, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner({"httpx": as_public(fixture_text("httpx", "local.jsonl"))})
        monkeypatch.setattr(http_probe, "run_tool", runner)
        result = await HttpProbe().run(TARGET, ctx)
        [asset] = result.assets
        assert asset.key == APP
        assert asset.attributes["http_title"] == "Fixture & Test Page"
        assert asset.attributes["web_server"] == "nginx/1.24.0"
        assert "WordPress:6.4" in asset.attributes["tech"]
        assert asset.state == {"web": True, "https": True}
        assert result.findings == []

    async def test_only_vetted_hosts_are_given_to_the_tool(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = FakeRunner()
        monkeypatch.setattr(http_probe, "run_tool", runner)
        await HttpProbe().run(TARGET, ctx)
        call = runner.last("httpx")
        assert call["files"]["httpx-targets.txt"].split() == [ROOT, APP]
        args = call["args"]
        # No hostname on the command line, no redirects followed, identifiable agent.
        assert not any(ROOT in a for a in args if not a.startswith(("/", "User-Agent")))
        assert args[args.index("-maxr") + 1] == "0"
        assert "-random-agent=false" in args
        assert any(a.startswith("User-Agent: perimeterwatch/") for a in args)

    async def test_answers_from_private_addresses_are_discarded(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # DNS changed between vetting and probing: the tool reports a loopback address.
        rebound = fixture_text("httpx", "local.jsonl").replace("127.0.0.1:18443", APP)
        monkeypatch.setattr(http_probe, "run_tool", FakeRunner({"httpx": rebound}))
        result = await HttpProbe().run(TARGET, ctx)
        assert result.assets == []
        assert any("non-public address" in n for n in result.notes)

    async def test_hosts_the_tool_was_not_given_are_ignored(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stray = as_public(fixture_text("httpx", "local.jsonl")).replace(APP, "evil.example.net")
        monkeypatch.setattr(http_probe, "run_tool", FakeRunner({"httpx": stray}))
        assert (await HttpProbe().run(TARGET, ctx)).assets == []

    async def test_plain_http_is_reported(self, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        row = json.loads(as_public(fixture_text("httpx", "local.jsonl")))
        row.update(scheme="http", url=f"http://{APP}")
        monkeypatch.setattr(http_probe, "run_tool", FakeRunner({"httpx": json.dumps(row)}))
        result = await HttpProbe().run(TARGET, ctx)
        assert [f.kind for f in result.findings] == ["http.no_https_redirect"]


class TestTlsCerts:
    async def test_reads_recorded_output(self, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner({"tlsx": as_public(fixture_text("tlsx", "local.jsonl"))})
        monkeypatch.setattr(tls_certs, "run_tool", runner)
        monkeypatch.setattr(tls_certs, "utcnow", lambda: datetime(2026, 9, 29, 13, 0, tzinfo=UTC))
        result = await TlsCerts().run(TARGET, ctx)
        kinds = {f.kind: f for f in result.findings}
        assert set(kinds) == {
            "tls.cert.expiring", "tls.cert.hostname_mismatch", "tls.cert.self_signed",
        }  # fmt: skip
        expiring = kinds["tls.cert.expiring"]
        assert expiring.state == {"bucket": "14d"}
        assert expiring.identity["cert_sha256"].startswith("009d9445")
        assert result.assets[0].attributes["cert_expires"] == "2026-10-09"

    async def test_expired(self, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            tls_certs,
            "run_tool",
            FakeRunner({"tlsx": as_public(fixture_text("tlsx", "local.jsonl"))}),
        )
        monkeypatch.setattr(tls_certs, "utcnow", lambda: datetime(2026, 12, 1, tzinfo=UTC))
        result = await TlsCerts().run(TARGET, ctx)
        expired = next(f for f in result.findings if f.kind == "tls.cert.expired")
        assert expired.severity is Severity.HIGH

    def test_buckets_change_only_at_boundaries(self) -> None:
        now = datetime(2026, 9, 1, tzinfo=UTC)
        cases = {
            60: None,
            31: None,
            30: "30d",
            15: "30d",
            14: "14d",
            8: "14d",
            7: "7d",
            1: "7d",
            -1: "expired",
        }
        for days, expected in cases.items():
            assert expiry_bucket(now + timedelta(days=days), now) == expected, days

    def test_name_matching(self) -> None:
        assert name_matches(APP, [APP])
        assert name_matches(APP, [f"*.{ROOT}"])
        assert not name_matches(f"a.b.{ROOT}", [f"*.{ROOT}"]), "a wildcard covers one level"
        assert not name_matches(APP, ["fixture.test"])
        assert not name_matches(ROOT, [f"*.{ROOT}"])

    async def test_works_without_tlsx(
        self, make_ctx: Any, ctx: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        bare = make_ctx(mode=ScanMode.PROBE, tools_dir=tmp_path / "none")
        bare.assets.add(ctx.assets.get("dns_resolve"))
        seen: list[tuple[str, str]] = []

        def fake_fetch(host: str, ip: str, timeout: float = 8.0) -> dict[str, Any]:
            seen.append((host, ip))
            return {"host": host, "ip": ip, "not_after": "2027-06-01T00:00:00+00:00",
                    "subject_an": [host], "issuer_cn": "R11", "self_signed": False,
                    "fingerprint_hash": {"sha256": "ab" * 32}}  # fmt: skip

        monkeypatch.setattr(tls_certs, "fetch_certificate", fake_fetch)
        result = await TlsCerts().run(TARGET, bare)
        assert seen == [(ROOT, PUBLIC_IP), (APP, PUBLIC_IP)], "connects to the vetted address"
        assert result.findings == []
        assert any("tlsx is not installed" in n for n in result.notes)


class TestPorts:
    async def test_scans_vetted_addresses_and_reports_unexpected_ports(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            {"ip": PUBLIC_IP, "port": 443, "protocol": "tcp"},
            {"ip": PUBLIC_IP, "port": 8545, "protocol": "tcp"},
            {"ip": PUBLIC_IP, "port": 8080, "protocol": "tcp"},
            {"ip": PUBLIC_IP, "port": 8080, "protocol": "tcp"},
            {"ip": "10.0.0.5", "port": 22, "protocol": "tcp"},
            {"ip": PUBLIC_IP, "port": "22; rm -rf /", "protocol": "tcp"},
            {"ip": PUBLIC_IP, "port": 99999, "protocol": "tcp"},
        ]
        runner = FakeRunner({"naabu": "\n".join(json.dumps(r) for r in rows)})
        monkeypatch.setattr(ports, "run_tool", runner)
        result = await Ports().run(TARGET, ctx)

        call = runner.last("naabu")
        assert call["files"]["naabu-targets.txt"].split() == [PUBLIC_IP]
        args = call["args"]
        assert args[args.index("-s") + 1] == "c", "connect scan, not raw packets"
        assert "-ec" in args, "CDN addresses are excluded"
        assert int(args[args.index("-rate") + 1]) <= 100

        by_port = {f.identity["port"]: f for f in result.findings}
        assert set(by_port) == {"8545", "8080"}
        assert by_port["8545"].severity is Severity.HIGH
        assert "Ethereum JSON-RPC" in by_port["8545"].title
        assert by_port["8080"].severity is Severity.MEDIUM
        assert by_port["8080"].evidence["hosts"] == [ROOT, APP]

    async def test_ipv6_is_scanned_and_ipv6_only_ports_are_reported(
        self, make_ctx: Any, tools: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        v6 = "2606:4700:4700::1111"
        ctx = make_ctx(mode=ScanMode.ACTIVE, level=AuthLevel.DNS_VERIFIED, tools_dir=tools)
        ctx.assets.add(resolved({APP: [PUBLIC_IP, v6], f"v4only.{ROOT}": ["104.18.0.7"]}))
        monkeypatch.setattr(ports, "has_ipv6_route", lambda: True)
        rows = [
            {"ip": PUBLIC_IP, "port": 443}, {"ip": v6, "port": 443},
            {"ip": v6, "port": 22}, {"ip": v6, "port": 6379},
            {"ip": "104.18.0.7", "port": 8080},
        ]  # fmt: skip
        runner = FakeRunner({"naabu": "\n".join(json.dumps(r) for r in rows)})
        monkeypatch.setattr(ports, "run_tool", runner)
        result = await Ports().run(TARGET, ctx)

        assert v6 in runner.last("naabu")["files"]["naabu-targets.txt"].split()
        only = {f.identity["port"]: f for f in result.findings if f.kind == "ports.ipv6_only_open"}
        assert set(only) == {"22", "6379"}, "443 is open on both, so it is not reported"
        assert only["6379"].severity is Severity.HIGH and "Redis" in only["6379"].title
        assert only["22"].asset_key == APP
        assert not any(f.asset_key == f"v4only.{ROOT}" for f in only.values())

    async def test_ipv6_is_left_out_when_this_machine_cannot_reach_it(
        self, make_ctx: Any, tools: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        v6 = "2606:4700:4700::1111"
        ctx = make_ctx(mode=ScanMode.ACTIVE, level=AuthLevel.DNS_VERIFIED, tools_dir=tools)
        ctx.assets.add(resolved({APP: [PUBLIC_IP, v6]}))
        monkeypatch.setattr(ports, "has_ipv6_route", lambda: False)
        runner = FakeRunner({"naabu": json.dumps({"ip": PUBLIC_IP, "port": 443})})
        monkeypatch.setattr(ports, "run_tool", runner)
        result = await Ports().run(TARGET, ctx)
        assert runner.last("naabu")["files"]["naabu-targets.txt"].split() == [PUBLIC_IP]
        assert any("no IPv6 connection" in n for n in result.notes)
        assert not [f for f in result.findings if f.kind == "ports.ipv6_only_open"]

    async def test_recorded_output_for_an_unvetted_address_is_ignored(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ports, "run_tool", FakeRunner({"naabu": fixture_text("naabu", "local.jsonl")})
        )
        assert (await Ports().run(TARGET, ctx)).findings == []


class TestNucleiSafe:
    @pytest.fixture
    def with_web(self, ctx: Any, tools: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        from perimeterwatch.core.models import Asset, AssetType, ModuleResult
        from perimeterwatch.tools.locate import manifest

        ctx.assets.add(
            ModuleResult(
                module="http_probe",
                status=ModuleStatus.OK,
                assets=[
                    Asset(type=AssetType.SUBDOMAIN, key=APP, state={"web": True, "https": True}),
                    Asset(type=AssetType.SUBDOMAIN, key="app.other-company.com",
                          state={"web": True, "https": True}),
                ],
            )
        )  # fmt: skip
        pin = manifest()["nuclei-templates"]
        target = tools / pin.name / pin.version / pin.binary
        target.rmdir()
        target.symlink_to(FIXTURES / "nuclei_templates", target_is_directory=True)
        return ctx

    async def test_runs_only_admitted_templates_against_vetted_servers(
        self, with_web: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            {"template-id": "git-config", "host": APP, "ip": PUBLIC_IP, "matcher-name": "",
             "matched-at": f"https://{APP}/.git/config",
             "info": {"name": "Git Configuration - Detect", "severity": "medium",
                      "description": "Git config is readable."}},
            {"template-id": "waf-detect", "host": APP, "ip": PUBLIC_IP, "info": {"severity": "info"}},
            {"template-id": "CVE-2099-0001", "host": APP, "ip": PUBLIC_IP,
             "info": {"severity": "critical"}},
            {"template-id": "git-config", "host": "app.other-company.com", "ip": "104.18.0.9",
             "info": {"severity": "medium"}},
            {"template-id": "git-config", "host": APP, "ip": "127.0.0.1", "info": {"severity": "medium"}},
        ]  # fmt: skip
        runner = FakeRunner({"nuclei": "\n".join(json.dumps(r) for r in rows)})
        monkeypatch.setattr(nuclei_safe, "run_tool", runner)
        result = await NucleiSafe().run(TARGET, with_web)

        call = runner.last("nuclei")
        assert call["files"]["nuclei-targets.txt"].split() == [f"https://{APP}"]
        templates = call["files"]["nuclei-templates.txt"].split()
        assert sorted(Path(t).name for t in templates) == ["git-config.yaml", "renamed-file.yaml"]
        for flag in ("-ni", "-lna", "-duc", "-or"):
            assert flag in call["args"], flag
        for forbidden in ("-tags", "-dast", "-fuzz", "-headless", "-code", "-lfa", "-itags"):
            assert forbidden not in call["args"], forbidden

        [finding] = result.findings
        assert finding.identity["template"] == "git-config"
        assert finding.asset_key == APP
        assert finding.severity is Severity.MEDIUM

    async def test_recorded_output_is_parsed(
        self, with_web: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded = as_public(fixture_text("nuclei", "local.jsonl")).replace(
            f'"host":"{PUBLIC_IP}"', f'"host":"{APP}"'
        )
        monkeypatch.setattr(nuclei_safe, "run_tool", FakeRunner({"nuclei": recorded}))
        result = await NucleiSafe().run(TARGET, with_web)
        # The recording holds tech-detect, headers, waf-detect, nginx-eol and nginx-version.
        # Only nginx-version is both admitted by the fixture templates and not ignored.
        assert [f.identity["template"] for f in result.findings] == ["nginx-version"]

    async def test_needs_web_servers_to_be_identified_first(self, ctx: Any) -> None:
        result = await NucleiSafe().run(TARGET, ctx)
        assert result.status is ModuleStatus.FAILED


class TestGitHubSecrets:
    @pytest.fixture
    def token(self, monkeypatch: pytest.MonkeyPatch) -> str:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtokentesttokentesttokentest1234")
        return "ghp_testtokentesttokentesttokentest1234"

    async def test_secrets_are_redacted_and_never_tested(
        self, ctx: Any, token: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = FakeRunner({"trufflehog": fixture_text("trufflehog", "org.jsonl")})
        monkeypatch.setattr(github_secrets, "run_tool", runner)
        result = await GitHubSecrets().run(TARGET, ctx)

        call = runner.last("trufflehog")
        assert "--no-verification" in call["args"]
        assert "--only-verified" not in call["args"]
        assert "--org=acme-protocol" in call["args"]
        assert token not in " ".join(call["args"]), "the token must not be on the command line"
        assert call["env"] == {"GITHUB_TOKEN": token}

        assert len(result.findings) == 2, "duplicates are merged"
        dumped = result.model_dump_json()
        assert CANARY not in dumped
        assert "AKIAIOSFODNN7EXAMPLE" not in dumped
        assert "ghp_CANARYcanaryCANARY" not in dumped, "trufflehog's own redaction shows too much"
        assert "ana.lopez" not in dumped, "the committer's address is personal data"

        first = next(f for f in result.findings if f.asset_key == "acme-protocol/deploy-scripts")
        assert first.sensitivity is Sensitivity.SECRET
        assert first.severity is Severity.HIGH
        assert first.evidence["starts_with"] == "ghp_********"
        assert first.evidence["tested"] == "no"
        assert first.evidence["file"] == "scripts/release.sh"
        assert len(first.identity["hash"]) == 8

    def test_short_secrets_show_nothing(self) -> None:
        row = {"DetectorName": "Pin", "Raw": "hunter2",
               "SourceMetadata": {"Data": {"Github": {"repository": "https://github.com/a/b.git"}}}}  # fmt: skip
        parsed = parse_result(row)
        assert parsed is not None
        assert parsed["starts_with"] == "********"
        assert "hunter2" not in json.dumps(parsed)

    @pytest.mark.parametrize(
        "row",
        [{}, {"Raw": "x"}, {"DetectorName": "X", "Raw": ""}, {"DetectorName": "X", "Raw": 5},
         {"DetectorName": "X", "Raw": "abcdefghijklmnop", "SourceMetadata": "nonsense"},
         {"DetectorName": "X", "Raw": "abcdefghijklmnop", "SourceMetadata": {"Data": {"Github": []}}}],
    )  # fmt: skip
    def test_malformed_rows_are_skipped(self, row: dict[str, Any]) -> None:
        try:
            assert parse_result(row) is None
        except AttributeError:
            pytest.fail("malformed tool output must not crash the module")


def test_certificate_names_keep_only_plain_hostnames() -> None:
    from perimeterwatch.modules.tls_certs import certificate_names

    row = {
        "subject_cn": "Acme-Protocol.xyz.",
        "subject_an": ["*.acme-protocol.xyz", "<script>alert(1)</script>", "a b.xyz", 7, ""],
    }
    assert certificate_names(row) == ["*.acme-protocol.xyz", "acme-protocol.xyz"]
