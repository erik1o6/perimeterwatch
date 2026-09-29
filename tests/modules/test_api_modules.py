"""Modules that read public or keyed APIs. All HTTP is served by a local stand-in."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from perimeterwatch.core.models import (
    AuthLevel,
    JobBoardRef,
    ModuleStatus,
    SafeRef,
    Sensitivity,
    Severity,
    Target,
)
from perimeterwatch.modules.breaches import Breaches, is_high_value
from perimeterwatch.modules.github_org import GitHubOrg
from perimeterwatch.modules.jobs_stack import JobsStack, find_technologies
from perimeterwatch.modules.safe_multisig import (
    RpcError,
    SafeMultisig,
    decode_addresses,
    decode_uint,
)
from tests.conftest import ROOT, fixture_text

OWNERS = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
]
SAFE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
RPC = "https://rpc.example.org/v2/SECRET-RPC-KEY"


def word(value: int) -> str:
    return f"{value:064x}"


def encode_addresses(addresses: list[str]) -> str:
    body = word(32) + word(len(addresses))
    body += "".join(a[2:].lower().rjust(64, "0") for a in addresses)
    return "0x" + body


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


@pytest.fixture
def router() -> Router:
    return Router()


class TestGitHubOrg:
    TARGET = Target(root_domain=ROOT, github_org="acme-protocol")

    def repos(self) -> list[dict[str, Any]]:
        return [
            {"full_name": "acme-protocol/core", "pushed_at": "2026-09-01T00:00:00Z", "language": "Solidity"},
            {"full_name": "acme-protocol/old-frontend", "pushed_at": "2022-01-01T00:00:00Z"},
            {"full_name": "acme-protocol/archived", "pushed_at": "2020-01-01T00:00:00Z", "archived": True},
            {"full_name": "acme-protocol/a-fork", "pushed_at": "2020-01-01T00:00:00Z", "fork": True},
        ]  # fmt: skip

    async def test_reports_stale_repositories(self, make_ctx: Any, router: Router) -> None:
        router.add(
            "api.github.com", "/orgs/acme-protocol", {"public_repos": 4, "is_verified": True}
        )
        router.add("api.github.com", "/orgs/acme-protocol/repos", self.repos())
        result = await GitHubOrg().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.OK
        assert [f.asset_key for f in result.findings] == ["acme-protocol/old-frontend"]
        assert result.stats == {"public_repos": 4, "stale": 1}
        assert "authorization" not in router.requests[0].headers
        assert any("two-factor" in n for n in result.notes)

    async def test_two_factor_setting_when_visible(
        self, make_ctx: Any, router: Router, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_ownertokenownertokenownertoken123456")
        router.add(
            "api.github.com", "/orgs/acme-protocol",
            {"public_repos": 0, "two_factor_requirement_enabled": False},
        )  # fmt: skip
        router.add("api.github.com", "/orgs/acme-protocol/repos", [])
        result = await GitHubOrg().run(self.TARGET, make_ctx(handler=router))
        [finding] = result.findings
        assert finding.kind == "github.org.two_factor_not_required"
        assert finding.severity is Severity.HIGH
        assert router.requests[0].headers["authorization"].startswith("Bearer ghp_")

    async def test_unknown_organisation(self, make_ctx: Any, router: Router) -> None:
        result = await GitHubOrg().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "no organisation named" in (result.skip_reason or "")

    async def test_rate_limit_is_explained(self, make_ctx: Any, router: Router) -> None:
        router.add(
            "api.github.com", "/orgs/acme-protocol",
            httpx.Response(403, headers={"x-ratelimit-remaining": "0"}, json={}),
        )  # fmt: skip
        result = await GitHubOrg().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "GITHUB_TOKEN" in (result.skip_reason or "")


class TestSafeMultisig:
    TARGET = Target(root_domain=ROOT, safes=[SafeRef(chain="eth", address=SAFE)])

    @pytest.fixture(autouse=True)
    def rpc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PW_RPC_ETH_MAINNET", RPC)

    def chain(self, owners: list[str], threshold: int) -> Any:
        def answer(request: httpx.Request) -> dict[str, Any]:
            call = json.loads(request.content)
            assert call["method"] == "eth_call", "only read-only calls are ever made"
            assert call["params"][0]["to"] == SAFE
            data = call["params"][0]["data"]
            result = encode_addresses(owners) if data == "0xa0e67e2b" else "0x" + word(threshold)
            return {"jsonrpc": "2.0", "id": 1, "result": result}

        return answer

    async def run(self, make_ctx: Any, router: Router, owners: list[str], threshold: int) -> Any:
        router.add("rpc.example.org", "/v2/SECRET-RPC-KEY", self.chain(owners, threshold))
        return await SafeMultisig().run(self.TARGET, make_ctx(handler=router))

    async def test_healthy_safe(self, make_ctx: Any, router: Router) -> None:
        result = await self.run(make_ctx, router, OWNERS, 2)
        [finding] = result.findings
        assert finding.kind == "web3.safe.owners"
        assert finding.severity is Severity.INFO
        assert finding.state == {"owners": sorted(OWNERS), "threshold": 2}
        assert result.assets[0].state == {"threshold": 2, "owner_count": 3}

    async def test_single_signature(self, make_ctx: Any, router: Router) -> None:
        result = await self.run(make_ctx, router, OWNERS, 1)
        kinds = {f.kind: f.severity for f in result.findings}
        assert kinds["web3.safe.low_threshold"] is Severity.HIGH

    async def test_few_owners(self, make_ctx: Any, router: Router) -> None:
        result = await self.run(make_ctx, router, OWNERS[:2], 2)
        assert "web3.safe.few_owners" in {f.kind for f in result.findings}

    async def test_every_owner_must_sign(self, make_ctx: Any, router: Router) -> None:
        result = await self.run(make_ctx, router, OWNERS, 3)
        assert "web3.safe.threshold_equals_owners" in {f.kind for f in result.findings}

    async def test_owner_change_changes_the_state(self, make_ctx: Any, router: Router) -> None:
        before = (await self.run(make_ctx, router, OWNERS, 2)).findings[0]
        replaced = [*OWNERS[:2], "0x52908400098527886E0F7030069857D2E4169EE7"]
        after = (await self.run(make_ctx, router, replaced, 2)).findings[0]
        assert before.identity == after.identity
        assert before.state != after.state

    async def test_failure_never_reveals_the_rpc_key(self, make_ctx: Any, router: Router) -> None:
        router.add("rpc.example.org", "/v2/SECRET-RPC-KEY", httpx.Response(500, text="boom"))
        result = await SafeMultisig().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED
        assert "SECRET-RPC-KEY" not in result.model_dump_json()

    async def test_address_without_a_contract(self, make_ctx: Any, router: Router) -> None:
        router.add(
            "rpc.example.org", "/v2/SECRET-RPC-KEY", {"jsonrpc": "2.0", "id": 1, "result": "0x"}
        )
        result = await SafeMultisig().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED

    def test_decoding(self) -> None:
        assert decode_addresses(encode_addresses(OWNERS)) == OWNERS
        assert decode_addresses(encode_addresses([])) == []
        assert decode_uint("0x" + word(3)) == 3

    @pytest.mark.parametrize(
        "data",
        [
            "0x",
            "0x1234",
            "0x" + word(32),
            "0x" + word(32) + word(5) + word(1),  # claims 5 addresses, holds 1
            "0x" + word(32) + word(10**6),  # absurd length
            "0x" + word(64) + word(1),  # offset beyond the data
            "0x" + word(32) + word(1) + "f" * 64,  # not an address
        ],
    )
    def test_malformed_answers_are_refused(self, data: str) -> None:
        with pytest.raises(RpcError):
            decode_addresses(data)


class TestJobsStack:
    TARGET = Target(
        root_domain=ROOT, job_board=JobBoardRef(kind="greenhouse", value="acmeprotocol")
    )

    async def test_greenhouse(self, make_ctx: Any, router: Router) -> None:
        router.add(
            "boards-api.greenhouse.io", "/v1/boards/acmeprotocol/jobs",
            json.loads(fixture_text("jobs", "greenhouse.json")),
        )  # fmt: skip
        result = await JobsStack().run(self.TARGET, make_ctx(handler=router))
        [finding] = result.findings
        found = set(finding.state["technologies"])
        assert {"Kubernetes", "AWS", "Terraform", "Fireblocks", "HashiCorp Vault", "Solidity",
                "Foundry", "Tenderly", "Okta", "CrowdStrike"} <= found  # fmt: skip
        assert "Helm" not in found, "'Helm' must not match inside other words"
        assert finding.severity is Severity.LOW, "raised because key management is named"
        assert finding.evidence["postings_read"] == 3
        assert "script" not in json.dumps(finding.evidence).lower()

    async def test_lever(self, make_ctx: Any, router: Router) -> None:
        router.add(
            "api.lever.co", "/v0/postings/acmeprotocol",
            [{"text": "SRE", "descriptionPlain": "We run Postgres and Redis on GCP.",
              "lists": [{"text": "Requirements", "content": "<li>Grafana</li>"}]}],
        )  # fmt: skip
        target = Target(root_domain=ROOT, job_board=JobBoardRef(kind="lever", value="acmeprotocol"))
        result = await JobsStack().run(target, make_ctx(handler=router))
        assert set(result.findings[0].state["technologies"]) == {
            "Postgres",
            "Redis",
            "GCP",
            "Grafana",
        }
        assert result.findings[0].severity is Severity.INFO

    async def test_unknown_board(self, make_ctx: Any, router: Router) -> None:
        result = await JobsStack().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.FAILED

    def test_word_boundaries_and_case(self) -> None:
        found = find_technologies([("t", "aws-savvy, not drawsomething. copper wiring. Uses MPC.")])
        assert "MPC" in found
        assert "AWS" not in found, "exact-case names do not match lower case"
        assert "Copper" not in found


class TestBreaches:
    TARGET = Target(root_domain=ROOT)

    @pytest.fixture
    def hibp(self, router: Router, monkeypatch: pytest.MonkeyPatch) -> Router:
        monkeypatch.setenv("HIBP_API_KEY", "0" * 32)
        host = "haveibeenpwned.com"
        router.add(host, f"/api/v3/breacheddomain/{ROOT}", {
            "ana.lopez": ["ExampleCo", "NewsletterList"],
            "bo": ["NewsletterList"],
            "bad alias; drop": ["ExampleCo"],
        })  # fmt: skip
        router.add(host, "/api/v3/breaches", json.loads(fixture_text("hibp", "breaches.json")))
        router.add(host, f"/api/v3/stealerlogsbyemaildomain/{ROOT}", {
            "ana.lopez": ["github.com", f"sso.{ROOT}", "clinic-portal.example.net",
                          "dating.example.org", "news.example.net"],
        })  # fmt: skip
        return router

    async def test_unverified_domain_gets_no_personal_data(
        self, make_ctx: Any, hibp: Router
    ) -> None:
        for level in (AuthLevel.NONE, AuthLevel.ACKNOWLEDGED):
            result = await Breaches().run(self.TARGET, make_ctx(handler=hibp, level=level))
            assert result.status is ModuleStatus.SKIPPED
            assert result.skip_reason == "requires a verified domain"
            assert result.findings == []
        assert hibp.requests == [], "the breach source must not even be asked"

    async def test_verified_domain(self, make_ctx: Any, hibp: Router) -> None:
        ctx = make_ctx(handler=hibp, level=AuthLevel.DNS_VERIFIED)
        result = await Breaches().run(self.TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.stats["addresses_affected"] == 2

        accounts = [f for f in result.findings if f.kind == "breach.account"]
        assert len(accounts) == 3
        assert all(f.sensitivity is Sensitivity.PERSONAL for f in accounts)
        assert all("haveibeenpwned.com" in (f.attribution or "") for f in accounts)
        with_passwords = next(f for f in accounts if f.identity["breach"] == "ExampleCo")
        assert with_passwords.severity is Severity.MEDIUM
        assert with_passwords.evidence["breach_date"] == "2024-05-01"
        newsletter = next(f for f in accounts if f.asset_key == f"bo@{ROOT}")
        assert newsletter.severity is Severity.LOW, "lowered: no passwords were in that breach"

        [stealer] = [f for f in result.findings if f.kind == "breach.stealer_log"]
        assert stealer.severity is Severity.CRITICAL, "raised: a GitHub login was captured"
        assert stealer.evidence["high_value_services"] == ["github.com"]
        assert stealer.evidence["your_own_systems"] == [f"sso.{ROOT}"]
        assert stealer.evidence["other_sites"] == "3 (not recorded)"
        assert stealer.state == {"sites": ["github.com", f"sso.{ROOT}"]}
        # Sites that say something about a person's private life are never kept.
        for private in ("clinic-portal", "dating", "news.example"):
            assert private not in result.model_dump_json()

        keyed = [r for r in hibp.requests if "breacheddomain" in r.url.path]
        assert keyed[0].headers["hibp-api-key"] == "0" * 32
        assert "No passwords are collected or stored." in result.notes

    async def test_staff_list_tells_current_staff_from_others(
        self, make_ctx: Any, hibp: Router
    ) -> None:
        target = Target(root_domain=ROOT, staff_emails=[f"Ana.Lopez@{ROOT}"])
        ctx = make_ctx(handler=hibp, level=AuthLevel.DNS_VERIFIED)
        result = await Breaches().run(target, ctx)
        listed = {f.asset_key: f.evidence["on_your_staff_list"] for f in result.findings}
        assert listed == {f"ana.lopez@{ROOT}": "yes", f"bo@{ROOT}": "no"}

        without = await Breaches().run(
            self.TARGET, make_ctx(handler=hibp, level=AuthLevel.DNS_VERIFIED)
        )
        assert not any("on_your_staff_list" in f.evidence for f in without.findings)

    async def test_no_field_can_hold_a_password(self, make_ctx: Any, hibp: Router) -> None:
        # Even if a source started returning credentials, nothing here would keep them.
        hibp.add(
            "haveibeenpwned.com", f"/api/v3/breacheddomain/{ROOT}", {"ana.lopez": ["ExampleCo"]}
        )
        catalogue = json.loads(fixture_text("hibp", "breaches.json"))
        catalogue[0]["Password"] = "hunter2-leaked"
        catalogue[0]["Description"] = "attacker text <script>alert(1)</script>"
        hibp.add("haveibeenpwned.com", "/api/v3/breaches", catalogue)
        ctx = make_ctx(handler=hibp, level=AuthLevel.DNS_VERIFIED)
        dumped = (await Breaches().run(self.TARGET, ctx)).model_dump_json()
        assert "hunter2" not in dumped
        assert "<script>" not in dumped

    async def test_clean_domain(self, make_ctx: Any, router: Router, monkeypatch: Any) -> None:
        monkeypatch.setenv("HIBP_API_KEY", "0" * 32)
        ctx = make_ctx(handler=router, level=AuthLevel.DNS_VERIFIED)  # every path answers 404
        result = await Breaches().run(self.TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []

    async def test_stealer_logs_need_a_higher_plan(self, make_ctx: Any, hibp: Router) -> None:
        hibp.add(
            "haveibeenpwned.com", f"/api/v3/stealerlogsbyemaildomain/{ROOT}", httpx.Response(403)
        )
        ctx = make_ctx(handler=hibp, level=AuthLevel.DNS_VERIFIED)
        result = await Breaches().run(self.TARGET, ctx)
        assert result.status is ModuleStatus.OK
        assert any("Pro subscription" in n for n in result.notes)
        assert not [f for f in result.findings if f.kind == "breach.stealer_log"]

    async def test_rejected_key(self, make_ctx: Any, hibp: Router) -> None:
        hibp.add("haveibeenpwned.com", f"/api/v3/breacheddomain/{ROOT}", httpx.Response(401))
        ctx = make_ctx(handler=hibp, level=AuthLevel.DNS_VERIFIED)
        result = await Breaches().run(self.TARGET, ctx)
        assert result.status is ModuleStatus.FAILED
        assert "0" * 32 not in result.model_dump_json()

    async def test_missing_key(self, make_ctx: Any, router: Router) -> None:
        ctx = make_ctx(handler=router, level=AuthLevel.DNS_VERIFIED)
        result = await Breaches().run(self.TARGET, ctx)
        assert result.status is ModuleStatus.SKIPPED
        assert result.skip_reason == "missing key: HIBP_API_KEY"

    async def test_hudson_rock_is_off_unless_switched_on(
        self, make_ctx: Any, router: Router, settings: Any
    ) -> None:
        router.add("cavalier.hudsonrock.com", "/api/json/v2/osint-tools/search-by-domain", {
            "employees": 4, "users": 120, "third_parties": 9,
            "data": {"employees_urls": [{"url": "https://sso.acme-protocol.xyz/login"}]},
            "stealers": [{"username": "ana.lopez@acme-protocol.xyz", "password": "hunter2"}],
        })  # fmt: skip
        result = await Breaches().run(self.TARGET, make_ctx(handler=router))
        assert result.status is ModuleStatus.SKIPPED
        assert router.requests == []

        settings.hudsonrock_enabled = True
        result = await Breaches().run(self.TARGET, make_ctx(handler=router))
        [summary] = result.findings
        assert summary.kind == "breach.domain_summary"
        assert summary.sensitivity is Sensitivity.NORMAL
        assert summary.evidence["staff_devices"] == 4
        dumped = result.model_dump_json()
        for leaked in ("hunter2", "ana.lopez", "sso.acme-protocol.xyz"):
            assert leaked not in dumped, "only counts may be read from this source"

    def test_high_value_sites(self) -> None:
        assert is_high_value("github.com")
        assert is_high_value("accounts.google.com")
        assert is_high_value("app.safe.global")
        assert not is_high_value("notgithub.com")
        assert not is_high_value("github.com.evil.net")
