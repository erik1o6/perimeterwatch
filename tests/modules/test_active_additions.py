"""TLS configuration and zone transfer checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from perimeterwatch.core.models import AuthLevel, ScanMode, Severity, Target
from perimeterwatch.modules import tls_config, zone_transfer
from perimeterwatch.modules.tls_config import TlsConfig, clean_suites
from perimeterwatch.modules.zone_transfer import ZoneTransfer
from tests.conftest import ROOT, fixture_text
from tests.helpers import FakeRunner, install_fake_tools, resolved

APP = f"app.{ROOT}"
IP = "104.18.0.1"
TARGET = Target(root_domain=ROOT)


@pytest.fixture
def ctx(make_ctx: Any, tmp_path: Path) -> Any:
    tools = install_fake_tools(tmp_path / "tools", "tlsx")
    context = make_ctx(mode=ScanMode.ACTIVE, level=AuthLevel.DNS_VERIFIED, tools_dir=tools)
    context.assets.add(resolved({APP: [IP], f"intranet.{ROOT}": ["10.0.0.5"]}))
    return context


def recorded(**changes: Any) -> str:
    row = json.loads(fixture_text("tlsx", "enum.jsonl"))
    row.update(host=APP, ip=IP, **changes)
    return json.dumps(row)


class TestTlsConfig:
    async def test_reads_recorded_output(self, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner({"tlsx": recorded()})
        monkeypatch.setattr(tls_config, "run_tool", runner)
        result = await TlsConfig().run(TARGET, ctx)
        [weak] = result.findings
        assert weak.kind == "tls.cipher.weak" and weak.severity is Severity.LOW
        assert "TLS_RSA_WITH_AES_128_CBC_SHA" in weak.state["suites"]
        call = runner.last("tlsx")
        assert call["files"]["tlsx-enum-targets.txt"].split() == [APP], "private hosts are left out"
        assert "-ve" in call["args"] and "-ce" in call["args"]

    async def test_legacy_versions_and_insecure_suites(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        row = recorded(
            version_enum=["tls13", "tls12", "tls10", "ssl30", "made-up"],
            cipher_enum=[{"version": "tls10", "ciphers": {
                "insecure": ["TLS_RSA_WITH_RC4_128_SHA"],
                "weak": ["TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"],
            }}],
        )  # fmt: skip
        monkeypatch.setattr(tls_config, "run_tool", FakeRunner({"tlsx": row}))
        by_kind = {f.kind: f for f in (await TlsConfig().run(TARGET, ctx)).findings}
        legacy = by_kind["tls.protocol.legacy"]
        assert legacy.state == {"versions": ["SSL 3.0", "TLS 1.0"]}
        assert legacy.severity is Severity.HIGH
        assert by_kind["tls.cipher.insecure"].state == {"suites": ["TLS_RSA_WITH_RC4_128_SHA"]}
        assert by_kind["tls.cipher.weak"].state == {"suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"]}

    async def test_modern_server_has_no_findings(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        row = recorded(version_enum=["tls13", "tls12"], cipher_enum=[])
        monkeypatch.setattr(tls_config, "run_tool", FakeRunner({"tlsx": row}))
        assert (await TlsConfig().run(TARGET, ctx)).findings == []

    @pytest.mark.parametrize(
        "changes",
        [
            {"host": "evil.example.net"},
            {"ip": "127.0.0.1"},
            {"ip": "10.0.0.5"},
            {"probe_status": False},
        ],
    )
    async def test_unexpected_answers_are_discarded(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any]
    ) -> None:
        row = json.loads(recorded(version_enum=["ssl30"]))
        row.update(changes)
        monkeypatch.setattr(tls_config, "run_tool", FakeRunner({"tlsx": json.dumps(row)}))
        assert (await TlsConfig().run(TARGET, ctx)).findings == []

    @pytest.mark.parametrize("bad", [None, "text", 5, {"a": 1}, [None, 5, {"x": 1}]])
    async def test_malformed_output(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch, bad: Any
    ) -> None:
        row = recorded(version_enum=bad, cipher_enum=bad)
        monkeypatch.setattr(tls_config, "run_tool", FakeRunner({"tlsx": row}))
        assert (await TlsConfig().run(TARGET, ctx)).findings == []

    def test_suite_names_are_validated(self) -> None:
        assert clean_suites(["TLS_A", "<script>", "x" * 200, "", 5, "TLS_A", "a b"]) == ["TLS_A"]
        assert len(clean_suites([f"TLS_{i}" for i in range(500)])) == 40

    def test_is_active(self) -> None:
        assert TlsConfig.spec.mode is ScanMode.ACTIVE


class TestZoneTransfer:
    @pytest.fixture
    def ns(self, dns: Any) -> Any:
        dns.add(ROOT, "NS", ["ns1.dnshost.net.", "ns2.dnshost.net.", "ns3.internal-dns.net."])
        dns.add("ns1.dnshost.net", "A", ["198.41.0.4"])
        dns.add("ns2.dnshost.net", "A", ["198.41.0.5"])
        dns.add("ns3.internal-dns.net", "A", ["10.0.0.53"])
        return dns

    def patch(self, monkeypatch: pytest.MonkeyPatch, answers: dict[str, int | None]) -> list[Any]:
        asked: list[tuple[str, str]] = []

        def fake(address: str, zone: str) -> int | None:
            asked.append((address, zone))
            return answers.get(address)

        monkeypatch.setattr(zone_transfer, "try_transfer", fake)
        return asked

    async def test_open_transfer_is_reported_without_keeping_records(
        self, make_ctx: Any, ns: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.patch(monkeypatch, {"198.41.0.4": 312, "198.41.0.5": None})
        result = await ZoneTransfer().run(TARGET, make_ctx(mode=ScanMode.ACTIVE))
        [finding] = result.findings
        assert finding.severity is Severity.HIGH
        assert finding.identity == {"nameserver": "ns1.dnshost.net"}
        assert finding.evidence["records_offered"] == 312
        assert finding.evidence["records_kept"] == "none"
        assert sorted(a for a, _ in asked) == ["198.41.0.4", "198.41.0.5"]
        assert all(zone == ROOT for _, zone in asked)

    async def test_private_nameservers_are_never_asked(
        self, make_ctx: Any, ns: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.patch(monkeypatch, {})
        result = await ZoneTransfer().run(TARGET, make_ctx(mode=ScanMode.ACTIVE))
        assert "10.0.0.53" not in [a for a, _ in asked]
        assert any("ns3.internal-dns.net has no public address" in n for n in result.notes)

    async def test_do_not_contact_list(
        self, make_ctx: Any, ns: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.patch(monkeypatch, {"198.41.0.4": 5})
        ctx = make_ctx(mode=ScanMode.ACTIVE)
        ctx.settings.never_contact = ["dnshost.net"]
        result = await ZoneTransfer().run(TARGET, ctx)
        assert asked == [] and result.findings == []

    async def test_refused_everywhere(
        self, make_ctx: Any, ns: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.patch(monkeypatch, {})
        result = await ZoneTransfer().run(TARGET, make_ctx(mode=ScanMode.ACTIVE))
        assert result.findings == [] and result.stats == {"nameservers_asked": 2}

    def test_network_failure_counts_as_refused(self) -> None:
        # 192.0.2.1 is reserved for documentation and never answers.
        def boom(*args: Any, **kw: Any) -> Any:
            raise OSError("unreachable")

        import dns.query

        original = dns.query.xfr
        dns.query.xfr = boom  # type: ignore[assignment]
        try:
            assert zone_transfer.try_transfer("192.0.2.1", ROOT) is None
        finally:
            dns.query.xfr = original  # type: ignore[assignment]

    def test_is_active(self) -> None:
        assert ZoneTransfer.spec.mode is ScanMode.ACTIVE
