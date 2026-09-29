from __future__ import annotations

from typing import Any

import checkdmarc
import pytest

from perimeterwatch.core.models import ModuleStatus, Severity, Target
from perimeterwatch.modules.email_posture import EmailPosture, dkim_key_bits, spf_all_policy
from tests.conftest import ROOT

# 1024-bit and 2048-bit RSA public keys, DER, base64. Test keys only.
RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vbqajDw4o6gJy8UtmIbkcpnkO3Kwc4qsEnSZp/TR+fQi62F79RHW"
    "mwKOtFmwteURgLbj7D/WGuNLGOfa/2vse3G2eHnHl5CB8ruRX9fBl/jiDLJ7qTEpFqKLMtzbXbFUFIeJQSFBPXoO0pX"
    "kfzFFQ2oZCN0OZ5jqJKWZsE9+QwIDAQAB"
)


ABSENT = "absent"


def patch_checks(monkeypatch: pytest.MonkeyPatch, dns: Any, **results: Any) -> None:
    """Stub checkdmarc, and publish the matching TXT records unless marked absent."""
    published = {
        "spf": (ROOT, "v=spf1 include:_spf.google.com -all"),
        "dmarc": (f"_dmarc.{ROOT}", "v=DMARC1; p=reject"),
        "mta_sts": (f"_mta-sts.{ROOT}", "v=STSv1; id=20260901"),
    }
    for name, (host, value) in published.items():
        if results.get(name) is ABSENT:
            results.pop(name)
            dns.nodata.add(host)
        else:
            dns.add(host, "TXT", [value])

    def unexpected(domain: str, **kwargs: Any) -> Any:
        raise AssertionError("checkdmarc must not be asked about a record that is absent")

    defaults = {
        "spf": {"record": "v=spf1 include:_spf.google.com -all", "valid": True, "parsed": {}},
        "dmarc": {
            "record": "v=DMARC1; p=reject; rua=mailto:d@acme-protocol.xyz",
            "valid": True,
            "tags": {
                "p": {"value": "reject"},
                "rua": {"value": [{"address": "d@acme-protocol.xyz"}]},
            },
        },
    }
    results.pop("mta_sts", None)
    defaults.update(results)
    for name in ("spf", "dmarc"):
        if (published[name][0], "TXT") not in dns.records:
            monkeypatch.setattr(checkdmarc, f"check_{name}", unexpected)
            defaults.pop(name)
    for name, value in defaults.items():

        def check(domain: str, _value: Any = value, **kwargs: Any) -> Any:
            if isinstance(_value, Exception):
                raise _value
            return _value

        monkeypatch.setattr(checkdmarc, f"check_{name}", check)


async def run(make_ctx: Any) -> Any:
    return await EmailPosture().run(Target(root_domain=ROOT), make_ctx())


def kinds(result: Any) -> set[str]:
    return {f.kind for f in result.findings}


@pytest.fixture
def mail_domain(dns: Any) -> Any:
    dns.add(ROOT, "MX", ["10 aspmx.l.google.com."])
    dns.add(f"google._domainkey.{ROOT}", "TXT", [f"v=DKIM1; k=rsa; p={RSA_1024}"])
    return dns


async def test_well_configured_domain_has_no_findings(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, dns: Any
) -> None:
    dns.add(ROOT, "MX", ["10 aspmx.l.google.com."])
    dns.add(
        f"selector1._domainkey.{ROOT}",
        "TXT",
        ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
    )
    patch_checks(monkeypatch, dns)
    result = await run(make_ctx)
    assert result.status is ModuleStatus.OK
    assert result.findings == []
    assert result.assets[0].attributes["dkim_selectors"] == ["selector1"]


async def test_missing_records(monkeypatch: pytest.MonkeyPatch, make_ctx: Any, dns: Any) -> None:
    dns.add(ROOT, "MX", ["10 mail.acme-protocol.xyz."])
    patch_checks(
        monkeypatch,
        dns,
        spf=ABSENT,
        dmarc=ABSENT,
        mta_sts=ABSENT,
    )
    result = await run(make_ctx)
    assert kinds(result) == {
        "email.spf.missing",
        "email.dmarc.missing",
        "email.mta_sts.missing",
        "email.dkim.not_found",
    }
    dmarc = next(f for f in result.findings if f.kind == "email.dmarc.missing")
    assert dmarc.severity is Severity.HIGH


async def test_monitor_only_and_soft_policies(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
) -> None:
    patch_checks(
        monkeypatch,
        dns,
        spf={"record": "v=spf1 include:x.example ~all", "valid": True, "parsed": {}},
        dmarc={"record": "v=DMARC1; p=none", "valid": True, "tags": {"p": {"value": "none"}}},
    )
    result = await run(make_ctx)
    assert kinds(result) == {
        "email.spf.softfail",
        "email.dmarc.policy_none",
        "email.dmarc.no_reporting",
        "email.dkim.weak_key",
    }


async def test_partial_dmarc_enforcement(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
) -> None:
    patch_checks(
        monkeypatch,
        dns,
        dmarc={
            "record": "v=DMARC1; p=reject; sp=none; pct=20; rua=mailto:d@x.example",
            "valid": True,
            "tags": {
                "p": {"value": "reject"},
                "sp": {"value": "none"},
                "pct": {"value": 20},
                "rua": {"value": [{"address": "d@x.example"}]},
            },
        },
    )
    result = await run(make_ctx)
    finding = next(f for f in result.findings if f.kind == "email.dmarc.partial_enforcement")
    assert finding.state == {"pct": 20, "sp": "none", "p": "reject"}


async def test_no_mail_servers_skips_mail_only_checks(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, dns: Any
) -> None:
    dns.nodata.add(ROOT)
    patch_checks(monkeypatch, dns, mta_sts=ABSENT)
    result = await run(make_ctx)
    assert kinds(result) == set()
    assert any("no mail servers" in n for n in result.notes)


async def test_a_failing_check_gives_a_partial_result(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
) -> None:
    patch_checks(monkeypatch, dns, dmarc=RuntimeError("resolver exploded"))
    result = await run(make_ctx)
    assert result.status is ModuleStatus.PARTIAL
    assert "email.dmarc.missing" not in kinds(result), "a failed lookup is not a missing record"


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"record": "v=spf1 -all"}, "fail"),
        ({"record": "v=spf1 mx ~all"}, "softfail"),
        ({"record": "v=spf1 mx ?all"}, "neutral"),
        ({"record": "v=spf1 +all"}, "pass"),
        ({"record": "v=spf1 all"}, "pass"),
        ({"record": "v=spf1 mx"}, None),
        (
            {
                "record": "v=spf1 redirect=x.example",
                "parsed": {"redirect": {"record": "v=spf1 ip4:192.0.2.1 -all"}},
            },
            "fail",
        ),
        # "all" inside a domain name is not an "all" rule.
        ({"record": "v=spf1 include:mall.example"}, None),
    ],
)
def test_spf_all_policy(result: dict[str, Any], expected: str | None) -> None:
    assert spf_all_policy(result) == expected


def test_dkim_key_sizes() -> None:
    assert dkim_key_bits(f"v=DKIM1; k=rsa; p={RSA_1024}") == ("rsa", 1024)
    assert dkim_key_bits("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=") == (
        "ed25519",
        256,
    )
    assert dkim_key_bits("v=DKIM1; p=") is None, "an empty key means the selector was revoked"
    assert dkim_key_bits("v=DKIM1; p=!!!not-base64!!!") is None


async def test_a_failed_lookup_is_never_reported_as_a_missing_record(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
) -> None:
    patch_checks(monkeypatch, dns)
    del dns.records[(f"_dmarc.{ROOT}", "TXT")]
    dns.errors.add(f"_dmarc.{ROOT}")
    result = await run(make_ctx)
    assert result.status is ModuleStatus.PARTIAL
    assert not any(k.startswith("email.dmarc") for k in kinds(result))
    assert any("DMARC lookup failed" in n for n in result.notes)


async def test_subdomain_inherits_the_organisation_dmarc_policy(
    monkeypatch: pytest.MonkeyPatch, make_ctx: Any, dns: Any
) -> None:
    sub = f"mail.{ROOT}"
    dns.add(sub, "MX", ["10 aspmx.l.google.com."])
    dns.add(sub, "TXT", ["v=spf1 -all"])
    dns.add(f"_dmarc.{ROOT}", "TXT", ["v=DMARC1; p=reject"])
    dns.add(f"_mta-sts.{sub}", "TXT", ["v=STSv1; id=1"])
    dns.add(
        f"google._domainkey.{sub}",
        "TXT",
        ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
    )
    for name in ("spf", "dmarc"):
        value = {
            "spf": {"record": "v=spf1 -all", "valid": True},
            "dmarc": {
                "record": "v=DMARC1; p=reject",
                "valid": True,
                "tags": {"p": {"value": "reject"}, "rua": {"value": [{"address": "d@x.example"}]}},
            },
            "mta_sts": {"valid": True, "policy": {"mode": "enforce"}},
        }[name]
        monkeypatch.setattr(checkdmarc, f"check_{name}", lambda d, _v=value, **kw: _v)
    result = await EmailPosture().run(Target(root_domain=sub), make_ctx(root=sub))
    assert kinds(result) == set()


class TestMtaStsPolicy:
    """Reading the policy file means contacting the organisation's web server."""

    POLICY = "version: STSv1\nmode: {mode}\nmx: aspmx.l.google.com\nmax_age: 604800\n"

    def handler(self, mode: str = "enforce", status: int = 200) -> Any:
        import httpx

        calls: list[Any] = []

        def handle(request: Any) -> Any:
            calls.append(request)
            assert str(request.url) == f"https://mta-sts.{ROOT}/.well-known/mta-sts.txt"
            return httpx.Response(status, text=self.POLICY.format(mode=mode))

        handle.calls = calls  # type: ignore[attr-defined]
        return handle

    async def test_a_passive_scan_sends_nothing_to_the_organisation(
        self, monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
    ) -> None:
        patch_checks(monkeypatch, dns)
        dns.add(f"mta-sts.{ROOT}", "A", ["104.18.0.1"])
        # make_ctx fails the test on any HTTP request unless a handler is given.
        result = await EmailPosture().run(Target(root_domain=ROOT), make_ctx())
        assert not any(k.startswith("email.mta_sts") for k in kinds(result))
        assert any("only read in probe mode" in n for n in result.notes)
        assert result.assets[0].attributes["mta_sts"] == "record present, policy not read"

    @pytest.mark.parametrize(
        ("mode", "expected"),
        [
            ("enforce", set()),
            ("testing", {"email.mta_sts.not_enforced"}),
            ("none", {"email.mta_sts.not_enforced"}),
        ],
    )
    async def test_probe_mode_reads_the_policy(
        self,
        monkeypatch: pytest.MonkeyPatch,
        make_ctx: Any,
        mail_domain: Any,
        dns: Any,
        mode: str,
        expected: set[str],
    ) -> None:
        from perimeterwatch.core.models import ScanMode

        patch_checks(monkeypatch, dns)
        dns.add(f"mta-sts.{ROOT}", "A", ["104.18.0.1"])
        handler = self.handler(mode)
        ctx = make_ctx(mode=ScanMode.PROBE, handler=handler)
        result = await EmailPosture().run(Target(root_domain=ROOT), ctx)
        assert {k for k in kinds(result) if k.startswith("email.mta_sts")} == expected
        assert len(handler.calls) == 1

    async def test_policy_host_at_a_private_address_is_not_fetched(
        self, monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
    ) -> None:
        from perimeterwatch.core.models import ScanMode

        patch_checks(monkeypatch, dns)
        dns.add(f"mta-sts.{ROOT}", "A", ["169.254.169.254"])
        ctx = make_ctx(mode=ScanMode.PROBE)  # any request fails the test
        result = await EmailPosture().run(Target(root_domain=ROOT), ctx)
        assert "email.mta_sts.invalid" in kinds(result)

    async def test_policy_host_on_the_do_not_contact_list_is_not_fetched(
        self, monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
    ) -> None:
        from perimeterwatch.core.models import ScanMode

        patch_checks(monkeypatch, dns)
        dns.add(f"mta-sts.{ROOT}", "A", ["104.18.0.1"])
        for entry in (f"mta-sts.{ROOT}", "104.18.0.0/16"):
            ctx = make_ctx(mode=ScanMode.PROBE)  # any request fails the test
            ctx.settings.never_contact = [entry]
            result = await EmailPosture().run(Target(root_domain=ROOT), ctx)
            assert not any(k.startswith("email.mta_sts") for k in kinds(result)), entry

    async def test_broken_policy_file(
        self, monkeypatch: pytest.MonkeyPatch, make_ctx: Any, mail_domain: Any, dns: Any
    ) -> None:
        from perimeterwatch.core.models import ScanMode

        patch_checks(monkeypatch, dns)
        dns.add(f"mta-sts.{ROOT}", "A", ["104.18.0.1"])
        ctx = make_ctx(mode=ScanMode.PROBE, handler=self.handler(status=404))
        result = await EmailPosture().run(Target(root_domain=ROOT), ctx)
        assert "email.mta_sts.invalid" in kinds(result)
