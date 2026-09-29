"""SSH server settings and public storage buckets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from parapet.core.models import (
    Asset,
    AssetType,
    AuthLevel,
    Category,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
)
from parapet.modules import bucket_exposure, ssh_audit
from parapet.modules.bucket_exposure import BucketExposure, bucket_from, valid_bucket
from parapet.modules.ssh_audit import ARGS, FORBIDDEN, SshAudit, parse_output
from parapet.tools.locate import ToolLocator, ToolPin, manifest, python_tool
from tests.conftest import ROOT, fixture_text
from tests.helpers import FakeRunner, install_fake_tools

IP = "104.18.0.1"
TARGET = Target(root_domain=ROOT)


def open_port(ip: str, port: int, hosts: list[str] | None = None) -> Finding:
    return Finding(
        kind="ports.unexpected_open", module="ports", category=Category.VULN, title="t",
        severity=Severity.MEDIUM, asset_type=AssetType.IP, asset_key=ip,
        identity={"port": str(port)}, evidence={"hosts": hosts or [f"bastion.{ROOT}"]},
    )  # fmt: skip


@pytest.fixture
def active(make_ctx: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    tools = install_fake_tools(tmp_path / "tools", "s3scanner")
    ctx = make_ctx(mode=ScanMode.ACTIVE, level=AuthLevel.DNS_VERIFIED, tools_dir=tools)
    # ssh-audit is a Python package, found through the environment, not the tools folder.
    monkeypatch.setattr(ctx.tools, "available", lambda name: True)
    return ctx


def recorded(target: str) -> dict[str, Any]:
    row = json.loads(fixture_text("ssh_audit", "openssh_8.0.json"))
    row["target"] = target
    return row


class TestSshAudit:
    def with_ports(self, ctx: Any, *findings: Finding) -> Any:
        ctx.assets.add(
            ModuleResult(module="ports", status=ModuleStatus.OK, findings=list(findings))
        )
        return ctx

    async def test_reads_recorded_output(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_ports(active, open_port(IP, 22), open_port(IP, 8080))
        runner = FakeRunner({"ssh-audit": json.dumps(recorded(f"{IP}:22"))})
        monkeypatch.setattr(ssh_audit, "run_tool", runner)
        result = await SshAudit().run(TARGET, ctx)

        by_kind = {f.kind: f for f in result.findings}
        weak = by_kind["ssh.weak_algorithms"]
        assert weak.severity is Severity.MEDIUM
        assert "kex: diffie-hellman-group14-sha1" in weak.state["algorithms"]
        assert "mac: hmac-sha1" in weak.state["algorithms"]
        assert weak.evidence["software"] == "OpenSSH_8.0"
        keys = by_kind["ssh.host_keys"].state["host_keys"]
        assert "ssh-ed25519 SHA256:UrnXIVH+7dlw8UqYocl48yUEcKrthGDQG2CPCgp7MxU" in keys
        assert not any("MD5" in k for k in keys)

        call = runner.last("ssh-audit")
        assert call["files"]["ssh-audit-targets.txt"].split() == [f"{IP}:22"], "only SSH ports"

    async def test_dangerous_options_can_never_be_passed(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_ports(active, open_port(IP, 22))
        runner = FakeRunner({"ssh-audit": "{}"})
        monkeypatch.setattr(ssh_audit, "run_tool", runner)
        await SshAudit().run(TARGET, ctx)
        args = runner.last("ssh-audit")["args"]
        assert "--skip-rate-test" in args, "the connection rate test must stay off"
        for option in FORBIDDEN:
            assert option not in args and option not in ARGS, option
        assert not any(a.startswith(("--dheat", "--conn-rate")) for a in args)

    async def test_changed_host_key_changes_state(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_ports(active, open_port(IP, 22))
        states = []
        for digest in ("UrnXIVH+7dlw8UqYocl48yUEcKrthGDQG2CPCgp7MxU", "A" * 43):
            row = recorded(f"{IP}:22")
            row["fingerprints"] = [{"hash": digest, "hash_alg": "SHA256", "hostkey": "ssh-ed25519"}]
            monkeypatch.setattr(ssh_audit, "run_tool", FakeRunner({"ssh-audit": json.dumps(row)}))
            result = await SshAudit().run(TARGET, ctx)
            finding = next(f for f in result.findings if f.kind == "ssh.host_keys")
            states.append((finding.identity, finding.state))
        assert states[0][0] == states[1][0]
        assert states[0][1] != states[1][1]

    async def test_several_targets_and_answers_about_others_ignored(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_ports(active, open_port(IP, 22), open_port("104.18.0.2", 2222))
        rows = [
            recorded(f"{IP}:22"),
            recorded("203.0.113.9:22"),
            recorded("10.0.0.5:22"),
            "junk",
            None,
        ]
        monkeypatch.setattr(ssh_audit, "run_tool", FakeRunner({"ssh-audit": json.dumps(rows)}))
        result = await SshAudit().run(TARGET, ctx)
        assert {f.asset_key for f in result.findings} == {IP}
        assert result.status is ModuleStatus.PARTIAL
        assert any("1 SSH server(s) did not answer" in n for n in result.notes)

    async def test_private_and_malformed_port_findings_are_not_targets(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_ports(
            active, open_port("10.0.0.5", 22), open_port("not-an-ip", 22),
            open_port("-oProxyCommand=x", 22), open_port("2606:4700::1", 22),
        )  # fmt: skip
        runner = FakeRunner()
        monkeypatch.setattr(ssh_audit, "run_tool", runner)
        result = await SshAudit().run(TARGET, ctx)
        assert runner.calls == []
        assert any("No SSH server" in n for n in result.notes)

    async def test_hostile_output_is_cleaned(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_ports(active, open_port(IP, 22))
        row = recorded(f"{IP}:22")
        row["banner"] = {"software": "<script>alert(1)</script>"}
        row["recommendations"] = {"critical": {"del": {
            "kex": [{"name": "<img src=x>"}, {"name": "x" * 500}, {"name": "ok-alg"}, "junk", None],
            "evil": [{"name": "ignored"}],
        }}}  # fmt: skip
        row["fingerprints"] = [{"hash": "<b>", "hash_alg": "SHA256", "hostkey": "ssh-rsa"}, "junk"]
        monkeypatch.setattr(ssh_audit, "run_tool", FakeRunner({"ssh-audit": json.dumps(row)}))
        result = await SshAudit().run(TARGET, ctx)
        dumped = result.model_dump_json()
        assert "<script>" not in dumped and "<img" not in dumped and "<b>" not in dumped
        [weak] = [f for f in result.findings if f.kind == "ssh.weak_algorithms"]
        assert "kex: ok-alg" in weak.state["algorithms"]
        assert not any(a.startswith("evil") for a in weak.state["algorithms"])

    @pytest.mark.parametrize("stdout", ["", "not json", "[]", "5", '"text"', "{", "null"])
    def test_malformed_output(self, stdout: str) -> None:
        assert parse_output(stdout) == []

    async def test_needs_the_port_check_first(self, active: Any) -> None:
        assert (await SshAudit().run(TARGET, active)).status is ModuleStatus.FAILED

    def test_is_active(self) -> None:
        assert SshAudit.spec.mode is ScanMode.ACTIVE


def alias(host: str, cname: str | None) -> Asset:
    return Asset(
        type=AssetType.SUBDOMAIN, key=host, source_module="dns_resolve",
        attributes={"ips": ["52.0.0.1"]}, state={"resolves": True, "cname": cname},
    )  # fmt: skip


def bucket_row(name: str, **perms: int) -> str:
    bucket = {"name": name, "exists": 1, "provider": "aws", "region": "us-east-1",
              "objects": [{"key": "private/customers.csv", "size": 10}],
              "owner_display_name": "ana.lopez",
              **{f"perm_all_users_{k}": 0 for k in ("read", "write", "read_acl", "write_acl", "full_control")}}  # fmt: skip
    bucket.update({f"perm_all_users_{k}": v for k, v in perms.items()})
    return json.dumps({"bucket": bucket, "level": "info", "msg": ""})


class TestBucketExposure:
    def with_dns(self, ctx: Any, *assets: Asset) -> Any:
        ctx.assets.add(
            ModuleResult(module="dns_resolve", status=ModuleStatus.OK, assets=list(assets))
        )
        return ctx

    async def test_public_bucket_is_reported_without_its_contents(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_dns(
            active,
            alias(f"assets.{ROOT}", "acme-assets.s3.amazonaws.com."),
            alias(f"app.{ROOT}", "acme-app.s3-website-us-east-1.amazonaws.com"),
            alias(f"www.{ROOT}", "acme.github.io"),
            alias(f"plain.{ROOT}", None),
            alias("cdn.other-company.com", "their-bucket.s3.amazonaws.com"),
        )
        out = "\n".join([
            bucket_row("acme-assets", read=1),
            bucket_row("acme-app", write=1, read=1, read_acl=1),
            bucket_row("someone-elses-bucket", write=1),
            '{"level":"error","msg":"noise"}', "not json",
        ])  # fmt: skip
        runner = FakeRunner({"s3scanner": out})
        monkeypatch.setattr(bucket_exposure, "run_tool", runner)
        result = await BucketExposure().run(TARGET, ctx)

        call = runner.last("s3scanner")
        assert call["files"]["buckets-aws.txt"].split() == ["acme-app", "acme-assets"]
        for option in bucket_exposure.FORBIDDEN:
            assert option not in call["args"], option

        found = {(f.kind, f.evidence["bucket"]): f for f in result.findings}
        assert set(found) == {
            ("cloud.bucket.public_read", "acme-assets"),
            ("cloud.bucket.public_write", "acme-app"),
            ("cloud.bucket.public_read", "acme-app"),
            ("cloud.bucket.public_acl", "acme-app"),
        }
        assert found[("cloud.bucket.public_write", "acme-app")].severity is Severity.CRITICAL
        assert found[("cloud.bucket.public_read", "acme-assets")].evidence["pointed_at_by"] == [
            f"assets.{ROOT}"
        ]
        dumped = result.model_dump_json()
        assert "customers.csv" not in dumped and "ana.lopez" not in dumped

    async def test_names_are_never_guessed(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_dns(active, alias(f"www.{ROOT}", "acme.github.io"), alias(ROOT, None))
        runner = FakeRunner()
        monkeypatch.setattr(bucket_exposure, "run_tool", runner)
        result = await BucketExposure().run(TARGET, ctx)
        assert runner.calls == [], "no bucket in DNS means nothing is asked"
        assert result.findings == []

    async def test_missing_or_private_bucket_gives_no_finding(
        self, active: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = self.with_dns(active, alias(f"assets.{ROOT}", "acme-assets.s3.amazonaws.com"))
        gone = json.loads(bucket_row("acme-assets", read=1))
        gone["bucket"]["exists"] = 0
        for out in (json.dumps(gone), bucket_row("acme-assets"), bucket_row("acme-assets", read=2)):
            monkeypatch.setattr(bucket_exposure, "run_tool", FakeRunner({"s3scanner": out}))
            assert (await BucketExposure().run(TARGET, ctx)).findings == []

    @pytest.mark.parametrize(
        ("host", "cname", "expected"),
        [
            ("a.acme.xyz", "acme-assets.s3.amazonaws.com", ("aws", "acme-assets")),
            ("a.acme.xyz", "ACME-Assets.S3.eu-west-1.amazonaws.com.", ("aws", "acme-assets")),
            ("a.acme.xyz", "b.s3-website.eu-west-1.amazonaws.com", None),
            ("a.acme.xyz", "my.bucket.s3-website-us-east-1.amazonaws.com", ("aws", "my.bucket")),
            ("a.acme.xyz", "acme.nyc3.digitaloceanspaces.com", ("digitalocean", "acme")),
            ("a.acme.xyz", "acme.nyc3.cdn.digitaloceanspaces.com", ("digitalocean", "acme")),
            ("static.acme.xyz", "c.storage.googleapis.com", ("gcp", "static.acme.xyz")),
            ("a.acme.xyz", "acme-site.storage.googleapis.com", ("gcp", "acme-site")),
            ("a.acme.xyz", "acme.github.io", None),
            ("a.acme.xyz", "s3.amazonaws.com", None),
            ("a.acme.xyz", "evil.s3.amazonaws.com.attacker.net", None),
            ("a.acme.xyz", "-oops.s3.amazonaws.com", None),
            ("a.acme.xyz", "a b.s3.amazonaws.com", None),
            ("a.acme.xyz", "../etc.s3.amazonaws.com", None),
            ("a.acme.xyz", "x" * 80 + ".s3.amazonaws.com", None),
        ],
    )
    def test_bucket_names_from_aliases(
        self, host: str, cname: str, expected: tuple[str, str] | None
    ) -> None:
        assert bucket_from(host, cname) == expected

    @pytest.mark.parametrize("name", ["", "a", "ab", "-ab", "ab-", "a..b", "A_B", "a/b", "a;b"])
    def test_invalid_bucket_names(self, name: str) -> None:
        assert not valid_bucket(name)

    async def test_needs_dns_first(self, active: Any) -> None:
        assert (await BucketExposure().run(TARGET, active)).status is ModuleStatus.FAILED

    def test_is_active(self) -> None:
        assert BucketExposure.spec.mode is ScanMode.ACTIVE


class TestPythonTools:
    def pin(self, **changes: Any) -> ToolPin:
        base = manifest()["ssh-audit"]
        values = {**base.__dict__, **changes}
        return ToolPin(**values)

    def test_found_when_the_pinned_version_is_installed(self, tmp_path: Path) -> None:
        path = python_tool(manifest()["ssh-audit"])
        assert path is not None and path.name == "ssh-audit"
        assert ToolLocator(tmp_path / "empty").available("ssh-audit")

    def test_a_different_installed_version_is_refused(self) -> None:
        assert python_tool(self.pin(version="0.0.1")) is None

    def test_a_package_that_is_not_installed(self) -> None:
        assert python_tool(self.pin(name="no-such-package-parapet")) is None

    def test_installer_reports_it(self, tmp_path: Path) -> None:
        from parapet.tools.installer import Installer

        state = Installer(tmp_path / "tools").install("ssh-audit")
        assert state.verified and "lock file" in state.detail
