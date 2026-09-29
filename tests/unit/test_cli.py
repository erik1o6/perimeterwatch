"""The command line, end to end, with stand-in scan modules and no network."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from perimeterwatch.cli.app import app
from perimeterwatch.core import engine
from perimeterwatch.core.models import AssetType, ModuleResult, ScanMode, Sensitivity
from perimeterwatch.safety import authorisation as auth
from tests.conftest import CANARY, ROOT
from tests.unit.test_engine_and_storage import make_module

runner = CliRunner()


def run(*args: str, input: str | None = None) -> Any:
    return runner.invoke(app, list(args), input=input, catch_exceptions=False)


def plain(text: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", text).split())


@pytest.fixture
def state() -> dict[str, Any]:
    return {"dmarc_missing": True}


@pytest.fixture(autouse=True)
def modules(monkeypatch: pytest.MonkeyPatch, state: dict[str, Any]) -> dict[str, Any]:
    async def passive(self: Any, target: Any, ctx: Any) -> ModuleResult:
        findings = []
        if state["dmarc_missing"]:
            findings.append(
                self.finding(
                    "email.dmarc.missing", AssetType.DOMAIN, ROOT, f"{ROOT} has no DMARC record"
                )
            )
        if ctx.verified:
            findings.append(
                self.finding(
                    "breach.account", AssetType.EMAIL_ADDRESS, f"ana.lopez@{ROOT}",
                    f"ana.lopez@{ROOT} appears in the ExampleCo breach",
                    sensitivity=Sensitivity.PERSONAL, evidence={"breach": "ExampleCo"},
                )
            )  # fmt: skip
        return self.result(findings=findings)

    registry = {
        "email_posture": make_module("email_posture", behaviour=passive),
        "ports": make_module("ports", mode=ScanMode.ACTIVE),
        "github_secrets": make_module("github_secrets", requires_keys=("GITHUB_TOKEN",)),
    }
    for target in (
        "perimeterwatch.core.module.all_modules",
        "perimeterwatch.report.build.all_modules",
        "perimeterwatch.cli.doctor.all_modules",
    ):
        monkeypatch.setattr(target, lambda: dict(registry))
    monkeypatch.setattr(engine, "all_modules", lambda: dict(registry))
    return registry


def verify_with(monkeypatch: pytest.MonkeyPatch, verified: bool) -> None:
    async def check(domain: str, token: str, **kw: Any) -> auth.VerificationResult:
        return auth.VerificationResult(
            verified, "authoritative", "Found." if verified else "No record."
        )

    monkeypatch.setattr(auth, "check_dns", check)
    monkeypatch.setattr("perimeterwatch.cli.verify.check_dns", check)


class TestScan:
    def test_passive_scan_writes_private_reports(self, tmp_path: Path) -> None:
        result = run("scan", ROOT, "--out", str(tmp_path / "out"))
        assert result.exit_code == 0, result.output
        text = plain(result.output)
        assert "1 high" in text
        assert "First scan of this domain" in text
        for name in ("report.html", "report.json"):
            path = tmp_path / "out" / name
            assert path.is_file()
            assert path.stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "out").stat().st_mode & 0o777 == 0o700
        data = json.loads((tmp_path / "out" / "report.json").read_text())
        assert data["scan"]["mode"] == "passive"
        assert {c["module"]: c["status"] for c in data["coverage"]} == {
            "email_posture": "ok", "ports": "skipped", "github_secrets": "skipped",
        }  # fmt: skip

    def test_second_scan_reports_changes(self, tmp_path: Path, state: dict[str, Any]) -> None:
        run("scan", ROOT, "--no-report")
        assert "No changes since the last scan" in plain(run("scan", ROOT, "--no-report").output)
        state["dmarc_missing"] = False
        assert "0 new, 1 resolved, 0 changed" in plain(run("scan", ROOT, "--no-report").output)
        diff = run("diff", ROOT, "--json")
        assert [f["kind"] for f in json.loads(diff.output)["resolved"]] == ["email.dmarc.missing"]

    @pytest.mark.parametrize(
        "domain",
        [
            "acme.xyz; rm -rf /",
            "$(id).acme.xyz",
            "--active",
            "10.0.0.1",
            "localhost",
            "example.com",
        ],
    )
    def test_bad_domains_exit_2(self, domain: str) -> None:
        result = run("scan", "--", domain)
        assert result.exit_code == 2
        assert "Error:" in result.output
        assert "Traceback" not in result.output

    def test_unknown_module_exits_2(self) -> None:
        assert run("scan", ROOT, "--only", "imaginary").exit_code == 2

    def test_unknown_format_exits_2(self) -> None:
        assert run("scan", ROOT, "--format", "pdf").exit_code == 2

    def test_strict_mode_exits_3_when_checks_were_skipped(self) -> None:
        result = run("scan", ROOT, "--no-report", "--strict")
        assert result.exit_code == 3
        assert "set GITHUB_TOKEN" in plain(result.output)

    def test_json_to_stdout(self) -> None:
        result = run("scan", ROOT, "--format", "json", "--out", "-")
        start = result.output.index("{")
        assert json.loads(result.output[start:])["target"]["root_domain"] == ROOT


class TestActiveGate:
    def test_refused_without_authorisation(self, modules: dict[str, Any]) -> None:
        result = run("scan", ROOT, "--active", "--no-report")
        assert result.exit_code == 4
        assert "pwatch verify init" in plain(result.output)
        assert modules["ports"].ran == []

    @pytest.mark.parametrize("flag", ["--force", "--yes", "--skip-verification", "-f"])
    def test_there_is_no_override(self, flag: str, modules: dict[str, Any]) -> None:
        result = run("scan", ROOT, "--active", flag)
        assert result.exit_code == 2, "unknown option"
        assert modules["ports"].ran == []

    def test_dns_verification_unlocks_and_withdrawal_locks_again(
        self, monkeypatch: pytest.MonkeyPatch, modules: dict[str, Any], tmp_path: Path
    ) -> None:
        shown = plain(run("verify", "init", ROOT).output)
        token = re.search(r"pw-verify=(\S+)", shown)
        assert token and f"_perimeterwatch-verify.{ROOT}" in shown

        verify_with(monkeypatch, False)
        assert run("verify", "check", ROOT).exit_code == 4
        assert run("scan", ROOT, "--active", "--no-report").exit_code == 4

        verify_with(monkeypatch, True)
        assert run("verify", "check", ROOT).exit_code == 0
        result = run("scan", ROOT, "--active", "--out", str(tmp_path / "out"))
        assert result.exit_code == 0
        assert modules["ports"].ran == ["ports"]
        report = json.loads((tmp_path / "out" / "report.json").read_text())
        assert report["authorisation"]["level"] == "dns_verified"
        assert (
            "Domain control proven by DNS record" in (tmp_path / "out" / "report.html").read_text()
        )

        # The DNS record is removed: the next active scan is refused again.
        verify_with(monkeypatch, False)
        assert run("scan", ROOT, "--active", "--no-report").exit_code == 4
        assert modules["ports"].ran == ["ports"]

    def test_the_same_token_is_shown_again(self) -> None:
        first = re.search(r"pw-verify=(\S+)", run("verify", "init", ROOT).output)
        second = re.search(r"pw-verify=(\S+)", run("verify", "init", ROOT).output)
        rotated = re.search(r"pw-verify=(\S+)", run("verify", "init", ROOT, "--rotate").output)
        assert first and second and rotated
        assert first.group(1) == second.group(1) != rotated.group(1)

    def test_acknowledgement_allows_active_checks_only(
        self, modules: dict[str, Any], tmp_path: Path
    ) -> None:
        answers = "\n".join(
            ["Ana Lopez", "Acme Protocol", "CTO", ROOT, f"I am authorised to test {ROOT}"]
        )
        result = run("authorise", ROOT, input=answers + "\n")
        assert result.exit_code == 0, result.output

        result = run("scan", ROOT, "--active", "--out", str(tmp_path / "out"))
        assert result.exit_code == 0
        assert modules["ports"].ran == ["ports"]
        html = (tmp_path / "out" / "report.html").read_text()
        assert "Ana Lopez" in html and "not proven" in html
        assert "ana.lopez@" not in html, "personal findings need DNS verification"

    @pytest.mark.parametrize(
        "answers",
        [
            ["Ana Lopez", "Acme", "CTO", "other-domain.xyz", f"I am authorised to test {ROOT}"],
            ["Ana Lopez", "Acme", "CTO", ROOT, "yes"],
            ["Ana Lopez", "Acme", "CTO", ROOT, f"i am authorised to test {ROOT}"],
        ],
    )
    def test_acknowledgement_must_be_typed_exactly(self, answers: list[str]) -> None:
        assert run("authorise", ROOT, input="\n".join(answers) + "\n").exit_code == 4
        assert run("scan", ROOT, "--active", "--no-report").exit_code == 4


class TestPersonalData:
    def test_personal_findings_only_when_verified_and_can_be_masked(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        run("scan", ROOT, "--out", str(tmp_path / "unverified"))
        assert "ana.lopez" not in (tmp_path / "unverified" / "report.json").read_text()

        run("verify", "init", ROOT)
        verify_with(monkeypatch, True)
        run("scan", ROOT, "--out", str(tmp_path / "verified"))
        assert "ana.lopez" in (tmp_path / "verified" / "report.html").read_text()

        run("report", ROOT, "--redact-personal", "--out", str(tmp_path / "shared"))
        for name in ("report.html", "report.json"):
            text = (tmp_path / "shared" / name).read_text()
            assert "ana.lopez" not in text and f"a***@{ROOT}" in text


class TestTargets:
    def test_add_show_list_remove(self, tmp_path: Path) -> None:
        staff = tmp_path / "staff.csv"
        staff.write_text(
            f"name,email\nAna,ana@{ROOT}\nBo,BO@{ROOT}\nEve,eve@gmail.com\nX,not-an-address\n"
        )
        result = run(
            "target", "add", ROOT, "--github-org", "acme-protocol",
            "--safe", "eth:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "--greenhouse", "acmeprotocol", "--staff-csv", str(staff),
            "--npm", "@Acme/SDK", "--npm", "acme-cli", "--pypi", "acme-sdk",
            "--contract", "eth:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359=Vault",
            "--ens", "acme.eth",
        )  # fmt: skip
        assert result.exit_code == 0, result.output
        assert "1 address(es) were ignored" in plain(result.output)

        shown = plain(run("target", "show", ROOT).output)
        assert "acme-protocol" in shown and "greenhouse: acmeprotocol" in shown
        assert "2 on file" in shown
        assert "@acme/sdk, acme-cli" in shown and "acme-sdk" in shown
        assert "Vault" in shown and "acme.eth" in shown
        assert "ana@" not in shown, "addresses are counted, never echoed"
        assert ROOT in run("target", "list").output

        assert run("target", "remove", ROOT, "--yes").exit_code == 0
        assert run("target", "show", ROOT).exit_code == 2

    @pytest.mark.parametrize(
        "args",
        [
            ["--github-org", "-rf"],
            ["--github-org", "a/b"],
            ["--safe", "eth:0x123"],
            ["--safe", "doge:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"],
            ["--safe", "eth:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"],
            ["--greenhouse", "../../etc"],
            ["--npm", "../../etc/passwd"],
            ["--npm", "@acme/../x"],
            ["--npm", "acme sdk"],
            ["--pypi", "-rf"],
            ["--pypi", "acme/sdk"],
            ["--contract", "eth:0x123"],
            ["--contract", "eth:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359=<script>"],
            ["--ens", "acme.com"],
            ["--ens", "Acme.eth/../x"],
            ["--ens", "-acme.eth"],
            ["--greenhouse", "a", "--lever", "b"],
            ["--staff-csv", "/nonexistent/staff.csv"],
        ],
    )
    def test_bad_target_details_exit_2(self, args: list[str]) -> None:
        assert run("target", "add", ROOT, *args).exit_code == 2


class TestSecretsHandling:
    def test_doctor_never_prints_secret_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", CANARY)
        monkeypatch.setenv("HIBP_API_KEY", "hibp-secret-value-123456")

        async def fine(self: Any, name: str, rdtype: str, **kw: Any) -> Any:
            from perimeterwatch.clients.dns import DnsAnswer, DnsStatus

            return DnsAnswer(name, rdtype, DnsStatus.OK, ("a.iana-servers.net",))

        monkeypatch.setattr("perimeterwatch.clients.dns.DnsClient.query", fine)
        result = run("doctor")
        assert result.exit_code == 0, result.output
        assert CANARY not in result.output and "hibp-secret-value" not in result.output
        assert "Key: GITHUB_TOKEN set" in plain(result.output)
        assert "Key: VIRUSTOTAL_API_KEY missing" in plain(result.output)

    def test_secrets_in_the_settings_file_are_refused(self, tmp_path: Path) -> None:
        Path("perimeterwatch.toml").write_text('retention_days = 30\ngithub_token = "ghp_x"\n')
        result = run("scan", ROOT, "--no-report")
        assert result.exit_code == 2
        assert "looks like a secret" in plain(result.output)
        assert "ghp_x" not in result.output

    def test_nested_secrets_are_refused_too(self) -> None:
        Path("perimeterwatch.toml").write_text('[providers.hibp]\napi_key = "abc"\n')
        assert run("scan", ROOT, "--no-report").exit_code == 2

    def test_settings_file_values_are_used(self, tmp_path: Path) -> None:
        Path("perimeterwatch.toml").write_text(
            'retention_days = 7\ncontact_url = "https://scanner.acme.example/about"\n'
        )
        run("scan", ROOT, "--out", str(tmp_path / "out"))
        method = json.loads((tmp_path / "out" / "report.json").read_text())["methodology"]
        assert method["retention_days"] == 7
        assert "scanner.acme.example" in method["user_agent"]

    def test_dotenv_is_read_without_exporting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Path(".env").write_text(f"GITHUB_TOKEN={CANARY}\nPW_RETENTION_DAYS=11\n")
        from perimeterwatch import config

        config._dotenv.cache_clear()
        assert config.secret("GITHUB_TOKEN") == CANARY
        assert config.load_settings().retention_days == 11
        assert "GITHUB_TOKEN" not in os.environ


class TestMaintenance:
    def test_purge(self) -> None:
        for _ in range(3):
            run("scan", ROOT, "--no-report")
        assert "Deleted 0 scan(s)" in plain(run("db", "purge").output)
        assert "Deleted 2 scan(s)" in plain(run("db", "purge", "--older-than", "0h").output)
        assert run("db", "purge", "--older-than", "soon").exit_code == 2

    def test_new_key_is_usable(self) -> None:
        from perimeterwatch.storage.crypto import DataKeys

        key = run("db", "new-key").output.strip()
        assert DataKeys([key]).decrypt(DataKeys([key]).encrypt(b"x")) == b"x"

    def test_modules_list(self) -> None:
        text = plain(run("modules", "list").output)
        assert "ports active" in text and "GITHUB_TOKEN" in text
