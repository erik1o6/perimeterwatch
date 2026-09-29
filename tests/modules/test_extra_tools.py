"""Betterleaks beside trufflehog, tested against recorded and hand-written output.

No tool is run and nothing touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from parapet.core.errors import ToolError
from parapet.core.models import ModuleStatus, ScanMode, Sensitivity, Target
from parapet.modules import _second_scanner, github_secrets
from parapet.modules._second_scanner import parse_finding, parse_report
from parapet.modules.github_secrets import GitHubSecrets
from parapet.safety.subprocess import ToolOutput
from tests.conftest import CANARY, ROOT, fixture_text
from tests.helpers import FakeRunner, install_fake_tools

TARGET = Target(root_domain=ROOT, github_org="acme-protocol")
TOKEN = "ghp_testtokentesttokentesttokentest1234"
ONLY_BETTERLEAKS = "canary_key_BLCANARYblcanaryBLCANARYblcanary0042"
PERSONAL = ("ana.lopez", "Ana Lopez", "add release script")


@pytest.fixture(autouse=True)
def token(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    return TOKEN


@pytest.fixture
def ctx(make_ctx: Any, tmp_path: Path) -> Any:
    tools = install_fake_tools(tmp_path / "tools", "trufflehog", "betterleaks")
    return make_ctx(mode=ScanMode.PASSIVE, tools_dir=tools)


@pytest.fixture
def ctx_one_scanner(make_ctx: Any, tmp_path: Path) -> Any:
    tools = install_fake_tools(tmp_path / "tools", "trufflehog")
    return make_ctx(mode=ScanMode.PASSIVE, tools_dir=tools)


def both(betterleaks: str | None = None, trufflehog: str | None = None) -> FakeRunner:
    return FakeRunner(
        {
            "trufflehog": fixture_text("trufflehog", "org.jsonl")
            if trufflehog is None
            else trufflehog,
            "betterleaks": fixture_text("betterleaks", "org.json")
            if betterleaks is None
            else betterleaks,
        }
    )


async def scan(runner: Any, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(github_secrets, "run_tool", runner)
    return await GitHubSecrets().run(TARGET, ctx)


def by_repo(result: Any, repo: str) -> Any:
    return next(f for f in result.findings if f.asset_key == repo)


class TestCommandLine:
    async def test_never_holds_the_token_and_never_enables_validation(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = both()
        await scan(runner, ctx, monkeypatch)
        call = runner.last("betterleaks")
        args = call["args"]

        assert TOKEN not in " ".join(args), "the token must not be on the command line"
        assert not any(a.startswith("--token") for a in args)
        assert call["env"]["GITHUB_TOKEN"] == TOKEN

        assert "--validation=false" in args
        enabling = {"--validation", "--validation=true", "--validation-debug"}
        assert not enabling & set(args)
        assert not any(a.startswith("--validation-") for a in args)
        assert "validate" not in args, "that subcommand tests a credential against its service"

        assert args[:2] == ["github", "https://github.com/acme-protocol"]
        assert "--ignore-gitleaks-allow" in args
        assert not any(a.startswith("--redact") for a in args)

    async def test_clones_stay_inside_the_scan_directory(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = both()
        await scan(runner, ctx, monkeypatch)
        scratch = Path(runner.last("betterleaks")["env"]["TMPDIR"])
        assert scratch.is_relative_to(ctx.workdir)

    async def test_trufflehog_is_run_as_before(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = both()
        await scan(runner, ctx, monkeypatch)
        call = runner.last("trufflehog")
        assert "--no-verification" in call["args"]
        assert call["env"] == {"GITHUB_TOKEN": TOKEN}

    def test_the_organisation_is_the_only_variable_part(self) -> None:
        assert [a for a in _second_scanner.command("acme") if "acme" in a] == [
            "https://github.com/acme"
        ]


class TestMerging:
    async def test_no_secret_reaches_the_result(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await scan(both(), ctx, monkeypatch)
        dumped = result.model_dump_json()
        assert CANARY not in dumped
        assert ONLY_BETTERLEAKS not in dumped
        assert ONLY_BETTERLEAKS[:12] not in dumped, "only the first four characters are kept"
        assert "AKIAIOSFODNN7EXAMPLE" not in dumped
        for personal in PERSONAL:
            assert personal not in dumped, "names, addresses and commit messages are dropped"

    async def test_found_by_both_is_one_finding(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await scan(both(), ctx, monkeypatch)
        matching = [f for f in result.findings if f.asset_key == "acme-protocol/deploy-scripts"]
        assert len(matching) == 1
        finding = matching[0]
        assert finding.evidence["found_by"] == ["betterleaks", "trufflehog"]
        assert finding.evidence["tested"] == "no"
        assert finding.evidence["starts_with"] == "ghp_********"
        assert finding.sensitivity is Sensitivity.SECRET

    async def test_a_second_scanner_does_not_change_what_trufflehog_found(
        self, ctx: Any, ctx_one_scanner: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Otherwise installing Betterleaks would report every old finding as new."""
        alone = await scan(both(), ctx_one_scanner, monkeypatch)
        together = await scan(both(), ctx, monkeypatch)
        for finding in alone.findings:
            twin = by_repo(together, finding.asset_key)
            assert twin.identity == finding.identity
            assert twin.title == finding.title

    async def test_found_only_by_betterleaks_still_appears(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await scan(both(), ctx, monkeypatch)
        finding = by_repo(result, "acme-protocol/payments")
        assert finding.evidence["found_by"] == ["betterleaks"]
        assert finding.evidence["type"] == "stripe-access-token"
        assert finding.evidence["file"] == "config/settings.py"
        assert finding.evidence["line"] == "7"
        assert finding.evidence["committed"] == "2025-03-02"
        assert finding.evidence["starts_with"] == "cana********"
        assert finding.evidence["tested"] == "no"
        assert len(finding.identity["hash"]) == 8
        assert finding.sensitivity is Sensitivity.SECRET

    async def test_found_only_by_trufflehog_still_appears(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await scan(both(), ctx, monkeypatch)
        assert by_repo(result, "acme-protocol/frontend").evidence["found_by"] == ["trufflehog"]

    async def test_counts(self, ctx: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        result = await scan(both(), ctx, monkeypatch)
        assert result.status is ModuleStatus.OK
        assert len(result.findings) == 3
        assert result.stats == {"credentials": 3, "from_trufflehog": 2, "from_betterleaks": 2}

    async def test_results_outside_github_are_dropped(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await scan(both(), ctx, monkeypatch)
        assert "elsewhere" not in result.model_dump_json()


class TestOptional:
    async def test_without_betterleaks_trufflehog_runs_alone(
        self, ctx_one_scanner: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = both()
        result = await scan(runner, ctx_one_scanner, monkeypatch)
        assert [c["binary"] for c in runner.calls] == ["trufflehog"]
        assert result.status is ModuleStatus.OK
        assert len(result.findings) == 2
        assert all(f.evidence["found_by"] == ["trufflehog"] for f in result.findings)
        assert any("Betterleaks is not installed" in note for note in result.notes)

    def test_the_module_declares_it_optional(self) -> None:
        assert GitHubSecrets.spec.requires_binaries == ("trufflehog",)
        assert GitHubSecrets.spec.optional_binaries == ("betterleaks",)

    async def test_a_failure_of_betterleaks_does_not_stop_the_module(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        inner = both()

        async def runner(ctx: Any, binary: str, args: Any, **kwargs: Any) -> ToolOutput:
            if binary == "betterleaks":
                raise ToolError("betterleaks exited with code 2.")
            return await inner(ctx, binary, args, **kwargs)

        result = await scan(runner, ctx, monkeypatch)
        assert len(result.findings) == 2
        # Partial, so that what only Betterleaks found before is not reported as fixed.
        assert result.status is ModuleStatus.PARTIAL
        assert any("Betterleaks failed" in note for note in result.notes)

    async def test_a_failure_of_trufflehog_still_fails_the_module(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        inner = both()

        async def runner(ctx: Any, binary: str, args: Any, **kwargs: Any) -> ToolOutput:
            if binary == "trufflehog":
                raise ToolError("trufflehog exited with code 1.")
            return await inner(ctx, binary, args, **kwargs)

        with pytest.raises(ToolError):
            await scan(runner, ctx, monkeypatch)

    async def test_an_unfinished_scan_is_reported_as_partial(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        inner = both()

        async def runner(ctx: Any, binary: str, args: Any, **kwargs: Any) -> ToolOutput:
            output = await inner(ctx, binary, args, **kwargs)
            if binary == "betterleaks":
                return ToolOutput(binary, 1, output.stdout, "")
            return output

        result = await scan(runner, ctx, monkeypatch)
        assert result.status is ModuleStatus.PARTIAL
        assert len(result.findings) == 3, "what was found before the error is kept"


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "output",
        [
            "",
            "not json at all",
            "[",
            "[]",
            "{}",
            "null",
            '["text", 5, null]',
            '[{"RuleID": "x"',
            "[" * 5000,
            '[{"a":' * 5000,
            "\x00\x01\x02",
            '[{"RuleID": "x", "Secret": "abcdefghijklmnop"}]',
        ],
    )
    async def test_the_module_survives(
        self, output: str, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await scan(both(betterleaks=output), ctx, monkeypatch)
        assert len(result.findings) == 2, "trufflehog's findings are unaffected"

    async def test_output_cut_short_keeps_what_came_before(
        self, ctx: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        text = fixture_text("betterleaks", "org.json")
        cut = text[: text.index('"RuleID": "generic-api-key"') + 30]
        result = await scan(both(betterleaks=cut), ctx, monkeypatch)
        assert by_repo(result, "acme-protocol/payments")
        assert ONLY_BETTERLEAKS not in result.model_dump_json()

    def test_report_rows_are_capped(self) -> None:
        text = json.dumps([{"n": n} for n in range(50)])
        assert len(list(parse_report(text, limit=10))) == 10

    @pytest.mark.parametrize(
        "row",
        [
            {},
            {"Secret": "abcdefghijklmnop"},
            {"RuleID": "x", "Secret": ""},
            {"RuleID": "x", "Secret": "   "},
            {"RuleID": "x", "Secret": 5},
            {"RuleID": 5, "Secret": "abcdefghijklmnop"},
            {"RuleID": "x", "Secret": "REDACTED", "Link": "https://github.com/a/b/blob/c/d"},
            {"RuleID": "x", "Secret": "abcdefghijklmnop", "Attributes": "nonsense"},
            {"RuleID": "x", "Secret": "abcdefghijklmnop", "Attributes": {"github.repo_url": []}},
            {"RuleID": "x", "Secret": "abcdefghijklmnop", "Link": "https://github.com/only-org"},
            {"RuleID": "x", "Secret": "abcdefghijklmnop", "Link": "https://github.com/a/<b>"},
            {"RuleID": "x", "Secret": "abcdefghijklmnop", "Link": "http://github.com/a/b"},
            {"RuleID": "x", "Secret": "abcdefghijklmnop", "Link": "https://github.com.evil.io/a/b"},
        ],
    )
    def test_rows_that_cannot_be_used_are_skipped(self, row: dict[str, Any]) -> None:
        assert parse_finding(row) is None

    def test_a_row_is_reduced_and_capped(self) -> None:
        row = {
            "RuleID": "r" * 500,
            "Secret": "hunter2-hunter2-hunter2",
            "Match": "password=hunter2-hunter2-hunter2",
            "StartLine": True,
            "Commit": "not a commit; rm -rf",
            "Date": "2025-03-02T10:11:12Z and a great deal more",
            "File": "f" * 5000,
            "Link": "https://github.com/a/b.git",
        }
        parsed = parse_finding(row)
        assert parsed is not None
        assert "hunter2-" not in json.dumps(parsed)
        assert parsed["repo"] == "a/b"
        assert len(parsed["detector"]) == 80
        assert len(parsed["file"]) == 300
        assert parsed["commit"] == ""
        assert parsed["line"] == ""
        assert parsed["committed"] == "2025-03-02"
        assert set(parsed) == {
            "detector", "repo", "file", "commit", "line", "committed", "starts_with", "hash",
        }  # fmt: skip
