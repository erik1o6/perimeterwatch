"""The subprocess runner, the installer, and the nuclei template rules."""

from __future__ import annotations

import hashlib
import io
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from perimeterwatch.core.errors import ToolError
from perimeterwatch.safety import subprocess as runner
from perimeterwatch.safety.templates import problem, select_templates
from perimeterwatch.tools import installer
from perimeterwatch.tools.bump import _parse_checksums
from perimeterwatch.tools.locate import ToolLocator, ToolPin, manifest
from tests.conftest import CANARY, FIXTURES

SRC = Path(__file__).parents[2] / "src"


class TestNoShell:
    def test_source_never_uses_a_shell(self) -> None:
        offenders = []
        patterns = (
            r"shell\s*=\s*True",
            r"os\.system\(",
            r"os\.popen\(",
            r"create_subprocess_shell",
        )
        for path in SRC.rglob("*.py"):
            text = path.read_text()
            for pattern in patterns:
                if re.search(pattern, text):
                    offenders.append(f"{path.relative_to(SRC)}: {pattern}")
        assert offenders == []

    def test_only_the_runner_and_installer_start_processes(self) -> None:
        allowed = {"perimeterwatch/safety/subprocess.py", "perimeterwatch/tools/installer.py"}
        starters = set()
        for path in SRC.rglob("*.py"):
            text = path.read_text()
            if re.search(r"create_subprocess_exec|subprocess\.(run|Popen|call|check_)", text):
                starters.add(str(path.relative_to(SRC)))
        assert starters <= allowed, starters - allowed


@pytest.fixture
def script_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_ctx: Any) -> Any:
    """A context whose 'subfinder' is a small script we control."""
    tools = tmp_path / "tools"
    pin = manifest()["subfinder"]
    target = tools / pin.name / pin.version
    target.mkdir(parents=True)

    def make(body: str) -> Any:
        binary = target / pin.binary
        binary.write_text("#!/bin/sh\n" + body)
        binary.chmod(0o755)
        return make_ctx(tools_dir=tools)

    return make


class TestRunner:
    async def test_arguments_are_passed_literally(self, script_tool: Any) -> None:
        ctx = script_tool('for a in "$@"; do printf "%s\\n" "$a"; done\n')
        hostile = ["$(id)", "`id`", "; rm -rf /", "a b", "*", "|cat /etc/passwd", "&&", ">out"]
        output = await runner.run_tool(ctx, "subfinder", hostile)
        assert list(output.stdout.splitlines()) == hostile
        assert not (ctx.workdir / "out").exists()

    @pytest.mark.parametrize("bad", ["a\nb", "a\x00b", "a\rb"])
    async def test_control_characters_are_refused(self, script_tool: Any, bad: str) -> None:
        ctx = script_tool("exit 0\n")
        with pytest.raises(ToolError):
            await runner.run_tool(ctx, "subfinder", [bad])

    async def test_environment_is_rebuilt(
        self, script_tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", CANARY)
        monkeypatch.setenv("HIBP_API_KEY", "secret-hibp")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-aws")
        ctx = script_tool("env\n")
        output = await runner.run_tool(ctx, "subfinder", [], env={"ONLY_THIS": "1"})
        names = {line.split("=")[0] for line in output.stdout.splitlines()}
        assert "ONLY_THIS" in names
        assert not names & {"GITHUB_TOKEN", "HIBP_API_KEY", "AWS_SECRET_ACCESS_KEY"}
        assert CANARY not in output.stdout
        home = next(line for line in output.stdout.splitlines() if line.startswith("HOME="))
        assert str(ctx.workdir) in home, "tools get a throwaway home directory"
        assert os.environ["HOME"] not in home

    async def test_stdin_lines_cannot_inject_extra_lines(self, script_tool: Any) -> None:
        ctx = script_tool("cat\n")
        output = await runner.run_tool(
            ctx, "subfinder", [], stdin_lines=["a.example", "b.example\nevil.example", ""]
        )
        assert output.stdout.split() == ["a.example"]

    async def test_timeout_kills_the_whole_process_group(self, script_tool: Any) -> None:
        ctx = script_tool('(sleep 60; echo late > "$PWD/late") &\nsleep 60\n')
        with pytest.raises(ToolError, match="did not finish"):
            await runner.run_tool(ctx, "subfinder", [], timeout_s=1)
        assert not (ctx.workdir / "late").exists()

    async def test_output_is_capped(self, script_tool: Any) -> None:
        ctx = script_tool("head -c 300000 /dev/zero | tr '\\0' 'a'\n")
        output = await runner.run_tool(ctx, "subfinder", [], max_output_bytes=1000)
        assert len(output.stdout) == 1000 and output.truncated

    async def test_failure_is_reported_without_leaking_stderr_secrets(
        self, script_tool: Any
    ) -> None:
        ctx = script_tool(f'echo "auth failed for {CANARY}" >&2\nexit 7\n')
        with pytest.raises(ToolError) as excinfo:
            await runner.run_tool(ctx, "subfinder", [])
        assert CANARY not in str(excinfo.value)
        assert "code 7" in str(excinfo.value)

    async def test_missing_tool(self, make_ctx: Any) -> None:
        with pytest.raises(ToolError, match="not installed"):
            await runner.run_tool(make_ctx(), "subfinder", [])

    def test_json_lines_tolerate_noise(self) -> None:
        output = runner.ToolOutput("x", 0, 'banner\n{"a":1}\n{broken\n[1,2]\n\n{"b":2}\n', "")
        assert list(output.json_lines()) == [{"a": 1}, {"b": 2}]


class TestLocator:
    def test_path_is_never_searched_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The Python httpx package installs a command with the same name as the tool.
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        (fake_bin / "httpx").write_text("#!/bin/sh\n")
        (fake_bin / "httpx").chmod(0o755)
        monkeypatch.setenv("PATH", str(fake_bin))
        assert ToolLocator(tmp_path / "tools").resolve("httpx") is None
        assert ToolLocator(tmp_path / "tools", allow_path=True).resolve("httpx") is not None

    def test_every_pin_has_a_full_checksum_and_a_github_url(self) -> None:
        pins = manifest()
        assert {
            "subfinder",
            "httpx",
            "tlsx",
            "naabu",
            "nuclei",
            "nuclei-templates",
            "trufflehog",
            "betterleaks",
        } <= set(pins)
        for pin in pins.values():
            assert pin.assets, pin.name
            for asset in pin.assets.values():
                assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), pin.name
                if pin.kind == "python":
                    # Installed from PyPI with the project. The lock file pins its hashes.
                    assert asset["url"].startswith("https://pypi.org/project/"), pin.name
                else:
                    assert asset["url"].startswith(f"https://github.com/{pin.repo}/"), pin.name
                assert pin.version in asset["url"], pin.name


def make_zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def make_tar(members: dict[str, bytes], links: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buffer.getvalue()


class TestInstaller:
    @pytest.fixture
    def pinned(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        """Pin a fake tool and serve its archive from memory."""

        def setup(archive: bytes, *, sha256: str | None = None, kind: str = "binary") -> Any:
            pin = ToolPin(
                name="faketool", version="1.0.0", repo="example/faketool", binary="faketool",
                license="MIT", version_args=("-version",), kind=kind,
                assets={"any": {
                    "url": "https://github.com/example/faketool/releases/download/v1.0.0/f.zip",
                    "sha256": sha256 or hashlib.sha256(archive).hexdigest(),
                }},
            )  # fmt: skip
            monkeypatch.setattr(installer, "manifest", lambda: {"faketool": pin})
            monkeypatch.setattr("perimeterwatch.tools.locate.manifest", lambda: {"faketool": pin})

            def fake_download(url: str, destination: Path, **kw: Any) -> str:
                installer.check_url(url)
                destination.write_bytes(archive)
                return hashlib.sha256(archive).hexdigest()

            monkeypatch.setattr(installer, "download", fake_download)
            return installer.Installer(tmp_path / "tools")

        return setup

    def test_installs_and_verifies(self, pinned: Any) -> None:
        inst = pinned(make_zip({"README.md": b"hi", "faketool": b"#!/bin/sh\nexit 0\n"}))
        state = inst.install("faketool")
        assert state.verified and state.path is not None
        assert state.path.stat().st_mode & 0o777 == 0o755
        assert sorted(p.name for p in state.path.parent.iterdir()) == [".sha256", "faketool"]

    def test_checksum_mismatch_installs_nothing(self, pinned: Any, tmp_path: Path) -> None:
        inst = pinned(make_zip({"faketool": b"#!/bin/sh\necho tampered\n"}), sha256="0" * 64)
        with pytest.raises(ToolError, match="failed verification"):
            inst.install("faketool")
        assert not list((tmp_path / "tools").rglob("faketool/1.0.0/faketool"))
        assert not inst.verify("faketool").installed

    def test_a_changed_binary_fails_verification(self, pinned: Any) -> None:
        inst = pinned(make_zip({"faketool": b"#!/bin/sh\nexit 0\n"}))
        path = inst.install("faketool").path
        path.write_bytes(path.read_bytes() + b"# tampered\n")
        state = inst.verify("faketool")
        assert state.installed and not state.verified
        assert "changed" in state.detail

    @pytest.mark.parametrize("name", ["../../evil", "/etc/cron.d/evil", "a/../../faketool"])
    def test_zip_path_traversal_is_refused(self, pinned: Any, name: str, tmp_path: Path) -> None:
        inst = pinned(make_zip({name: b"x", "faketool": b"#!/bin/sh\n"}))
        with pytest.raises(ToolError, match="unsafe path"):
            inst.install("faketool")
        assert not (tmp_path / "evil").exists()

    def test_tar_link_in_place_of_the_binary_is_refused(self, pinned: Any) -> None:
        inst = pinned(make_tar({}, links={"faketool": "/bin/sh"}))
        with pytest.raises(ToolError, match="link"):
            inst.install("faketool")

    def test_archive_without_the_binary(self, pinned: Any) -> None:
        inst = pinned(make_zip({"other": b"x"}))
        with pytest.raises(ToolError, match="does not contain"):
            inst.install("faketool")

    def test_data_archive_cannot_escape(self, pinned: Any, tmp_path: Path) -> None:
        inst = pinned(make_tar({"top/ok.yaml": b"id: x", "top/../../escape": b"x"}), kind="data")
        with pytest.raises(Exception, match=r"(?i)outside|unsafe|escape"):
            inst.install("faketool")
        assert not (tmp_path / "escape").exists()

    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com/x/y/releases/download/v1/f.zip",
            "https://github.com.evil.net/x.zip",
            "https://evil.net/github.com/x.zip",
            "https://raw.githubusercontent.com/x/y/main/f.zip",
            "file:///etc/passwd",
            "https://169.254.169.254/latest/meta-data/",
        ],
    )
    def test_downloads_only_from_github_over_https(self, url: str) -> None:
        with pytest.raises(ToolError):
            installer.check_url(url)

    def test_checksum_file_parsing(self) -> None:
        text = (
            f"{'a' * 64}  tool_1.0_linux_amd64.zip\n"
            f"{'B' * 64} *tool_1.0_linux_arm64.zip\n"
            "not a checksum line\n"
            f"{'c' * 10}  short.zip\n"
        )
        assert _parse_checksums(text) == {
            "tool_1.0_linux_amd64.zip": "a" * 64,
            "tool_1.0_linux_arm64.zip": "b" * 64,
        }


def template(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "example",
        "info": {"name": "Example", "severity": "info", "tags": "exposure,config"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/.git/config"]}],
    }
    base.update(overrides)
    return base


class TestTemplateRules:
    def test_a_plain_get_is_admitted(self) -> None:
        assert problem(template()) is None
        assert problem(template(http=[{"path": ["{{BaseURL}}"]}])) is None, "GET is the default"
        assert problem(template(http=[{"method": "HEAD", "path": ["{{RootURL}}/x"]}])) is None

    @pytest.mark.parametrize(
        "changes",
        [
            {"http": [{"method": "POST", "path": ["{{BaseURL}}"]}]},
            {"http": [{"method": "PUT", "path": ["{{BaseURL}}"]}]},
            {"http": [{"method": "DELETE", "path": ["{{BaseURL}}/x"]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}"], "body": "x=1"}]},
            {"http": [{"raw": ["POST / HTTP/1.1\nHost: {{Hostname}}\n\nx"]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}/{{p}}"], "payloads": {"p": ["a"]}}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}"], "fuzzing": [{}]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}"], "attack": "clusterbomb"}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}"], "race": True}]},
            {"http": [{"method": "GET", "path": ["https://evil.example.net/collect"]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}/?u=http://{{interactsh-url}}"]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}/../../etc/passwd"]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}/?q=<script>alert(1)</script>"]}]},
            {"http": [{"method": "GET", "path": [f"{{{{BaseURL}}}}/{i}" for i in range(20)]}]},
            {"http": [{"method": "GET", "path": ["{{BaseURL}}"]},
                      {"method": "POST", "path": ["{{BaseURL}}"]}]},
            {"http": "nonsense"},
            {"http": [], "requests": [{"method": "POST", "path": ["{{BaseURL}}"]}]},
            {"tcp": [{"host": ["{{Hostname}}"]}]},
            {"code": [{"engine": ["sh"], "source": "id"}]},
            {"javascript": [{"code": "x"}]},
            {"headless": [{"steps": []}]},
            {"file": [{"extensions": ["all"]}]},
            {"flow": "http(1) && http(2)"},
            {"self-contained": True},
            {"info": {"severity": "high", "tags": "exposure,rce"}},
            {"info": {"severity": "high", "tags": "cve,cve2024,exposure"}},
            {"info": {"severity": "info", "tags": ["tech", "intrusive"]}},
            {"info": {"severity": "info", "tags": "EXPOSURE, FUZZ"}},
            {"info": {"severity": "info", "tags": "panel,login"}},
            {"info": {"severity": "info"}},
            {"info": "nonsense"},
            {"id": ""},
        ],
    )  # fmt: skip
    def test_anything_else_is_refused(self, changes: dict[str, Any]) -> None:
        assert problem(template(**changes)) is not None

    @pytest.mark.parametrize("value", [None, [], "text", 5])
    def test_malformed_templates_are_refused(self, value: Any) -> None:
        assert problem(value) is not None

    def test_selection_from_a_directory(self) -> None:
        selection = select_templates(FIXTURES / "nuclei_templates")
        assert selection.ids == {"git-config", "nginx-version"}
        assert selection.rejected == {"request uses body": 1}, "the WAF template is refused"
        # Templates outside the allowed directories are never even read.
        assert not any("cves" in str(p) for p in selection.admitted)

    def test_links_out_of_the_directory_are_refused(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.yaml"
        outside.write_text(yaml.safe_dump(template()))
        base = tmp_path / "templates" / "http" / "exposures"
        base.mkdir(parents=True)
        (base / "linked.yaml").symlink_to(outside)
        (base / "real.yaml").write_text(yaml.safe_dump(template(id="real")))
        selection = select_templates(tmp_path / "templates")
        assert selection.ids == {"real"}

    def test_yaml_cannot_run_code(self, tmp_path: Path) -> None:
        base = tmp_path / "http" / "exposures"
        base.mkdir(parents=True)
        (base / "evil.yaml").write_text(
            '!!python/object/apply:os.system ["touch ' + str(tmp_path / "pwned") + '"]\n'
        )
        selection = select_templates(tmp_path)
        assert selection.admitted == []
        assert not (tmp_path / "pwned").exists()
