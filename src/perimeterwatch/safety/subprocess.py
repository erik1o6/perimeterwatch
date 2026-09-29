"""The only way external tools are run.

Rules enforced here:
- exec only, never through a shell
- the binary comes from the managed tools directory
- no argument may be a value taken from user input unless it passed a validator,
  and scan targets are passed by file or stdin, never on the command line
- the environment is rebuilt from an allowlist, so no secret reaches a tool by accident
- every run has a timeout and an output cap
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from perimeterwatch.core.errors import ToolError
from perimeterwatch.logging import scrub

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
DEFAULT_MAX_OUTPUT = 64_000_000


@dataclass(frozen=True)
class ToolOutput:
    binary: str
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False

    def lines(self) -> Iterator[str]:
        for line in self.stdout.splitlines():
            line = line.strip()
            if line:
                yield line

    def json_lines(self) -> Iterator[dict[str, Any]]:
        """Parsed JSONL. Lines that are not JSON objects are skipped."""
        for line in self.lines():
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def check_args(args: Sequence[str]) -> list[str]:
    checked = []
    for arg in args:
        if not isinstance(arg, str):
            raise ToolError("Tool arguments must be text.")
        if "\x00" in arg or "\n" in arg or "\r" in arg:
            raise ToolError("Tool argument contains a control character.")
        checked.append(arg)
    return checked


def clean_env(home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """A minimal environment. HOME is a throwaway directory: the tools insist on
    writing config files there, and must not read the user's own."""
    home.mkdir(mode=0o700, exist_ok=True)
    env = {k: os.environ[k] for k in ENV_ALLOWLIST if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin")
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["NO_COLOR"] = "1"
    if extra:
        env.update(extra)
    return env


async def _read_capped(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if size < limit:
            chunks.append(chunk[: limit - size])
        size += len(chunk)
        if size > limit:
            truncated = True
    return b"".join(chunks), truncated


def _kill_group(process: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def run_tool(
    ctx: ScanContext,
    binary: str,
    args: Sequence[str],
    *,
    stdin_lines: Iterable[str] | None = None,
    timeout_s: int = 600,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
    env: dict[str, str] | None = None,
    ok_returncodes: tuple[int, ...] = (0,),
) -> ToolOutput:
    path = ctx.tools.resolve(binary)
    if path is None:
        raise ToolError(f"{binary} is not installed. Run 'pwatch tools install {binary}'.")

    stdin_data = None
    if stdin_lines is not None:
        lines = [line for line in stdin_lines if line and "\n" not in line and "\x00" not in line]
        stdin_data = ("\n".join(lines) + "\n").encode()

    process = await asyncio.create_subprocess_exec(
        str(path),
        *check_args(args),
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(ctx.workdir),
        env=clean_env(ctx.workdir / "home", env),
        start_new_session=True,  # own process group, so children die with it
    )
    assert process.stdout is not None and process.stderr is not None

    async def feed() -> None:
        if stdin_data is not None and process.stdin is not None:
            try:
                process.stdin.write(stdin_data)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()

    try:
        async with asyncio.timeout(timeout_s):
            _, (stdout, truncated), (stderr, _) = await asyncio.gather(
                feed(),
                _read_capped(process.stdout, max_output_bytes),
                _read_capped(process.stderr, 1_000_000),
            )
            returncode = await process.wait()
    except TimeoutError as exc:
        _kill_group(process)
        await process.wait()
        raise ToolError(f"{binary} did not finish within {timeout_s} seconds.") from exc
    except BaseException:
        _kill_group(process)
        raise

    output = ToolOutput(
        binary=binary,
        returncode=returncode,
        stdout=stdout.decode("utf-8", "replace"),
        stderr=scrub(stderr.decode("utf-8", "replace")),
        truncated=truncated,
    )
    if returncode not in ok_returncodes:
        tail = output.stderr.strip().splitlines()[-3:]
        ctx.log.warning("tool failed", binary=binary, code=returncode, stderr=" | ".join(tail))
        raise ToolError(f"{binary} exited with code {returncode}.")
    return output
