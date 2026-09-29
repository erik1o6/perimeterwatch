"""Helpers for tests that involve external tools. No tool is ever really run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from perimeterwatch.core.models import Asset, AssetType, ModuleResult, ModuleStatus
from perimeterwatch.safety.subprocess import ToolOutput
from perimeterwatch.tools.locate import manifest


def install_fake_tools(tools_dir: Path, *names: str) -> Path:
    """Create empty stand-ins so the locator reports the tools as installed."""
    for name in names:
        pin = manifest()[name]
        target = tools_dir / pin.name / pin.version
        target.mkdir(parents=True, exist_ok=True)
        if pin.kind == "data":
            (target / pin.binary).mkdir(exist_ok=True)
        else:
            binary = target / pin.binary
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
    return tools_dir


class FakeRunner:
    """Stands in for run_tool. Records every call and answers from canned output."""

    def __init__(self, outputs: dict[str, str] | None = None, returncode: int = 0) -> None:
        self.outputs = outputs or {}
        self.returncode = returncode
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, ctx: Any, binary: str, args: Any, **kwargs: Any) -> ToolOutput:
        call = {"binary": binary, "args": list(args), **kwargs, "files": {}}
        # Capture the input files, which are deleted with the scan's work directory.
        for arg in args:
            path = Path(str(arg))
            if path.is_absolute() and path.is_file() and path.is_relative_to(ctx.workdir):
                call["files"][path.name] = path.read_text()
        self.calls.append(call)
        return ToolOutput(binary, self.returncode, self.outputs.get(binary, ""), "")

    def last(self, binary: str) -> dict[str, Any]:
        return next(c for c in reversed(self.calls) if c["binary"] == binary)


def resolved(
    hosts: dict[str, list[str]], *, wildcard: set[str] | None = None, root: str | None = None
) -> ModuleResult:
    """A dns_resolve result: host -> addresses."""
    assets = []
    for host, ips in hosts.items():
        from perimeterwatch.safety.netguard import is_public_ip

        assets.append(
            Asset(
                type=AssetType.DOMAIN if host == root else AssetType.SUBDOMAIN,
                key=host,
                source_module="dns_resolve",
                attributes={
                    "ips": ips,
                    "dns_status": "ok" if ips else "nxdomain",
                    "wildcard_match": host in (wildcard or set()),
                    "private_ips": [ip for ip in ips if not is_public_ip(ip)],
                },
                state={"resolves": bool(ips), "cname": None},
            )
        )
    return ModuleResult(module="dns_resolve", status=ModuleStatus.OK, assets=assets)
