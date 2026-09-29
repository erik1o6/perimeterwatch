"""Run subfinder. Passive sources only: it queries indexes, never the target."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from perimeterwatch.safety.subprocess import run_tool

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

# subfinder source name -> the secret that holds its key
SOURCE_KEYS = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "certspotter": "CERTSPOTTER_API_KEY",
    "chaos": "CHAOS_API_KEY",
    "github": "GITHUB_TOKEN",
}


def provider_config(ctx: ScanContext) -> str:
    """YAML for subfinder's provider file. Values are JSON strings, which YAML accepts."""
    lines = []
    for source, secret_name in SOURCE_KEYS.items():
        value = ctx.secret(secret_name)
        if value:
            lines.append(f"{source}:\n  - {json.dumps(value)}")
    return "\n".join(lines) + "\n"


async def run_subfinder(domain: str, ctx: ScanContext) -> list[str]:
    config = ctx.workdir / "subfinder-providers.yaml"
    fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(provider_config(ctx))
    targets = ctx.workdir / "subfinder-targets.txt"
    targets.write_text(domain + "\n")
    try:
        output = await run_tool(
            ctx,
            "subfinder",
            [
                "-dL",
                str(targets),
                "-provider-config",
                str(config),
                "-oJ",
                "-silent",
                "-disable-update-check",
                "-timeout",
                "30",
                "-max-time",
                "4",
            ],
            timeout_s=300,
        )
    finally:
        config.unlink(missing_ok=True)
    names = []
    for row in output.json_lines():
        host = row.get("host")
        if isinstance(host, str):
            names.append(host)
    return names
