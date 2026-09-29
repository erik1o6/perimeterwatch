"""What an SSH server offers before anyone signs in. Active: needs authorisation.

Connects, reads the server's banner and the list of algorithms it offers, and
disconnects. It never attempts to sign in. The tool used also has a
denial-of-service test and a connection rate test: neither is ever run.
"""

from __future__ import annotations

import json
from typing import Any

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.netguard import is_public_ip
from perimeterwatch.safety.subprocess import run_tool

SSH_PORTS = {22, 2222}
MAX_TARGETS = 50
MAX_NAMES = 40
# Fixed arguments. A test asserts that the dangerous options can never appear.
ARGS = ("-j", "-n", "--skip-rate-test", "-t", "8", "--threads", "4")
FORBIDDEN = ("--dheat", "--conn-rate-test", "-c", "--client-audit", "-g", "--gex-test", "--socks5")


def clean(value: Any, length: int = 80) -> str:
    text = " ".join(str(value or "").split())[:length]
    return text if all(c.isprintable() and c not in "<>\"'&" for c in text) else ""


def parse_output(stdout: str) -> list[dict[str, Any]]:
    """One result, or a list of them when several targets were given."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    rows = data if isinstance(data, list) else [data]
    return [r for r in rows if isinstance(r, dict)]


def weak_algorithms(row: dict[str, Any]) -> list[str]:
    """Algorithms the tool says must be removed, as 'kind: name'."""
    critical = (row.get("recommendations") or {}).get("critical") or {}
    remove = critical.get("del") if isinstance(critical, dict) else None
    names: set[str] = set()
    for kind, items in (remove or {}).items() if isinstance(remove, dict) else ():
        for item in items if isinstance(items, list) else []:
            name = clean(item.get("name")) if isinstance(item, dict) else ""
            if name and kind in ("kex", "key", "enc", "mac"):
                names.add(f"{kind}: {name}")
    return sorted(names)[:MAX_NAMES]


def host_keys(row: dict[str, Any]) -> list[str]:
    keys = set()
    for item in row.get("fingerprints") or []:
        if isinstance(item, dict) and item.get("hash_alg") == "SHA256":
            kind, digest = clean(item.get("hostkey"), 40), clean(item.get("hash"), 64)
            if kind and digest:
                keys.add(f"{kind} SHA256:{digest}")
    return sorted(keys)[:10]


@register
class SshAudit(ScanModule):
    spec = ModuleSpec(
        name="ssh_audit",
        title="SSH server settings",
        category=Category.VULN,
        mode=ScanMode.ACTIVE,
        description="Weak algorithms offered by your SSH servers, and changes of host key.",
        requires_binaries=("ssh-audit",),
        depends_on=("ports",),
        contacts=("each host with an open SSH port, a few connections without signing in",),
        default_timeout_s=900,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        ports = ctx.assets.get("ports")
        if ports is None or not ctx.assets.completed("ports"):
            return self.result(
                ModuleStatus.FAILED, skip_reason="open ports were not identified first"
            )
        targets: dict[str, list[str]] = {}
        for finding in ports.findings:
            port = finding.identity.get("port", "")
            ip = finding.asset_key
            if port.isdigit() and int(port) in SSH_PORTS and is_public_ip(ip) and ":" not in ip:
                hosts = [str(h) for h in finding.evidence.get("hosts", [])][:5]
                targets[f"{ip}:{port}"] = hosts
        if not targets:
            return self.result(notes=["No SSH server was found on the scanned hosts."])
        selected = sorted(targets)[:MAX_TARGETS]

        listing = ctx.workdir / "ssh-audit-targets.txt"
        listing.write_text("\n".join(selected) + "\n")
        output = await run_tool(
            ctx,
            "ssh-audit",
            [*ARGS, "-T", str(listing)],
            timeout_s=840,
            # The tool exits with 2 or 3 when it finds something to report.
            ok_returncodes=(0, 1, 2, 3),
        )

        findings: list[Finding] = []
        seen = 0
        for row in parse_output(output.stdout):
            where = clean(row.get("target"), 60)
            if where not in targets:
                continue  # an answer about something that was not asked
            seen += 1
            ip, _, port = where.rpartition(":")
            hosts = targets[where]
            label = hosts[0] if hosts else ip
            banner = row.get("banner") if isinstance(row.get("banner"), dict) else {}
            software = clean((banner or {}).get("software"), 60)
            weak = weak_algorithms(row)
            if weak:
                findings.append(
                    self.finding(
                        "ssh.weak_algorithms", AssetType.IP, ip,
                        f"The SSH server on {label} offers {len(weak)} weak algorithm(s)",
                        identity={"port": port},
                        state={"algorithms": weak},
                        evidence={"algorithms": weak, "software": software, "hosts": hosts},
                        confidence=Confidence.CONFIRMED,
                    )
                )  # fmt: skip
            keys = host_keys(row)
            if keys:
                findings.append(
                    self.finding(
                        "ssh.host_keys", AssetType.IP, ip,
                        f"SSH host keys of {label}",
                        identity={"port": port},
                        state={"host_keys": keys},
                        evidence={"host_keys": keys, "software": software, "hosts": hosts},
                        confidence=Confidence.CONFIRMED,
                    )
                )  # fmt: skip
        notes = []
        if seen < len(selected):
            notes.append(f"{len(selected) - seen} SSH server(s) did not answer.")
        truncated = len(targets) > MAX_TARGETS
        return self.result(
            ModuleStatus.PARTIAL if truncated or seen < len(selected) else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={"servers_asked": len(selected), "servers_answered": seen},
        )
