"""Which ports are reachable from the internet. Active: runs only with authorisation.

Ordinary TCP connections to the hundred most common ports, at a gentle rate.
Hosts behind a CDN are skipped apart from ports 80 and 443, because those
addresses belong to the CDN and are shared with its other customers.
"""

from __future__ import annotations

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
from perimeterwatch.safety.targets import contactable_hosts

EXPECTED = {80, 443}
MAX_ADDRESSES = 200

# Services that should almost never face the internet.
RISKY = {
    21: "FTP", 23: "Telnet", 135: "Windows RPC", 139: "NetBIOS", 445: "SMB",
    1433: "SQL Server", 1521: "Oracle", 2375: "Docker API", 2376: "Docker API",
    2379: "etcd", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API",
    8545: "Ethereum JSON-RPC", 8546: "Ethereum JSON-RPC", 9200: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
}  # fmt: skip


@register
class Ports(ScanModule):
    spec = ModuleSpec(
        name="ports",
        title="Open ports",
        category=Category.VULN,
        mode=ScanMode.ACTIVE,
        description="Services reachable from the internet on your own hosts.",
        requires_binaries=("naabu",),
        depends_on=("dns_resolve",),
        contacts=("each discovered host, connection attempts on common ports",),
        default_timeout_s=1800,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        targets = contactable_hosts(ctx)
        notes = [f"{host} was not scanned: {why}." for host, why in targets.excluded.items()]
        # Addresses are passed, not names, so the tool scans exactly what was vetted.
        addresses = sorted(
            {ip for h in targets.hosts for ip in h.public_ips if ":" not in ip and is_public_ip(ip)}
        )
        truncated = targets.truncated or len(addresses) > MAX_ADDRESSES
        addresses = addresses[:MAX_ADDRESSES]
        if not addresses:
            return self.result(notes=[*notes, "No host qualified for scanning."])

        listing = ctx.workdir / "naabu-targets.txt"
        listing.write_text("\n".join(addresses) + "\n")
        output = await run_tool(
            ctx,
            "naabu",
            [
                "-l", str(listing),
                "-tp", "100",
                "-s", "c",
                "-ec",
                "-Pn",
                "-rate", "100",
                "-c", "10",
                "-retries", "1",
                "-j", "-silent", "-duc",
            ],
            timeout_s=1700,
        )  # fmt: skip

        allowed = set(addresses)
        open_ports: dict[str, set[int]] = {}
        for row in output.json_lines():
            ip, port = row.get("ip"), row.get("port")
            if ip in allowed and isinstance(port, int) and 0 < port < 65536:
                open_ports.setdefault(str(ip), set()).add(port)

        findings: list[Finding] = []
        for ip, ports in sorted(open_ports.items()):
            hosts = targets.owner_of(ip)
            label = hosts[0] if hosts else ip
            for port in sorted(ports - EXPECTED):
                service = RISKY.get(port)
                findings.append(
                    self.finding(
                        "ports.unexpected_open",
                        AssetType.IP,
                        ip,
                        f"Port {port}{f' ({service})' if service else ''} is open on {label}",
                        identity={"port": str(port)},
                        evidence={"address": ip, "port": port, "hosts": hosts[:10]},
                        confidence=Confidence.CONFIRMED,
                        severity_steps=1 if service else 0,
                        severity_note=f"{service} should not normally be reachable from the internet."
                        if service
                        else None,
                    )
                )
        if truncated:
            notes.append(f"Only the first {MAX_ADDRESSES} addresses were scanned.")
        return self.result(
            ModuleStatus.PARTIAL if truncated else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={
                "addresses": len(addresses),
                "open_ports": sum(len(p) for p in open_ports.values()),
            },
        )
