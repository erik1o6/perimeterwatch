"""Which TLS versions and cipher suites a server accepts. Active: needs authorisation.

Finding this out takes many handshakes per host, one for each version and
suite tried, so it is an active check. The handshakes are ordinary ones. None
carries a malformed or attack-shaped message.
"""

from __future__ import annotations

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
from perimeterwatch.safety.subprocess import run_tool
from perimeterwatch.safety.targets import contactable_hosts, reported_ip_is_safe

LEGACY = {"ssl30": "SSL 3.0", "tls10": "TLS 1.0", "tls11": "TLS 1.1"}
KNOWN_VERSIONS = {*LEGACY, "tls12", "tls13"}
MAX_HOSTS = 50
MAX_CIPHERS = 40


def clean_suites(raw: Any) -> list[str]:
    """Cipher suite names from tool output, keeping only well-formed ones."""
    if not isinstance(raw, list):
        return []
    names = {
        s for s in raw if isinstance(s, str) and 0 < len(s) <= 80 and s.replace("_", "").isalnum()
    }
    return sorted(names)[:MAX_CIPHERS]


@register
class TlsConfig(ScanModule):
    spec = ModuleSpec(
        name="tls_config",
        title="TLS versions and cipher suites",
        category=Category.VULN,
        mode=ScanMode.ACTIVE,
        description="Old TLS versions and weak cipher suites that your servers still accept.",
        requires_binaries=("tlsx",),
        depends_on=("dns_resolve",),
        contacts=("each discovered host, repeated TLS handshakes on port 443",),
        default_timeout_s=1800,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        targets = contactable_hosts(ctx, limit=MAX_HOSTS)
        notes = [f"{host} was not checked: {why}." for host, why in targets.excluded.items()]
        if targets.truncated:
            notes.append(f"Only the first {MAX_HOSTS} hosts were checked.")
        if not targets.hosts:
            return self.result(notes=[*notes, "No host qualified for checking."])

        listing = ctx.workdir / "tlsx-enum-targets.txt"
        listing.write_text("\n".join(targets.names) + "\n")
        output = await run_tool(
            ctx,
            "tlsx",
            [
                "-l", str(listing),
                "-p", "443",
                "-j", "-silent", "-duc",
                "-ve",
                "-ce", "-ct", "weak,insecure",
                "-c", "2",
                "-cec", "4",
                "-timeout", "8",
                "-retry", "1",
            ],
            timeout_s=1700,
        )  # fmt: skip

        allowed = set(targets.names)
        findings: list[Finding] = []
        checked = 0
        for row in output.json_lines():
            host = str(row.get("host", "")).lower()
            if host not in allowed or row.get("probe_status") is False:
                continue
            if not reported_ip_is_safe(row.get("ip")):
                notes.append(f"{host} answered from a non-public address and was discarded.")
                continue
            checked += 1
            findings.extend(self._assess(host, row))
        return self.result(
            ModuleStatus.PARTIAL if targets.truncated else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={"hosts_checked": checked, "findings": len(findings)},
        )

    def _assess(self, host: str, row: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        versions = row.get("version_enum")
        accepted = (
            sorted({v for v in versions if isinstance(v, str) and v in KNOWN_VERSIONS})
            if isinstance(versions, list)
            else []
        )
        legacy = [LEGACY[v] for v in accepted if v in LEGACY]
        if legacy:
            findings.append(
                self.finding(
                    "tls.protocol.legacy", AssetType.SUBDOMAIN, host,
                    f"{host} still accepts {', '.join(legacy)}",
                    identity={"port": "443"},
                    state={"versions": legacy},
                    evidence={"accepted_versions": accepted},
                    confidence=Confidence.CONFIRMED,
                    severity_steps=1 if "SSL 3.0" in legacy else 0,
                    severity_note="SSL 3.0 is broken outright." if "SSL 3.0" in legacy else None,
                )
            )  # fmt: skip

        insecure: set[str] = set()
        weak: set[str] = set()
        groups = row.get("cipher_enum")
        for group in groups if isinstance(groups, list) else []:
            ciphers = group.get("ciphers") if isinstance(group, dict) else None
            if not isinstance(ciphers, dict):
                continue
            insecure.update(clean_suites(ciphers.get("insecure")))
            weak.update(clean_suites(ciphers.get("weak")))
        for kind, suites, word in (
            ("tls.cipher.insecure", insecure, "insecure"),
            ("tls.cipher.weak", weak - insecure, "weak"),
        ):
            if suites:
                listed = sorted(suites)[:MAX_CIPHERS]
                findings.append(
                    self.finding(
                        kind, AssetType.SUBDOMAIN, host,
                        f"{host} accepts {len(listed)} {word} cipher suite(s)",
                        identity={"port": "443"},
                        state={"suites": listed},
                        evidence={"cipher_suites": listed},
                        confidence=Confidence.CONFIRMED,
                    )
                )  # fmt: skip
        return findings
