"""One TLS handshake per host, to read the certificate it serves."""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
    utcnow,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.subprocess import run_tool
from perimeterwatch.safety.targets import contactable_hosts, reported_ip_is_safe

# Days remaining -> bucket. A finding changes only when it crosses a boundary,
# so an expiring certificate does not produce a "changed" event every day.
BUCKETS = ((7, "7d"), (14, "14d"), (30, "30d"))


def expiry_bucket(not_after: datetime, now: datetime) -> str | None:
    days = (not_after - now).total_seconds() / 86400
    if days < 0:
        return "expired"
    for limit, label in BUCKETS:
        if days <= limit:
            return label
    return None


def parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def name_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def fetch_certificate(host: str, ip: str, timeout: float = 8.0) -> dict[str, Any] | None:
    """Fallback when tlsx is not installed. Connects to the vetted address."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((ip, 443), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = [str(n) for n in san.value.get_values_for_type(x509.DNSName)]  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        names = []
    common = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "host": host,
        "ip": ip,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "subject_cn": str(common[0].value) if common else "",
        "subject_an": names,
        "issuer_cn": str(issuer[0].value) if issuer else "",
        "self_signed": cert.issuer == cert.subject,
        "fingerprint_hash": {"sha256": hashlib.sha256(der).hexdigest()},
    }


MAX_CERT_NAMES = 100
_CERT_NAME_RE = re.compile(
    r"^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$"
)


def certificate_names(row: dict[str, Any]) -> list[str]:
    """Hostnames the certificate covers. Anything that is not a plain name is dropped."""
    raw = [*(row.get("subject_an") or []), row.get("subject_cn")]
    names = {str(n).lower().rstrip(".") for n in raw if isinstance(n, str)}
    return sorted(n for n in names if len(n) <= 253 and _CERT_NAME_RE.match(n))[:MAX_CERT_NAMES]


@register
class TlsCerts(ScanModule):
    spec = ModuleSpec(
        name="tls_certs",
        title="TLS certificates",
        category=Category.SURFACE,
        mode=ScanMode.PROBE,
        description="Certificates that are expired, about to expire, or do not match.",
        optional_binaries=("tlsx",),
        depends_on=("dns_resolve",),
        contacts=("each discovered host, one TLS handshake on port 443",),
        default_timeout_s=900,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        targets = contactable_hosts(ctx)
        notes = [f"{host} was not contacted: {why}." for host, why in targets.excluded.items()]
        if not targets.hosts:
            return self.result(notes=[*notes, "No host qualified for contact."])

        if ctx.tools.available("tlsx"):
            rows = await self._tlsx(ctx, targets.names)
        else:
            notes.append("tlsx is not installed, so a simpler built-in check was used.")
            rows = [
                row
                for row in await asyncio.gather(
                    *(
                        asyncio.to_thread(fetch_certificate, h.host, h.public_ips[0])
                        for h in targets.hosts
                    )
                )
                if row
            ]

        now = utcnow()
        allowed = set(targets.names)
        assets: list[Asset] = []
        findings: list[Finding] = []
        for row in rows:
            host = str(row.get("host", "")).lower()
            if host not in allowed or row.get("probe_status") is False:
                continue
            if not reported_ip_is_safe(row.get("ip")):
                notes.append(f"{host} answered from a non-public address and was discarded.")
                continue
            findings.extend(self._assess(host, row, now))
            not_after = parse_time(row.get("not_after"))
            assets.append(
                self.asset(
                    AssetType.SUBDOMAIN if host != target.root_domain else AssetType.DOMAIN,
                    host,
                    attributes={
                        "cert_expires": not_after.date().isoformat() if not_after else "",
                        "cert_issuer": str(row.get("issuer_cn") or "")[:100],
                        "cert_names": certificate_names(row),
                    },
                    state={"tls": True},
                )
            )
        return self.result(
            ModuleStatus.PARTIAL if targets.truncated else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={"contacted": len(targets.hosts), "certificates": len(assets)},
        )

    async def _tlsx(self, ctx: ScanContext, hosts: list[str]) -> list[dict[str, Any]]:
        listing = ctx.workdir / "tlsx-targets.txt"
        listing.write_text("\n".join(hosts) + "\n")
        output = await run_tool(
            ctx,
            "tlsx",
            [
                "-l", str(listing),
                "-p", "443",
                "-j", "-silent", "-duc",
                "-hash", "sha256",
                "-tv",
                "-c", "10",
                "-timeout", "8",
                "-retry", "1",
            ],
            timeout_s=840,
        )  # fmt: skip
        return list(output.json_lines())

    def _assess(self, host: str, row: dict[str, Any], now: datetime) -> list[Finding]:
        findings: list[Finding] = []
        fingerprint = str((row.get("fingerprint_hash") or {}).get("sha256", ""))[:64]
        identity = {"port": "443", "cert_sha256": fingerprint}
        issuer = str(row.get("issuer_cn") or "")[:100]
        names = [str(n) for n in row.get("subject_an") or []]
        if row.get("subject_cn"):
            names.append(str(row["subject_cn"]))

        not_after = parse_time(row.get("not_after"))
        bucket = expiry_bucket(not_after, now) if not_after else None
        if not_after and bucket == "expired":
            findings.append(
                self.finding(
                    "tls.cert.expired", AssetType.SUBDOMAIN, host,
                    f"The certificate for {host} has expired",
                    identity=identity,
                    evidence={"expired_on": not_after.date().isoformat(), "issuer": issuer},
                    confidence=Confidence.CONFIRMED,
                )
            )  # fmt: skip
        elif not_after and bucket:
            findings.append(
                self.finding(
                    "tls.cert.expiring", AssetType.SUBDOMAIN, host,
                    f"The certificate for {host} expires within {bucket[:-1]} days",
                    identity=identity,
                    state={"bucket": bucket},
                    evidence={"expires_on": not_after.date().isoformat(), "issuer": issuer},
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH if bucket == "7d" else None,
                    severity_note="Less than a week remains." if bucket == "7d" else None,
                )
            )  # fmt: skip

        mismatched = row.get("mismatched")
        if mismatched is None:
            mismatched = bool(names) and not name_matches(host, names)
        if mismatched:
            findings.append(
                self.finding(
                    "tls.cert.hostname_mismatch", AssetType.SUBDOMAIN, host,
                    f"The certificate served by {host} is for a different name",
                    identity=identity,
                    evidence={"certificate_names": sorted(set(names))[:10]},
                    confidence=Confidence.CONFIRMED,
                )
            )  # fmt: skip
        if row.get("self_signed"):
            findings.append(
                self.finding(
                    "tls.cert.self_signed", AssetType.SUBDOMAIN, host,
                    f"{host} serves a self-signed certificate",
                    identity=identity,
                    evidence={"issuer": issuer},
                    confidence=Confidence.CONFIRMED,
                )
            )  # fmt: skip
        return findings
