"""Can someone send mail that appears to come from this domain? DNS lookups only,
plus the standard fetch of the domain's own published MTA-STS policy file."""

from __future__ import annotations

import asyncio
import base64
import re
from importlib import resources
from typing import Any

import checkdmarc
import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from perimeterwatch.clients.dns import PUBLIC_RESOLVERS, DnsStatus
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
from perimeterwatch.safety.domains import registrable_domain, validate_slug
from perimeterwatch.safety.netguard import is_public_ip
from perimeterwatch.safety.targets import blocked_by

MAX_POLICY_CHARS = 20_000
_ALL_RE = re.compile(r"(?:^|\s)([+\-~?]?)all\s*$", re.IGNORECASE)
_QUALIFIER = {"": "pass", "+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def default_selectors() -> list[str]:
    text = resources.files("perimeterwatch.data").joinpath("dkim_selectors.txt").read_text()
    return [s.strip() for s in text.splitlines() if s.strip() and not s.startswith("#")]


def spf_all_policy(result: dict[str, Any]) -> str | None:
    """How the record treats senders it does not list: pass, fail, softfail or neutral."""
    parsed = result.get("parsed") or {}
    record = str(result.get("record") or "")
    match = _ALL_RE.search(record)
    if match:
        return _QUALIFIER[match.group(1)]
    redirect = parsed.get("redirect")
    if isinstance(redirect, dict):
        return spf_all_policy(redirect)
    declared = parsed.get("all")
    if isinstance(declared, str) and declared:
        return declared
    return None


def dkim_key_bits(record: str) -> tuple[str, int] | None:
    """Key type and size from a DKIM TXT record, or None if it cannot be read."""
    tags = dict(
        (k.strip().lower(), v.strip())
        for k, _, v in (part.partition("=") for part in record.split(";"))
        if k.strip()
    )
    encoded = re.sub(r"\s+", "", tags.get("p", ""))
    if not encoded:
        return None
    key_type = tags.get("k", "rsa").lower()
    try:
        raw = base64.b64decode(encoded, validate=False)
        if key_type == "ed25519":
            return ("ed25519", 256)
        key = load_der_public_key(raw)
    except Exception:
        return None
    if isinstance(key, rsa.RSAPublicKey):
        return ("rsa", key.key_size)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return ("ed25519", 256)
    return None


@register
class EmailPosture(ScanModule):
    spec = ModuleSpec(
        name="email_posture",
        title="Email spoofing protection",
        category=Category.EMAIL,
        mode=ScanMode.PASSIVE,
        description="SPF, DMARC, DKIM and MTA-STS records. The MTA-STS policy file is on "
        "your web server, so it is read only at probe depth.",
        contacts=("public DNS resolvers",),
        default_timeout_s=180,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        domain = target.root_domain
        kwargs: dict[str, Any] = {
            "nameservers": list(PUBLIC_RESOLVERS),
            "timeout": ctx.settings.dns_timeout_s,
        }
        notes: list[str] = []
        findings: list[Finding] = []
        failures = 0

        mx = await ctx.dns.query(domain, "MX")
        mx_hosts = [r.split()[-1].rstrip(".").lower() for r in mx.records] if mx.ok else []
        receives_mail = bool(mx_hosts) and mx_hosts != [""]
        attributes: dict[str, Any] = {"mx": mx_hosts[:10], "receives_mail": receives_mail}

        checks = {"spf": checkdmarc.check_spf, "dmarc": checkdmarc.check_dmarc}
        results: dict[str, dict[str, Any]] = {}
        for name, check in checks.items():
            # Presence is decided here, not by checkdmarc, which reports a DNS
            # timeout the same way as a record that does not exist.
            present = await self._present(name, domain, ctx)
            if present is None:
                failures += 1
                notes.append(f"{name.upper()} lookup failed, so it was not assessed.")
                continue
            if not present:
                results[name] = {"valid": False, "record": None, "error": "", "absent": True}
                continue
            try:
                results[name] = dict(await asyncio.to_thread(check, domain, **kwargs))
            except Exception as exc:
                failures += 1
                notes.append(f"{name.upper()} check failed ({type(exc).__name__}).")

        sts_present = await self._present("mta_sts", domain, ctx)
        if sts_present is None:
            failures += 1
            notes.append("MTA-STS lookup failed, so it was not assessed.")
        elif not sts_present:
            results["mta_sts"] = {"valid": False, "absent": True}
        elif ctx.mode_ceiling.rank >= ScanMode.PROBE.rank:
            results["mta_sts"] = await self._mta_sts_policy(domain, ctx)
        else:
            # Reading the policy means a request to the organisation's own web
            # server. A passive scan sends nothing there, so it stops at the DNS record.
            results["mta_sts"] = {"valid": True, "policy": None}
            notes.append(
                "An MTA-STS record exists. Its policy file is only read in probe mode, "
                "because that needs a request to your web server."
            )

        if "spf" in results:
            findings.extend(self._spf(domain, results["spf"], attributes))
        if "dmarc" in results:
            findings.extend(self._dmarc(domain, results["dmarc"], attributes))
        if "mta_sts" in results and receives_mail:
            findings.extend(self._mta_sts(domain, results["mta_sts"], attributes))

        if receives_mail and sts_present:
            # Reports are about failures of a published policy, so the record is
            # only asked for where a policy exists.
            rpt_present = await self._present("tls_rpt", domain, ctx)
            if rpt_present is None:
                failures += 1
                notes.append("TLS reporting lookup failed, so it was not assessed.")
            else:
                attributes["tls_rpt"] = "present" if rpt_present else "missing"
                if not rpt_present:
                    findings.append(
                        self.finding(
                            "email.tls_rpt.missing",
                            AssetType.DOMAIN,
                            domain,
                            f"{domain} publishes no TLS reporting record",
                            evidence={"looked_up": f"_smtp._tls.{domain}"},
                            confidence=Confidence.CONFIRMED,
                        )
                    )

        if receives_mail:
            findings.extend(await self._dkim(domain, ctx, attributes))
        else:
            notes.append("The domain has no mail servers, so DKIM and MTA-STS were not assessed.")

        asset = self.asset(AssetType.DOMAIN, domain, attributes=attributes)
        return self.result(
            ModuleStatus.PARTIAL if failures else ModuleStatus.OK,
            assets=[asset],
            findings=findings,
            notes=notes,
            stats={"checks": len(results), "failed_checks": failures},
        )

    async def _present(self, check: str, domain: str, ctx: ScanContext) -> bool | None:
        """Whether the record exists. None means the lookup itself failed."""
        prefix, marker = {
            "spf": ("", "v=spf1"),
            "dmarc": ("_dmarc.", "v=dmarc1"),
            "mta_sts": ("_mta-sts.", "v=stsv1"),
            "tls_rpt": ("_smtp._tls.", "v=tlsrptv1"),
        }[check]
        names = [f"{prefix}{domain}"]
        apex = registrable_domain(domain)
        if check == "dmarc" and apex != domain:
            names.append(f"{prefix}{apex}")  # subdomains inherit the organisation's policy
        failed = False
        for name in names:
            answer = await ctx.dns.query(name, "TXT")
            if answer.status is DnsStatus.ERROR:
                failed = True
            elif any(r.strip().strip('"').lower().startswith(marker) for r in answer.records):
                return True
        return None if failed else False

    async def _mta_sts_policy(self, domain: str, ctx: ScanContext) -> dict[str, Any]:
        """Fetch the policy file ourselves: vetted address, our own User-Agent, no redirects."""
        host = f"mta-sts.{domain}"
        ips, _ = await ctx.dns.addresses(host)
        if not ips or not all(is_public_ip(ip) for ip in ips):
            return {"valid": False, "error": f"{host} does not resolve to a public address"}
        if blocked_by(host, ips, ctx.settings.never_contact):
            return {"valid": True, "policy": None}  # on the do-not-contact list: not read
        await ctx.limiter.acquire(host)
        try:
            response = await ctx.http.get(f"https://{host}/.well-known/mta-sts.txt")
        except httpx.HTTPError as exc:
            return {
                "valid": False,
                "error": f"the policy file could not be fetched ({type(exc).__name__})",
            }
        if response.status_code != 200:
            return {
                "valid": False,
                "error": f"the policy file answered HTTP {response.status_code}",
            }
        fields: dict[str, str] = {}
        for line in response.text[:MAX_POLICY_CHARS].splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields.setdefault(key.strip().lower(), value.strip().lower())
        if fields.get("version") != "stsv1" or fields.get("mode") not in (
            "enforce",
            "testing",
            "none",
        ):
            return {"valid": False, "error": "the policy file is not a valid MTA-STS policy"}
        return {"valid": True, "policy": {"mode": fields["mode"]}}

    def _spf(self, domain: str, result: dict[str, Any], attrs: dict[str, Any]) -> list[Finding]:
        record = result.get("record")
        attrs["spf_record"] = record
        error = str(result.get("error") or "")
        if result.get("absent"):
            attrs["spf"] = "missing"
            return [
                self.finding(
                    "email.spf.missing",
                    AssetType.DOMAIN,
                    domain,
                    f"{domain} has no SPF record",
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if not result.get("valid", False):
            attrs["spf"] = "invalid"
            return [
                self.finding(
                    "email.spf.invalid",
                    AssetType.DOMAIN,
                    domain,
                    f"The SPF record for {domain} is invalid",
                    state={"error": error[:200]},
                    evidence={"record": record, "problem": error[:300]},
                    confidence=Confidence.CONFIRMED,
                )
            ]
        policy = spf_all_policy(result)
        attrs["spf"] = policy or "no 'all' rule"
        attrs["spf_dns_lookups"] = result.get("dns_lookups")
        if policy in ("pass", "neutral") or policy is None:
            return [
                self.finding(
                    "email.spf.permissive",
                    AssetType.DOMAIN,
                    domain,
                    f"The SPF record for {domain} does not reject unlisted senders",
                    state={"policy": policy or "none"},
                    evidence={"record": record},
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if policy == "softfail":
            return [
                self.finding(
                    "email.spf.softfail",
                    AssetType.DOMAIN,
                    domain,
                    f"The SPF record for {domain} only soft-fails unlisted senders",
                    evidence={"record": record},
                    confidence=Confidence.CONFIRMED,
                )
            ]
        return []

    def _dmarc(self, domain: str, result: dict[str, Any], attrs: dict[str, Any]) -> list[Finding]:
        record = result.get("record")
        attrs["dmarc_record"] = record
        error = str(result.get("error") or "")
        if result.get("absent"):
            attrs["dmarc"] = "missing"
            return [
                self.finding(
                    "email.dmarc.missing",
                    AssetType.DOMAIN,
                    domain,
                    f"{domain} has no DMARC record, so spoofed mail is not rejected",
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if not result.get("valid", False):
            attrs["dmarc"] = "invalid"
            return [
                self.finding(
                    "email.dmarc.invalid",
                    AssetType.DOMAIN,
                    domain,
                    f"The DMARC record for {domain} is invalid",
                    state={"error": error[:200]},
                    evidence={"record": record, "problem": error[:300]},
                    confidence=Confidence.CONFIRMED,
                )
            ]

        tags = result.get("tags") or {}

        def tag(name: str) -> Any:
            entry = tags.get(name)
            return entry.get("value") if isinstance(entry, dict) else None

        policy = str(tag("p") or "none").lower()
        subdomain_policy = str(tag("sp") or policy).lower()
        try:
            pct = int(tag("pct")) if tag("pct") is not None else 100
        except (TypeError, ValueError):
            pct = 100
        attrs["dmarc"] = policy
        attrs["dmarc_sp"] = subdomain_policy
        attrs["dmarc_pct"] = pct

        findings: list[Finding] = []
        if policy == "none":
            findings.append(
                self.finding(
                    "email.dmarc.policy_none",
                    AssetType.DOMAIN,
                    domain,
                    f"DMARC for {domain} is set to monitor only",
                    evidence={"record": record},
                    confidence=Confidence.CONFIRMED,
                )
            )
        else:
            rank = {"none": 0, "quarantine": 1, "reject": 2}
            weaker_sp = rank.get(subdomain_policy, 0) < rank.get(policy, 0)
            if pct < 100 or weaker_sp:
                findings.append(
                    self.finding(
                        "email.dmarc.partial_enforcement",
                        AssetType.DOMAIN,
                        domain,
                        f"DMARC for {domain} is only partly enforced",
                        state={"pct": pct, "sp": subdomain_policy, "p": policy},
                        evidence={
                            "record": record,
                            "pct": pct,
                            "subdomain_policy": subdomain_policy,
                        },
                        confidence=Confidence.CONFIRMED,
                    )
                )
        if not tag("rua"):
            findings.append(
                self.finding(
                    "email.dmarc.no_reporting",
                    AssetType.DOMAIN,
                    domain,
                    f"DMARC for {domain} has no reporting address",
                    evidence={"record": record},
                    confidence=Confidence.CONFIRMED,
                )
            )
        return findings

    def _mta_sts(self, domain: str, result: dict[str, Any], attrs: dict[str, Any]) -> list[Finding]:
        error = str(result.get("error") or "")
        if not result.get("valid", False):
            if result.get("absent"):
                attrs["mta_sts"] = "missing"
                return [
                    self.finding(
                        "email.mta_sts.missing",
                        AssetType.DOMAIN,
                        domain,
                        f"{domain} has no MTA-STS policy",
                        confidence=Confidence.CONFIRMED,
                    )
                ]
            attrs["mta_sts"] = "invalid"
            return [
                self.finding(
                    "email.mta_sts.invalid",
                    AssetType.DOMAIN,
                    domain,
                    f"The MTA-STS setup for {domain} could not be validated",
                    state={"error": error[:200]},
                    evidence={"problem": error[:300]},
                )
            ]
        policy = result.get("policy") or {}
        mode = str(policy.get("mode") or "").lower() if isinstance(policy, dict) else ""
        attrs["mta_sts"] = mode or "record present, policy not read"
        if mode and mode != "enforce":
            return [
                self.finding(
                    "email.mta_sts.not_enforced",
                    AssetType.DOMAIN,
                    domain,
                    f"The MTA-STS policy for {domain} is in '{mode}' mode",
                    state={"mode": mode},
                    confidence=Confidence.CONFIRMED,
                )
            ]
        return []

    async def _dkim(self, domain: str, ctx: ScanContext, attrs: dict[str, Any]) -> list[Finding]:
        selectors = list(dict.fromkeys(default_selectors() + self._extra_selectors(ctx)))
        answers = await asyncio.gather(
            *(ctx.dns.query(f"{s}._domainkey.{domain}", "TXT", retries=0) for s in selectors)
        )
        found: dict[str, tuple[str, int] | None] = {}
        for selector, answer in zip(selectors, answers, strict=True):
            for record in answer.records:
                lowered = record.lower()
                # The version and key type tags are optional (RFC 6376, 3.6.1). Some
                # mail services publish the key alone.
                key = dkim_key_bits(record)
                if "p=" in lowered and ("v=dkim1" in lowered or "k=" in lowered or key):
                    found[selector] = key
        attrs["dkim_selectors"] = sorted(found)

        if not found:
            return [
                self.finding(
                    "email.dkim.not_found",
                    AssetType.DOMAIN,
                    domain,
                    f"No DKIM key was found for {domain} under common selector names",
                    evidence={"selectors_tried": len(selectors)},
                    confidence=Confidence.CANDIDATE,
                )
            ]
        findings = []
        for selector, key in sorted(found.items()):
            if key and key[0] == "rsa" and key[1] < 2048:
                findings.append(
                    self.finding(
                        "email.dkim.weak_key",
                        AssetType.DOMAIN,
                        domain,
                        f"DKIM key '{selector}' for {domain} is only {key[1]} bits",
                        identity={"selector": selector},
                        state={"bits": key[1]},
                        evidence={"selector": selector, "key_type": key[0], "bits": key[1]},
                        confidence=Confidence.CONFIRMED,
                        severity_steps=1 if key[1] < 1024 else 0,
                        severity_note="Keys under 1024 bits can be broken cheaply."
                        if key[1] < 1024
                        else None,
                    )
                )
        return findings

    @staticmethod
    def _extra_selectors(ctx: ScanContext) -> list[str]:
        extra = []
        for raw in ctx.settings.dkim_selectors_extra:
            try:
                extra.append(validate_slug(raw, "DKIM selector").lower())
            except Exception:  # noqa: S112 - a bad selector in config is skipped, not fatal
                continue
        return extra
