"""Resolve discovered names and check DNS hygiene. DNS queries only."""

from __future__ import annotations

import asyncio
import re
import secrets

import checkdmarc

from perimeterwatch.clients.dns import PUBLIC_RESOLVERS, DnsStatus
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
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.domains import registrable_domain
from perimeterwatch.safety.netguard import is_public_ip

# Labels that suggest a system not meant for the public.
_SENSITIVE = re.compile(
    r"(^|[.-])("
    r"admin|administrator|internal|intranet|corp|staging|stage|stg|uat|qa|dev|develop|test|testing|"
    r"sandbox|preprod|demo|beta|old|legacy|backup|bak|vpn|remote|rdp|ssh|bastion|jump|"
    r"jenkins|gitlab|git|ci|cd|build|deploy|argocd|argo|grafana|kibana|prometheus|sentry|"
    r"vault|consul|k8s|kube|kubernetes|rancher|portainer|phpmyadmin|pma|adminer|db|database|"
    r"mysql|postgres|redis|mongo|elastic|rpc|node|validator|signer|keys?|secrets?"
    r")([.-]|\d|$)"
)


def sensitive_label(host: str, root: str) -> str | None:
    prefix = host[: -len(root)].rstrip(".") if host != root else ""
    match = _SENSITIVE.search(prefix)
    return match.group(2) if match else None


@register
class DnsResolve(ScanModule):
    spec = ModuleSpec(
        name="dns_resolve",
        title="DNS resolution and hygiene",
        category=Category.SURFACE,
        mode=ScanMode.PASSIVE,
        description="Which discovered names resolve, where they point, and DNS safeguards.",
        depends_on=("subdomains",),
        contacts=("public DNS resolvers",),
        default_timeout_s=600,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        root = target.root_domain
        names = ctx.assets.hostnames() or [root]
        if root not in names:
            names.insert(0, root)
        notes: list[str] = []
        if not ctx.assets.completed("subdomains"):
            notes.append("Subdomain discovery did not complete. Only the root domain was checked.")

        wildcard_ips = await self._wildcard(root, ctx)
        resolved = await asyncio.gather(*(self._resolve(n, ctx) for n in names))

        assets: list[Asset] = []
        findings: list[Finding] = []
        errors = 0
        live = 0
        for name, (ips, cname, dns_status) in zip(names, resolved, strict=True):
            if dns_status is DnsStatus.ERROR:
                errors += 1
            matches_wildcard = bool(
                wildcard_ips and ips and not cname and set(ips) <= wildcard_ips and name != root
            )
            resolves = bool(ips)
            live += resolves and not matches_wildcard
            private = [ip for ip in ips if not is_public_ip(ip)]
            assets.append(
                self.asset(
                    AssetType.DOMAIN if name == root else AssetType.SUBDOMAIN,
                    name,
                    attributes={
                        "ips": ips[:8],
                        "dns_status": dns_status.value,
                        "wildcard_match": matches_wildcard,
                        "private_ips": private[:8],
                    },
                    state={"resolves": resolves, "cname": cname},
                )
            )
            if private:
                findings.append(
                    self.finding(
                        "dns.private_ip",
                        AssetType.SUBDOMAIN,
                        name,
                        f"{name} points to a private address",
                        state={"ips": sorted(private)},
                        evidence={"addresses": sorted(private)},
                        confidence=Confidence.CONFIRMED,
                    )
                )
            label = sensitive_label(name, root)
            if label and resolves and not matches_wildcard:
                findings.append(
                    self.finding(
                        "surface.subdomain.sensitive_name",
                        AssetType.SUBDOMAIN,
                        name,
                        f"{name} looks like a non-public system and is reachable by name",
                        identity={"label": label},
                        evidence={"matched": label, "points_to": cname or ips[:3]},
                        confidence=Confidence.CANDIDATE,
                    )
                )

        if wildcard_ips:
            findings.append(
                self.finding(
                    "dns.wildcard",
                    AssetType.DOMAIN,
                    root,
                    f"A wildcard DNS record answers for any name under {root}",
                    evidence={"addresses": sorted(wildcard_ips)[:8]},
                    confidence=Confidence.CONFIRMED,
                )
            )

        findings.extend(await self._root_checks(root, ctx, notes))

        status = ModuleStatus.OK
        if errors > max(3, len(names) // 10) or not ctx.assets.completed("subdomains"):
            status = ModuleStatus.PARTIAL
            if errors:
                notes.append(f"{errors} names could not be looked up because of DNS errors.")
        return self.result(
            status,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={"names": len(names), "resolving": int(live), "dns_errors": errors},
        )

    async def _resolve(
        self, name: str, ctx: ScanContext
    ) -> tuple[list[str], str | None, DnsStatus]:
        cname_answer = await ctx.dns.query(name, "CNAME")
        cname = cname_answer.records[0].lower().rstrip(".") if cname_answer.ok else None
        ips, status = await ctx.dns.addresses(name)
        return ips, cname, status

    async def _wildcard(self, root: str, ctx: ScanContext) -> set[str]:
        """Addresses returned for names that cannot exist, if there is a wildcard."""
        probes = [f"pw-{secrets.token_hex(6)}.{root}" for _ in range(2)]
        answers = await asyncio.gather(*(ctx.dns.addresses(p) for p in probes))
        if all(ips for ips, _ in answers):
            return {ip for ips, _ in answers for ip in ips}
        return set()

    async def _root_checks(self, root: str, ctx: ScanContext, notes: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        apex = registrable_domain(root)

        caa = await ctx.dns.query(apex, "CAA")
        if caa.status in (DnsStatus.NODATA, DnsStatus.NXDOMAIN):
            findings.append(
                self.finding(
                    "dns.caa.missing",
                    AssetType.DOMAIN,
                    apex,
                    f"{apex} has no CAA record",
                    confidence=Confidence.CONFIRMED,
                )
            )
        elif caa.status is DnsStatus.ERROR:
            notes.append("CAA lookup failed.")

        try:
            signed = await asyncio.to_thread(
                checkdmarc.check_dnssec,
                apex,
                nameservers=list(PUBLIC_RESOLVERS),
                timeout=ctx.settings.dns_timeout_s,
            )
        except Exception as exc:
            notes.append(f"DNSSEC check failed ({type(exc).__name__}).")
        else:
            if not signed:
                findings.append(
                    self.finding(
                        "dns.dnssec.disabled",
                        AssetType.DOMAIN,
                        apex,
                        f"{apex} is not signed with DNSSEC",
                        confidence=Confidence.CONFIRMED,
                    )
                )

        ns = await ctx.dns.query(apex, "NS")
        if ns.ok:
            providers = {registrable_or_self(n) for n in ns.records}
            if len(providers) == 1:
                findings.append(
                    self.finding(
                        "dns.nameserver.single_provider",
                        AssetType.DOMAIN,
                        apex,
                        f"All nameservers for {apex} are with one provider",
                        state={"provider": next(iter(providers))},
                        evidence={"nameservers": list(ns.records)},
                        confidence=Confidence.CONFIRMED,
                    )
                )
        return findings


def registrable_or_self(host: str) -> str:
    try:
        return registrable_domain(host.lower().rstrip("."))
    except Exception:
        return host.lower().rstrip(".")
