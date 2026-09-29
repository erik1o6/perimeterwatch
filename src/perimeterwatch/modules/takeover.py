"""DNS records that point at something no longer there.

Works from DNS alone, so results are candidates: the hosted resource appears to
be gone, which is the precondition for someone else claiming it.
"""

from __future__ import annotations

import asyncio
import json
import re
from functools import lru_cache
from importlib import resources

from perimeterwatch.clients.dns import DnsStatus
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
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
from perimeterwatch.safety.domains import registrable_domain


@lru_cache(maxsize=1)
def _services() -> list[tuple[str, tuple[str, ...], tuple[re.Pattern[str], ...]]]:
    raw = resources.files("perimeterwatch.data").joinpath("takeover_services.json").read_text()
    out = []
    for entry in json.loads(raw)["services"]:
        out.append(
            (
                str(entry["service"]),
                tuple(s.lower() for s in entry.get("suffixes", [])),
                tuple(re.compile(p) for p in entry.get("patterns", [])),
            )
        )
    return out


def claimable_service(cname_target: str) -> str | None:
    """Name of the hosted service a CNAME target belongs to, if it is one we know."""
    target = cname_target.lower().rstrip(".")
    for service, suffixes, patterns in _services():
        if any(target.endswith(s) or target == s.lstrip(".") for s in suffixes):
            return service
        if any(p.search(target) for p in patterns):
            return service
    return None


@register
class Takeover(ScanModule):
    spec = ModuleSpec(
        name="takeover",
        title="Dangling DNS records",
        category=Category.TAKEOVER,
        mode=ScanMode.PASSIVE,
        description="Names that point at hosted resources or nameservers that no longer exist.",
        depends_on=("dns_resolve",),
        contacts=("public DNS resolvers",),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        resolved = ctx.assets.get("dns_resolve")
        if resolved is None or not ctx.assets.completed("dns_resolve"):
            return self.result(ModuleStatus.FAILED, skip_reason="DNS resolution did not complete")

        aliases = {a.key: str(a.state["cname"]) for a in resolved.assets if a.state.get("cname")}
        checked = await asyncio.gather(
            *(self._alias(name, cname, ctx) for name, cname in aliases.items())
        )
        findings = [f for f in checked if f is not None]
        findings.extend(await self._nameservers(target.root_domain, ctx))

        incomplete = resolved.status is not ModuleStatus.OK
        return self.result(
            ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
            findings=findings,
            notes=["DNS resolution was incomplete, so some names were not checked."]
            if incomplete
            else [],
            stats={"aliases_checked": len(aliases), "candidates": len(findings)},
        )

    async def _alias(self, name: str, cname: str, ctx: ScanContext) -> Finding | None:
        ips, status = await ctx.dns.addresses(cname)
        if ips or status is not DnsStatus.NXDOMAIN:
            return None
        if ctx.in_scope(cname):
            # An alias to another of the organisation's own names: broken, not claimable.
            return None

        service = claimable_service(cname)
        unregistered = await self._unregistered(cname, ctx)
        evidence = {"alias_for": cname, "target_status": "does not exist"}

        if service:
            return self.finding(
                "takeover.cname.dangling",
                AssetType.SUBDOMAIN,
                name,
                f"{name} points at a {service} resource that no longer exists",
                identity={"cname": cname},
                evidence={**evidence, "service": service},
                confidence=Confidence.CANDIDATE,
            )
        return self.finding(
            "takeover.cname.unresolvable",
            AssetType.SUBDOMAIN,
            name,
            f"{name} is an alias for {cname}, which does not exist",
            identity={"cname": cname},
            state={"target_domain_unregistered": unregistered},
            evidence={**evidence, "target_domain_unregistered": unregistered},
            confidence=Confidence.LIKELY if unregistered else Confidence.CANDIDATE,
            severity_steps=1 if unregistered else 0,
            severity_note="The target's domain appears unregistered, so anyone could register it."
            if unregistered
            else None,
        )

    async def _unregistered(self, host: str, ctx: ScanContext) -> bool:
        try:
            owner = registrable_domain(host)
        except ValidationError:
            return False
        answer = await ctx.dns.query(owner, "NS")
        return answer.status is DnsStatus.NXDOMAIN

    async def _nameservers(self, root: str, ctx: ScanContext) -> list[Finding]:
        apex = registrable_domain(root)
        ns = await ctx.dns.query(apex, "NS")
        if not ns.ok:
            return []
        findings = []
        for server in ns.records:
            server = server.lower().rstrip(".")
            ips, status = await ctx.dns.addresses(server)
            if ips or status is not DnsStatus.NXDOMAIN:
                continue
            unregistered = await self._unregistered(server, ctx)
            findings.append(
                self.finding(
                    "takeover.ns.dangling",
                    AssetType.DOMAIN,
                    apex,
                    f"Nameserver {server} for {apex} does not exist",
                    identity={"nameserver": server},
                    state={"nameserver_domain_unregistered": unregistered},
                    evidence={
                        "nameserver": server,
                        "nameserver_domain_unregistered": unregistered,
                    },
                    confidence=Confidence.LIKELY,
                    severity_steps=1 if unregistered else 0,
                    severity_note="The nameserver's domain appears unregistered."
                    if unregistered
                    else None,
                )
            )
        return findings
