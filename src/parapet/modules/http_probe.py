"""One ordinary web request per host, the same as a browser visiting it."""

from __future__ import annotations

from typing import Any

from parapet.branding import user_agent
from parapet.core.context import ScanContext
from parapet.core.models import (
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
from parapet.core.module import ModuleSpec, ScanModule, register
from parapet.safety.subprocess import run_tool
from parapet.safety.targets import contactable_hosts, reported_ip_is_safe


def clip(value: Any, length: int = 120) -> str:
    text = " ".join(str(value or "").split())
    return text[:length]


@register
class HttpProbe(ScanModule):
    spec = ModuleSpec(
        name="http_probe",
        title="Web servers",
        category=Category.SURFACE,
        mode=ScanMode.PROBE,
        description="Which hosts answer on the web, and what software they reveal.",
        requires_binaries=("httpx",),
        depends_on=("dns_resolve",),
        contacts=("each discovered host, one web request",),
        default_timeout_s=900,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        targets = contactable_hosts(ctx)
        notes = [f"{host} was not contacted: {why}." for host, why in targets.excluded.items()]
        if targets.truncated:
            notes.append(f"Only the first {len(targets.hosts)} hosts were contacted.")
        if not targets.hosts:
            return self.result(notes=[*notes, "No host qualified for contact."])

        listing = ctx.workdir / "httpx-targets.txt"
        listing.write_text("\n".join(targets.names) + "\n")
        s = ctx.settings
        output = await run_tool(
            ctx,
            "httpx",
            [
                "-l", str(listing),
                "-j", "-silent", "-duc", "-no-stdin",
                "-sc", "-title", "-server", "-td", "-ip", "-cname", "-cdn", "-location",
                "-random-agent=false",
                "-H", f"User-Agent: {user_agent(s.contact_url, s.abuse_email)}",
                "-maxr", "0",
                "-t", "10",
                "-rl", str(max(1, int(s.per_host_rps * 5))),
                "-timeout", "10",
                "-retries", "0",
            ],
            timeout_s=840,
        )  # fmt: skip

        allowed = set(targets.names)
        assets: list[Asset] = []
        findings: list[Finding] = []
        for row in output.json_lines():
            host = str(row.get("input", "")).lower().split(":")[0]
            if host not in allowed or row.get("failed"):
                continue
            if not reported_ip_is_safe(row.get("host_ip") or row.get("host")):
                notes.append(f"{host} answered from a non-public address and was discarded.")
                continue
            scheme = str(row.get("scheme", ""))
            tech = sorted({clip(t, 60) for t in row.get("tech") or []})[:30]
            assets.append(
                self.asset(
                    AssetType.SUBDOMAIN if host != target.root_domain else AssetType.DOMAIN,
                    host,
                    attributes={
                        "url": clip(row.get("url"), 200),
                        "http_status": row.get("status_code"),
                        "http_title": clip(row.get("title")),
                        "web_server": clip(row.get("webserver"), 80),
                        "tech": tech,
                        "cdn": clip(row.get("cdn_name"), 40) if row.get("cdn") else "",
                        "redirects_to": clip(row.get("location"), 200),
                    },
                    state={"web": True, "https": scheme == "https"},
                )
            )
            if scheme == "http":
                findings.append(
                    self.finding(
                        "http.no_https_redirect",
                        AssetType.SUBDOMAIN,
                        host,
                        f"{host} is served over plain HTTP only",
                        evidence={"url": clip(row.get("url"), 200)},
                        confidence=Confidence.CONFIRMED,
                    )
                )
        return self.result(
            ModuleStatus.PARTIAL if targets.truncated else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={"contacted": len(targets.hosts), "answered": len(assets)},
        )
