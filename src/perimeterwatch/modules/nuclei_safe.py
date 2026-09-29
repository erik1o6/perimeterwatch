"""Known exposures and misconfigurations. Active: runs only with authorisation.

Only templates admitted by safety/templates.py are run: plain GET and HEAD
requests for things like a readable .git directory or an open admin page.
Nothing here attempts to exploit anything.
"""

from __future__ import annotations

from typing import Any

from perimeterwatch.branding import user_agent
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Severity,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.subprocess import run_tool
from perimeterwatch.safety.targets import contactable_hosts, reported_ip_is_safe
from perimeterwatch.safety.templates import select_templates

SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
# Reported elsewhere, or too noisy to be useful as findings.
IGNORED_TEMPLATES = frozenset({"tech-detect", "http-missing-security-headers", "waf-detect"})
MAX_FINDINGS = 300


def clip(value: Any, length: int = 200) -> str:
    return " ".join(str(value or "").split())[:length]


@register
class NucleiSafe(ScanModule):
    spec = ModuleSpec(
        name="nuclei_safe",
        title="Exposures and misconfigurations",
        category=Category.VULN,
        mode=ScanMode.ACTIVE,
        description="Readable config files, open admin pages and similar, using read-only checks.",
        requires_binaries=("nuclei", "nuclei-templates"),
        depends_on=("http_probe",),
        contacts=("each web server found, read-only requests for known exposures",),
        default_timeout_s=3600,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        probed = ctx.assets.get("http_probe")
        if probed is None or not ctx.assets.completed("http_probe"):
            return self.result(
                ModuleStatus.FAILED, skip_reason="web servers were not identified first"
            )
        allowed = set(contactable_hosts(ctx).names)
        urls = sorted(
            {
                f"{'https' if a.state.get('https') else 'http'}://{a.key}"
                for a in probed.assets
                if a.key in allowed and a.state.get("web")
            }
        )
        if not urls:
            return self.result(notes=["No web server qualified for checking."])

        templates_dir = ctx.tools.resolve("nuclei-templates")
        assert templates_dir is not None
        selection = select_templates(templates_dir)
        if not selection.admitted:
            return self.result(
                ModuleStatus.FAILED, skip_reason="no template passed the safety rules"
            )

        url_list = ctx.workdir / "nuclei-targets.txt"
        url_list.write_text("\n".join(urls) + "\n")
        template_list = ctx.workdir / "nuclei-templates.txt"
        template_list.write_text("\n".join(str(p) for p in selection.admitted) + "\n")

        s = ctx.settings
        output = await run_tool(
            ctx,
            "nuclei",
            [
                "-l", str(url_list),
                "-t", str(template_list),
                "-jsonl", "-silent", "-nc", "-duc",
                "-or", "-ot",  # leave raw requests, responses and templates out of the output
                "-ni",  # no out-of-band callbacks
                "-lna",  # refuse connections to private networks
                "-nh",
                "-rl", "20", "-c", "10", "-bs", "5",
                "-timeout", "8", "-retries", "0", "-mhe", "10",
                "-H", f"User-Agent: {user_agent(s.contact_url, s.abuse_email)}",
            ],
            timeout_s=3500,
        )  # fmt: skip

        admitted_ids = selection.ids
        findings: dict[tuple[str, str, str], Finding] = {}
        for row in output.json_lines():
            template_id = clip(row.get("template-id"), 100)
            host = clip(row.get("host"), 253).lower().split(":")[0]
            if template_id in IGNORED_TEMPLATES or template_id not in admitted_ids:
                continue
            if host not in allowed or not reported_ip_is_safe(row.get("ip")):
                continue
            raw_info = row.get("info")
            info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            severity = SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            matcher = clip(row.get("matcher-name"), 80)
            key = (template_id, host, matcher)
            findings.setdefault(
                key,
                self.finding(
                    "nuclei.finding",
                    AssetType.SUBDOMAIN,
                    host,
                    f"{clip(info.get('name') or template_id, 120)} on {host}",
                    identity={"template": template_id, "matcher": matcher},
                    evidence={
                        "check": template_id,
                        "matched": matcher,
                        "at": clip(row.get("matched-at"), 300),
                        "about": clip(info.get("description"), 400),
                    },
                    confidence=Confidence.LIKELY,
                    severity=severity,
                    remediation=clip(info.get("remediation"), 600) or None,
                ),
            )
        kept = list(findings.values())[:MAX_FINDINGS]
        notes = [
            f"{len(selection.admitted)} read-only checks were run. "
            f"{sum(selection.rejected.values())} others were refused by the safety rules."
        ]
        truncated = output.truncated or len(findings) > MAX_FINDINGS
        return self.result(
            ModuleStatus.PARTIAL if truncated else ModuleStatus.OK,
            findings=kept,
            notes=notes,
            stats={"servers": len(urls), "checks": len(selection.admitted), "matches": len(kept)},
        )
