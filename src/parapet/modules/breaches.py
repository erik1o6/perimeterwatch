"""Staff addresses in known breaches and malware logs.

Who sees what:
- Before the domain is verified: counts only, and only from a source that
  gives nothing but counts.
- After verification: which addresses, which breach, when, and what kinds of
  data. Never a password or any other breached value.
"""

from __future__ import annotations

from parapet.breach.base import BreachProvider, ProviderError, ProviderResult
from parapet.breach.hibp import Hibp
from parapet.breach.hudsonrock import HudsonRock
from parapet.core.context import ScanContext
from parapet.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Sensitivity,
    Target,
)
from parapet.core.module import ModuleSpec, ScanModule, register, skipped

PROVIDERS: dict[str, type[BreachProvider]] = {"hibp": Hibp, "hudsonrock": HudsonRock}

# Breaches that held these are more urgent: the data helps an attacker log in.
CREDENTIAL_CLASSES = {
    "passwords",
    "password hints",
    "security questions and answers",
    "auth tokens",
}
# Logins for these matter most to a crypto team.
HIGH_VALUE_SITES = (
    "github.com", "gitlab.com", "npmjs.com", "accounts.google.com", "login.microsoftonline.com",
    "okta.com", "aws.amazon.com", "cloudflare.com", "vercel.com", "namecheap.com", "godaddy.com",
    "safe.global", "fireblocks.io", "1password.com", "slack.com", "discord.com", "x.com",
    "twitter.com", "telegram.org",
)  # fmt: skip


def is_high_value(site: str) -> bool:
    return any(site == s or site.endswith("." + s) for s in HIGH_VALUE_SITES)


@register
class Breaches(ScanModule):
    spec = ModuleSpec(
        name="breaches",
        title="Breach exposure",
        category=Category.BREACH,
        mode=ScanMode.PASSIVE,
        description="Work email addresses found in known breaches and malware logs. "
        "Details about people are shown only for a verified domain.",
        optional_keys=("HIBP_API_KEY",),
        contacts=("Have I Been Pwned", "Hudson Rock (only if switched on)"),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        domain = target.root_domain
        notes: list[str] = []
        findings: list[Finding] = []
        ran = failed = 0
        reasons: list[str] = []

        wanted = [*ctx.settings.breach_providers]
        if ctx.settings.hudsonrock_enabled and "hudsonrock" not in wanted:
            wanted.append("hudsonrock")

        for name in wanted:
            provider_cls = PROVIDERS.get(name)
            if provider_cls is None:
                notes.append(f"Unknown breach source '{name}' in settings was ignored.")
                continue
            provider = provider_cls()
            if provider.per_person and not ctx.verified:
                reasons.append("requires a verified domain")
                continue
            problem = provider.configured(ctx)
            if problem:
                reasons.append(problem)
                continue
            try:
                result = await provider.lookup(domain, ctx)
            except ProviderError as exc:
                failed += 1
                notes.append(str(exc))
                continue
            ran += 1
            notes.extend(result.notes)
            findings.extend(self._findings(target, result, ctx))

        if not ran and not failed:
            reason = reasons[0] if reasons else "no breach source is configured"
            hint = (
                f"parapet verify init {domain}"
                if "verified" in reason
                else "set HIBP_API_KEY in the environment or .env"
            )
            return skipped(self.spec, reason, hint)
        if not ran:
            return self.result(ModuleStatus.FAILED, skip_reason=notes[0], notes=notes)

        people = {f.asset_key for f in findings if f.sensitivity is Sensitivity.PERSONAL}
        return self.result(
            ModuleStatus.PARTIAL if failed else ModuleStatus.OK,
            findings=findings,
            notes=[*notes, "No passwords are collected or stored."],
            stats={"addresses_affected": len(people), "findings": len(findings)},
        )

    def _findings(self, target: Target, result: ProviderResult, ctx: ScanContext) -> list[Finding]:
        domain = target.root_domain
        findings: list[Finding] = []
        # The list the organisation supplied tells current staff apart from
        # former staff and shared mailboxes. Without one, nothing is claimed.
        staff = {e.lower() for e in target.staff_emails}

        def on_list(email: str) -> dict[str, str]:
            if not staff:
                return {}
            return {"on_your_staff_list": "yes" if email.lower() in staff else "no"}

        # Second check, next to the one in run(): no per-person result leaves
        # this module unless the domain is verified.
        if ctx.verified:
            for record in result.breaches:
                credentials = bool(CREDENTIAL_CLASSES & {c.lower() for c in record.data_classes})
                findings.append(
                    self.finding(
                        "breach.account",
                        AssetType.EMAIL_ADDRESS,
                        record.email,
                        f"{record.email} appears in the {record.breach} breach",
                        identity={"breach": record.breach, "source": record.source},
                        evidence={
                            "breach": record.breach,
                            "breach_date": record.breach_date,
                            "kinds_of_data": list(record.data_classes),
                            **on_list(record.email),
                        },
                        confidence=Confidence.CONFIRMED,
                        sensitivity=Sensitivity.PERSONAL,
                        severity_steps=0 if credentials else -1,
                        severity_note=None
                        if credentials
                        else "This breach did not include passwords.",
                        attribution=result.attribution,
                    )
                )
            for log in result.stealer_logs:
                # Which sites someone had logins for can reveal their health, beliefs
                # or private life. Only two kinds are kept by name: the organisation's
                # own, and services that control code, infrastructure or funds.
                # Everything else is reduced to a count.
                own = sorted(s for s in log.sites if ctx.in_scope(s))
                valuable = sorted(s for s in log.sites if is_high_value(s))
                kept = sorted(set(own) | set(valuable))
                other = len(set(log.sites)) - len(kept)
                findings.append(
                    self.finding(
                        "breach.stealer_log",
                        AssetType.EMAIL_ADDRESS,
                        log.email,
                        f"Logins for {log.email} were captured by malware",
                        identity={"source": log.source},
                        state={"sites": kept},
                        evidence={
                            "your_own_systems": own,
                            "high_value_services": valuable,
                            "other_sites": f"{other} (not recorded)",
                            **on_list(log.email),
                        },
                        confidence=Confidence.CONFIRMED,
                        sensitivity=Sensitivity.PERSONAL,
                        severity_steps=1 if valuable else 0,
                        severity_note="Includes logins for services that control code, "
                        "infrastructure or funds."
                        if valuable
                        else None,
                        attribution=result.attribution,
                    )
                )
        if result.summary is not None:
            s = result.summary
            findings.append(
                self.finding(
                    "breach.domain_summary",
                    AssetType.DOMAIN,
                    domain,
                    f"Malware logs hold logins from {s.employees} staff device(s) at {domain}",
                    identity={"source": s.source},
                    state={"staff_bucket": _bucket(s.employees)},
                    evidence={
                        "staff_devices": s.employees,
                        "customer_devices": s.users,
                        "note": "Counts only. No addresses are given by this source.",
                    },
                    confidence=Confidence.LIKELY,
                    severity_steps=1 if s.employees else 0,
                    severity_note="At least one staff device appears to have been infected."
                    if s.employees
                    else None,
                    attribution=result.attribution,
                )
            )
        return findings


def _bucket(count: int) -> str:
    for limit, label in ((0, "0"), (5, "1-5"), (25, "6-25"), (100, "26-100")):
        if count <= limit:
            return label
    return "100+"
