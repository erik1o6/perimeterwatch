"""Turn a scan and its diff into the structure both report formats render."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from perimeterwatch import __version__
from perimeterwatch.branding import PRODUCT_NAME
from perimeterwatch.core.diff import ScanDiff
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanSnapshot,
    Sensitivity,
    Severity,
)
from perimeterwatch.core.module import all_modules
from perimeterwatch.core.redact import mask_email

SCHEMA_VERSION = "1.0"

SECTION_TITLES: dict[Category, str] = {
    Category.SURFACE: "Attack surface",
    Category.EMAIL: "Email security",
    Category.LOOKALIKE: "Lookalike domains",
    Category.TAKEOVER: "Dangling DNS and takeover candidates",
    Category.SECRETS: "Leaked secrets",
    Category.BREACH: "Breach exposure",
    Category.WEB3: "Web3 and organisation",
    Category.SUPPLY_CHAIN: "Code, packages and frontend",
    Category.VULN: "Exposed services and misconfigurations",
}

SECTION_INTRO: dict[Category, str] = {
    Category.SURFACE: "Hostnames found in public records, and how your DNS is protected.",
    Category.EMAIL: "Whether someone can send mail that appears to come from your domain.",
    Category.LOOKALIKE: (
        "Registered domains that resemble yours. These were found through DNS and "
        "certificate records only. None of them was contacted."
    ),
    Category.TAKEOVER: (
        "DNS records pointing at something that no longer exists. These are candidates "
        "found from DNS alone: confirm each before acting."
    ),
    Category.SECRETS: (
        "Credentials found in public repositories. Values are never stored or shown in "
        "full. Found credentials were not tested."
    ),
    Category.BREACH: (
        "Work email addresses that appear in known data breaches. Only the breach name, "
        "date and kinds of data are shown. No passwords are collected or stored."
    ),
    Category.WEB3: "Multisig and contract control, source code organisation, and hiring disclosures.",
    Category.SUPPLY_CHAIN: (
        "What you ship and how it reaches users: the scripts your site serves, the packages "
        "you publish, and how your repositories are protected."
    ),
    Category.VULN: "Results of active checks, run only with authorisation.",
}


class CheckItem(BaseModel):
    label: str
    status: str  # pass | fail | unknown
    detail: str = ""


class Action(BaseModel):
    title: str
    severity: str
    remediation: str
    count: int = 1


class HostRow(BaseModel):
    name: str
    ips: list[str] = Field(default_factory=list)
    cname: str | None = None
    note: str = ""
    sources: list[str] = Field(default_factory=list)


class Section(BaseModel):
    category: Category
    title: str
    intro: str
    findings: list[Finding] = Field(default_factory=list)
    ran: bool = True
    skipped_reason: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Coverage(BaseModel):
    module: str
    title: str
    mode: str
    status: str
    reason: str | None = None
    hint: str | None = None
    notes: list[str] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    seconds: float = 0.0


class ReportData(BaseModel):
    schema_version: str = SCHEMA_VERSION
    product: str = PRODUCT_NAME
    product_version: str = __version__
    scan: dict[str, Any]
    target: dict[str, Any]
    authorisation: dict[str, Any]
    summary: dict[str, Any]
    checklist: list[CheckItem]
    actions: list[Action]
    diff: ScanDiff
    sections: list[Section]
    hosts: list[HostRow]
    hosts_not_resolving: int = 0
    lookalike_assets: list[Asset] = Field(default_factory=list)
    coverage: list[Coverage]
    methodology: dict[str, Any]
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attributions: list[str] = Field(default_factory=list)
    personal_redacted: bool = False


def _sort_key(finding: Finding) -> tuple[int, str, str]:
    return (-int(finding.severity), finding.kind, finding.asset_key)


def _redact_personal(finding: Finding) -> Finding:
    if finding.sensitivity is not Sensitivity.PERSONAL:
        return finding
    masked = mask_email(finding.asset_key)
    copy = finding.model_copy(deep=True)
    copy.title = copy.title.replace(finding.asset_key, masked)
    copy.asset_key = masked
    copy.evidence = {
        k: (mask_email(v) if isinstance(v, str) and "@" in v else v)
        for k, v in copy.evidence.items()
    }
    return copy


def _module(snapshot: ScanSnapshot, name: str) -> ModuleResult | None:
    return next((m for m in snapshot.modules if m.module == name), None)


def _checklist(snapshot: ScanSnapshot, findings: list[Finding]) -> list[CheckItem]:
    kinds = {f.kind for f in findings}
    status = snapshot.module_status()

    def ran(module: str) -> bool:
        return status.get(module) in (ModuleStatus.OK, ModuleStatus.PARTIAL)

    def item(label: str, module: str, failing: set[str], ok: str, bad: str) -> CheckItem:
        if not ran(module):
            return CheckItem(label=label, status="unknown", detail="Not checked in this scan.")
        hit = kinds & failing
        return CheckItem(label=label, status="fail" if hit else "pass", detail=bad if hit else ok)

    items = [
        item(
            "SPF rejects unlisted senders",
            "email_posture",
            {
                "email.spf.missing",
                "email.spf.invalid",
                "email.spf.permissive",
                "email.spf.softfail",
            },
            "SPF ends in '-all'.",
            "SPF is missing, broken, or does not reject.",
        ),
        item(
            "DMARC is enforced",
            "email_posture",
            {
                "email.dmarc.missing",
                "email.dmarc.invalid",
                "email.dmarc.policy_none",
                "email.dmarc.partial_enforcement",
            },
            "Policy is quarantine or reject for all mail.",
            "Spoofed mail is not reliably refused.",
        ),
        item(
            "DKIM key found",
            "email_posture",
            {"email.dkim.not_found", "email.dkim.weak_key"},
            "A DKIM key of adequate strength is published.",
            "No key found under common names, or a key is weak.",
        ),
        item(
            "MTA-STS enforced",
            "email_posture",
            {"email.mta_sts.missing", "email.mta_sts.invalid", "email.mta_sts.not_enforced"},
            "Inbound mail requires TLS.",
            "Inbound mail can be downgraded to plain text.",
        ),
        item(
            "DNSSEC enabled",
            "dns_resolve",
            {"dns.dnssec.disabled"},
            "The zone is signed.",
            "DNS answers for the domain can be forged.",
        ),
        item(
            "CAA record published",
            "dns_resolve",
            {"dns.caa.missing"},
            "Certificate issuers are restricted.",
            "Any certificate authority may issue.",
        ),
        item(
            "No dangling DNS records",
            "takeover",
            {"takeover.cname.dangling", "takeover.cname.unresolvable", "takeover.ns.dangling"},
            "No candidates found.",
            "Some names point at resources that no longer exist.",
        ),
        item(
            "No mail-capable lookalike domains",
            "lookalikes",
            {"lookalike.mail_capable"},
            "None found.",
            "At least one lookalike domain can receive mail.",
        ),
    ]
    optional = [
        (
            "Certificates valid for 14+ days",
            "tls_certs",
            {"tls.cert.expiring", "tls.cert.expired"},
            "No certificate is close to expiry.",
            "A certificate has expired or is about to.",
        ),
        (
            "No secrets in public repositories",
            "github_secrets",
            {"secrets.exposed"},
            "None found.",
            "Credentials were found in public code.",
        ),
        (
            "Multisig needs 2+ signatures from 3+ owners",
            "safe_multisig",
            {"web3.safe.low_threshold", "web3.safe.few_owners"},
            "Threshold and owner count meet the baseline.",
            "A Safe is below the baseline.",
        ),
        (
            "No staff addresses in malware logs",
            "breaches",
            {"breach.stealer_log"},
            "None found.",
            "A staff device appears to have been infected.",
        ),
    ]
    registry = all_modules()
    for label, module, failing, ok, bad in optional:
        if module in registry or module in status:
            items.append(item(label, module, failing, ok, bad))
    return items


def _actions(findings: list[Finding], limit: int = 5) -> list[Action]:
    grouped: dict[str, Action] = {}
    for finding in sorted(findings, key=_sort_key):
        if finding.severity < Severity.LOW or not finding.remediation:
            continue
        existing = grouped.get(finding.kind)
        if existing:
            existing.count += 1
            continue
        grouped[finding.kind] = Action(
            title=finding.title,
            severity=finding.severity.label,
            remediation=finding.remediation,
        )
    return list(grouped.values())[:limit]


def _hosts(assets: list[Asset]) -> tuple[list[HostRow], int]:
    rows: list[HostRow] = []
    missing = 0
    for asset in assets:
        if asset.type not in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
            continue
        attrs = asset.attributes
        if "dns_status" not in attrs:
            continue  # discovered, but resolution did not run
        if not asset.state.get("resolves"):
            missing += 1
            continue
        if attrs.get("wildcard_match"):
            continue
        notes = []
        if attrs.get("private_ips"):
            notes.append("private address")
        if attrs.get("http_title"):
            notes.append(str(attrs["http_title"])[:80])
        rows.append(
            HostRow(
                name=asset.key,
                ips=[str(i) for i in attrs.get("ips", [])][:4],
                cname=asset.state.get("cname"),
                note=", ".join(notes),
                sources=[str(s) for s in attrs.get("sources", [])],
            )
        )
    rows.sort(key=lambda r: (r.name.count("."), r.name))
    return rows, missing


def build_report(
    snapshot: ScanSnapshot,
    diff: ScanDiff,
    *,
    user_agent: str,
    contact_url: str,
    abuse_email: str | None,
    retention_days: int,
    redact_personal: bool = False,
) -> ReportData:
    findings = sorted(snapshot.findings, key=_sort_key)
    if redact_personal:
        findings = [_redact_personal(f) for f in findings]
        diff = diff.model_copy(deep=True)
        diff.new = [_redact_personal(f) for f in diff.new]
        diff.resolved = [_redact_personal(f) for f in diff.resolved]
        diff.stale = [_redact_personal(f) for f in diff.stale]
        for change in diff.changed:
            change.before = _redact_personal(change.before)
            change.after = _redact_personal(change.after)

    assets = sorted(snapshot.assets, key=lambda a: (a.type.value, a.key))
    registry = all_modules()
    status = snapshot.module_status()

    by_severity = {s.label: 0 for s in reversed(Severity)}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.label] += 1
        by_category[finding.category.value] = by_category.get(finding.category.value, 0) + 1

    sections: list[Section] = []
    for category, title in SECTION_TITLES.items():
        members = [name for name, cls in registry.items() if cls.spec.category is category]
        members += [m.module for m in snapshot.modules if m.module not in registry]
        ran = [m for m in members if status.get(m) in (ModuleStatus.OK, ModuleStatus.PARTIAL)]
        section_findings = [f for f in findings if f.category is category]
        if not members and not section_findings:
            continue
        reason = None
        if not ran and not section_findings:
            reasons = [
                m.skip_reason for m in snapshot.modules if m.module in members and m.skip_reason
            ]
            reason = reasons[0] if reasons else "not part of this scan"
        sections.append(
            Section(
                category=category,
                title=title,
                intro=SECTION_INTRO[category],
                findings=section_findings,
                ran=bool(ran) or bool(section_findings),
                skipped_reason=reason,
            )
        )

    email_asset = next(
        (a for a in assets if a.type is AssetType.DOMAIN and "spf" in a.attributes), None
    )
    for section in sections:
        if section.category is Category.EMAIL and email_asset is not None:
            section.extra = {
                k: email_asset.attributes.get(k)
                for k in ("mx", "spf_record", "dmarc_record", "dkim_selectors", "mta_sts")
            }

    hosts, not_resolving = _hosts(assets)

    coverage = []
    for module in snapshot.modules:
        spec = registry[module.module].spec if module.module in registry else None
        coverage.append(
            Coverage(
                module=module.module,
                title=spec.title if spec else module.module,
                mode=spec.mode.value if spec else "",
                status=module.status.value,
                reason=module.skip_reason,
                hint=module.hint,
                notes=module.notes,
                stats=module.stats,
                seconds=round((module.finished_at - module.started_at).total_seconds(), 1),
            )
        )

    contacted = sorted(
        {
            c
            for m in snapshot.modules
            if m.status in (ModuleStatus.OK, ModuleStatus.PARTIAL) and m.module in registry
            for c in registry[m.module].spec.contacts
        }
    )

    return ReportData(
        scan={
            "id": str(snapshot.scan_id),
            "started_at": snapshot.started_at.isoformat(),
            "finished_at": snapshot.finished_at.isoformat() if snapshot.finished_at else None,
            "mode": snapshot.mode.value,
            "tool_versions": snapshot.tool_versions,
        },
        target=snapshot.target.model_dump(mode="json", exclude={"staff_emails"}),
        authorisation=snapshot.authorisation.model_dump(mode="json"),
        summary={
            "total": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "hosts_resolving": len(hosts),
            "names_discovered": sum(
                1 for a in assets if a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
            ),
        },
        checklist=_checklist(snapshot, findings),
        actions=_actions(findings),
        diff=diff,
        sections=sections,
        hosts=hosts,
        hosts_not_resolving=not_resolving,
        lookalike_assets=[a for a in assets if a.type is AssetType.LOOKALIKE_DOMAIN],
        coverage=coverage,
        methodology={
            "contacted": contacted,
            "user_agent": user_agent,
            "contact_url": contact_url,
            "abuse_email": abuse_email,
            "retention_days": retention_days,
            "mode_meaning": {
                "passive": "Public records and third-party indexes only. No connection was made to your hosts.",
                "probe": "As passive, plus one ordinary web request and TLS handshake per host.",
                "active": "As probe, plus port and misconfiguration checks on your own hosts.",
            }[snapshot.mode.value],
        },
        assets=assets,
        findings=findings,
        attributions=sorted({f.attribution for f in findings if f.attribution}),
        personal_redacted=redact_personal,
    )
