"""Everything a scan finds is attacker-influenced text. The report must treat it so."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from uuid import uuid4

from parapet.core.diff import compute_diff
from parapet.core.fingerprint import finding_fingerprint, finding_state_hash
from parapet.core.models import (
    Asset,
    AssetType,
    Authorisation,
    Category,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    ScanSnapshot,
    Sensitivity,
    Severity,
    Target,
)
from parapet.report.build import ReportData, build_report
from parapet.report.render_html import render_html
from parapet.report.render_json import render_json, render_jsonl, schema
from tests.conftest import ROOT

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
XSS = "<script>alert(document.domain)</script>"
ATTR_BREAK = '"><img src=x onerror=alert(1)>'
HOSTILE_VALUES = [
    XSS,
    ATTR_BREAK,
    "{{ 7*7 }}",
    "{% include '/etc/passwd' %}",
    "javascript:alert(1)",
]


def finding(kind: str, category: Category, title: str, asset: str = ROOT, **kw) -> Finding:
    f = Finding(
        kind=kind,
        module=kw.pop("module", "email_posture"),
        category=category,
        title=title,
        severity=kw.pop("severity", Severity.MEDIUM),
        asset_type=kw.pop("asset_type", AssetType.DOMAIN),
        asset_key=asset,
        remediation=kw.pop("remediation", "Fix it."),
        **kw,
    )
    f.fingerprint = finding_fingerprint(ROOT, f, b"k" * 32)
    f.state_hash = finding_state_hash(f)
    return f


def snapshot(findings: list[Finding], assets: list[Asset] | None = None, **kw) -> ScanSnapshot:
    modules = [
        ModuleResult(
            module="email_posture",
            status=ModuleStatus.OK,
            findings=findings,
            assets=assets or [],
            started_at=NOW,
            finished_at=NOW,
            notes=kw.pop("notes", []),
        ),
        ModuleResult(
            module="subdomains",
            status=ModuleStatus.SKIPPED,
            started_at=NOW,
            finished_at=NOW,
            skip_reason="missing key: GITHUB_TOKEN",
            hint="set GITHUB_TOKEN in the environment",
        ),
    ]
    return ScanSnapshot(
        scan_id=uuid4(),
        target=Target(root_domain=ROOT),
        mode=ScanMode.PASSIVE,
        authorisation=Authorisation(),
        started_at=NOW,
        finished_at=NOW,
        modules=modules,
        **kw,
    )


def report(snap: ScanSnapshot, prev: ScanSnapshot | None = None, **kw) -> ReportData:
    return build_report(
        snap,
        compute_diff(prev, snap),
        user_agent="parapet/test",
        contact_url="https://scanner.example.org",
        abuse_email="abuse@example.org",
        retention_days=90,
        **kw,
    )


def hostile_snapshot() -> ScanSnapshot:
    findings = [
        finding(
            "email.dmarc.missing",
            Category.EMAIL,
            f"title {value}",
            asset=f"asset-{i}.{ROOT}",
            evidence={"record": value, value: "key position", "nested": [value, {"k": value}]},
            remediation=f"remediation {value}",
            severity_note=f"note {value}",
            attribution=f"attribution {value}",
            references=[value],
        )
        for i, value in enumerate(HOSTILE_VALUES)
    ]
    assets = [
        Asset(
            type=AssetType.LOOKALIKE_DOMAIN,
            key=f"lookalike{i}.xyz",
            source_module="email_posture",
            attributes={"display": value, "technique": value},
            state={"mail_capable": True, "has_address": True},
            fingerprint=f"fp{i}",
        )
        for i, value in enumerate(HOSTILE_VALUES)
    ]
    return snapshot(findings, assets, notes=list(HOSTILE_VALUES))


class TestHtmlSafety:
    def test_hostile_text_is_escaped_everywhere(self) -> None:
        html = render_html(report(hostile_snapshot()))
        assert "<script" not in html.lower()
        assert "<img" not in html.lower()
        assert "onerror=alert(1)>" not in html
        assert "&lt;script&gt;alert(document.domain)&lt;/script&gt;" in html
        # Template syntax in data is shown as text, never evaluated.
        assert "title {{ 7*7 }}" in html
        assert "title 49" not in html
        assert "{% include" in html

    def test_no_links_are_made_from_finding_data(self) -> None:
        html = render_html(report(hostile_snapshot()))
        hrefs = re.findall(r'href="([^"]*)"', html)
        assert hrefs and all(h.startswith("#") for h in hrefs), hrefs
        assert "javascript:" not in " ".join(hrefs)

    def test_report_is_self_contained(self) -> None:
        html = render_html(report(hostile_snapshot()))
        assert "Content-Security-Policy" in html and "default-src 'none'" in html
        assert not re.findall(r'(?:src|href)="(?:https?:)?//', html)
        assert "@import" not in html and "url(" not in html
        assert "<link" not in html.lower() and "<iframe" not in html.lower()

    def test_no_score_or_grade_is_given(self) -> None:
        html = render_html(report(snapshot([finding("email.dmarc.missing", Category.EMAIL, "t")])))
        text = re.sub(r"<[^>]+>", " ", re.sub(r"<style>.*?</style>", "", html, flags=re.S)).lower()
        assert "gives no overall score" in " ".join(text.split())
        for word in ("grade:", "rating:", "score:", "/100", "out of 100"):
            assert word not in text


class TestContent:
    def test_sections_and_coverage(self) -> None:
        data = report(snapshot([finding("email.dmarc.missing", Category.EMAIL, "No DMARC")]))
        html = render_html(data)
        assert "No DMARC" in html
        assert "first scan of this domain" in html
        # Skip reasons keep their capitals: GITHUB_TOKEN must not be lower-cased.
        assert "Missing key: GITHUB_TOKEN." in html
        assert "set GITHUB_TOKEN in the environment" in html
        assert [c.status for c in data.coverage] == ["ok", "skipped"]

    def test_checklist_is_unknown_when_a_check_did_not_run(self) -> None:
        data = report(snapshot([]))
        by_label = {c.label: c.status for c in data.checklist}
        assert by_label["DMARC is enforced"] == "pass"
        assert by_label["DNSSEC enabled"] == "unknown", "dns_resolve did not run"
        assert by_label["No dangling DNS records"] == "unknown"

    def test_actions_are_grouped_and_ordered(self) -> None:
        findings = [
            finding(
                "lookalike.registered",
                Category.LOOKALIKE,
                f"variation {i}",
                asset=f"v{i}.xyz",
                severity=Severity.LOW,
            )
            for i in range(4)
        ] + [
            finding("email.dmarc.missing", Category.EMAIL, "No DMARC", severity=Severity.HIGH),
            finding(
                "dns.nameserver.single_provider", Category.SURFACE, "fyi", severity=Severity.INFO
            ),
        ]
        actions = report(snapshot(findings)).actions
        assert [a.severity for a in actions] == ["high", "low"]
        assert actions[1].count == 4

    def test_changes_section(self) -> None:
        old = snapshot([finding("email.dmarc.missing", Category.EMAIL, "No DMARC")])
        new = snapshot([finding("email.spf.missing", Category.EMAIL, "No SPF")])
        html = render_html(report(new, old))
        assert "1 new, 1 resolved, 0 changed" in " ".join(html.split())

    def test_personal_details_can_be_masked(self) -> None:
        address = f"ana.lopez@{ROOT}"
        person = finding(
            "breach.account",
            Category.BREACH,
            f"{address} appears in a breach",
            asset=address,
            asset_type=AssetType.EMAIL_ADDRESS,
            sensitivity=Sensitivity.PERSONAL,
            evidence={"address": address, "breach": "ExampleCo 2024"},
            module="email_posture",
        )
        full = report(snapshot([person]))
        assert address in render_html(full) and address in render_json(full)
        masked = report(snapshot([person]), redact_personal=True)
        for output in (render_html(masked), render_json(masked), render_jsonl(masked)):
            assert address not in output
            assert "ana.lopez" not in output
            assert f"a***@{ROOT}" in output
        assert "Personal details have been masked" in render_html(masked)


class TestJson:
    def test_json_is_valid_and_versioned(self) -> None:
        data = json.loads(render_json(report(hostile_snapshot())))
        assert data["schema_version"] == "1.0"
        assert data["target"]["root_domain"] == ROOT
        assert "staff_emails" not in data["target"]
        assert len(data["findings"]) == len(HOSTILE_VALUES)
        assert data["findings"][0]["evidence"]["record"] in HOSTILE_VALUES
        assert {c["module"] for c in data["coverage"]} == {"email_posture", "subdomains"}

    def test_jsonl_has_one_finding_per_line(self) -> None:
        lines = render_jsonl(report(hostile_snapshot())).splitlines()
        assert len(lines) == len(HOSTILE_VALUES)
        assert all(json.loads(line)["kind"] == "email.dmarc.missing" for line in lines)
        assert render_jsonl(report(snapshot([]))) == ""

    def test_schema_is_published(self) -> None:
        assert json.loads(schema())["title"] == "ReportData"
