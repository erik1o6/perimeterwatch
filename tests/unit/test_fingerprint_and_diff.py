from __future__ import annotations

import random
from datetime import UTC, datetime
from uuid import uuid4

from perimeterwatch.core.diff import compute_diff
from perimeterwatch.core.fingerprint import (
    asset_fingerprint,
    asset_state_hash,
    finding_fingerprint,
    finding_state_hash,
)
from perimeterwatch.core.models import (
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

ROOT = "acme-protocol.xyz"
KEY = b"k" * 32
NOW = datetime(2026, 9, 1, tzinfo=UTC)


def finding(kind: str = "tls.cert.expiring", asset: str = "app.acme-protocol.xyz", **kw) -> Finding:
    data = {
        "kind": kind,
        "module": "tls_certs",
        "category": Category.SURFACE,
        "title": "t",
        "severity": Severity.MEDIUM,
        "asset_type": AssetType.SUBDOMAIN,
        "asset_key": asset,
    }
    data.update(kw)
    f = Finding(**data)
    f.fingerprint = finding_fingerprint(ROOT, f, KEY)
    f.state_hash = finding_state_hash(f)
    return f


def asset(key: str, module: str = "subdomains", **state) -> Asset:
    a = Asset(type=AssetType.SUBDOMAIN, key=key, state=state, source_module=module)
    a.fingerprint = asset_fingerprint(ROOT, a)
    a.state_hash = asset_state_hash(a)
    a.facets = {module: a.state_hash}
    return a


def snapshot(*modules: ModuleResult) -> ScanSnapshot:
    return ScanSnapshot(
        scan_id=uuid4(),
        target=Target(root_domain=ROOT),
        mode=ScanMode.PASSIVE,
        authorisation=Authorisation(),
        started_at=NOW,
        finished_at=NOW,
        modules=list(modules),
    )


def module(name: str, status: ModuleStatus = ModuleStatus.OK, **kw) -> ModuleResult:
    return ModuleResult(module=name, status=status, started_at=NOW, finished_at=NOW, **kw)


class TestFingerprint:
    def test_identity_order_does_not_matter(self) -> None:
        pairs = [("host", "a"), ("port", "443"), ("cert", "abc"), ("zone", "z")]
        expected = finding(identity=dict(pairs)).fingerprint
        for _ in range(20):
            random.shuffle(pairs)
            assert finding(identity=dict(pairs)).fingerprint == expected

    def test_volatile_fields_do_not_change_identity(self) -> None:
        base = finding(state={"bucket": "30d"}, evidence={"days_left": 29})
        later = finding(
            state={"bucket": "7d"},
            evidence={"days_left": 6, "checked": "2027-01-01"},
            title="different wording",
            severity=Severity.HIGH,
            remediation="other",
        )
        assert base.fingerprint == later.fingerprint
        assert base.state_hash != later.state_hash

    def test_evidence_alone_is_not_a_change(self) -> None:
        a = finding(state={"bucket": "30d"}, evidence={"days_left": 29})
        b = finding(state={"bucket": "30d"}, evidence={"days_left": 22})
        assert a.state_hash == b.state_hash

    def test_kind_asset_and_domain_all_matter(self) -> None:
        base = finding()
        assert finding(kind="tls.cert.expired").fingerprint != base.fingerprint
        assert finding(asset="api.acme-protocol.xyz").fingerprint != base.fingerprint
        other = finding()
        other.fingerprint = finding_fingerprint("other.xyz", other, KEY)
        assert other.fingerprint != base.fingerprint

    def test_case_of_asset_does_not_matter(self) -> None:
        assert finding(asset="APP.acme-protocol.xyz").fingerprint == finding().fingerprint

    def test_personal_fingerprints_are_keyed(self) -> None:
        person = {
            "kind": "breach.account",
            "asset": "ana@acme-protocol.xyz",
            "sensitivity": Sensitivity.PERSONAL,
            "asset_type": AssetType.EMAIL_ADDRESS,
        }
        a = finding(**person)
        b = finding(**person)
        b.fingerprint = finding_fingerprint(ROOT, b, b"another-key" * 3)
        assert a.fingerprint != b.fingerprint, "a different key must give a different fingerprint"
        assert "ana" not in a.fingerprint


class TestDiff:
    def test_first_scan_is_a_baseline(self) -> None:
        diff = compute_diff(None, snapshot(module("tls_certs", findings=[finding()])))
        assert diff.baseline
        assert len(diff.new) == 1

    def test_identical_scans_show_nothing(self) -> None:
        prev = snapshot(module("tls_certs", findings=[finding()]))
        curr = snapshot(module("tls_certs", findings=[finding()]))
        diff = compute_diff(prev, curr)
        assert not diff.has_changes
        assert diff.unchanged == 1

    def test_new_resolved_changed(self) -> None:
        kept = finding(asset="a.acme-protocol.xyz", state={"bucket": "30d"})
        kept_changed = finding(asset="a.acme-protocol.xyz", state={"bucket": "7d"})
        gone = finding(asset="b.acme-protocol.xyz")
        fresh = finding(asset="c.acme-protocol.xyz")
        diff = compute_diff(
            snapshot(module("tls_certs", findings=[kept, gone])),
            snapshot(module("tls_certs", findings=[kept_changed, fresh])),
        )
        assert [f.asset_key for f in diff.new] == ["c.acme-protocol.xyz"]
        assert [f.asset_key for f in diff.resolved] == ["b.acme-protocol.xyz"]
        assert [c.after.asset_key for c in diff.changed] == ["a.acme-protocol.xyz"]

    def test_a_module_that_did_not_complete_resolves_nothing(self) -> None:
        prev = snapshot(module("tls_certs", findings=[finding()]))
        for status in (ModuleStatus.SKIPPED, ModuleStatus.FAILED, ModuleStatus.PARTIAL):
            diff = compute_diff(prev, snapshot(module("tls_certs", status)))
            assert diff.resolved == [], status
            assert len(diff.stale) == 1, status
            assert not diff.has_changes, status

    def test_a_module_left_out_of_the_scan_resolves_nothing(self) -> None:
        prev = snapshot(module("tls_certs", findings=[finding()]))
        diff = compute_diff(prev, snapshot(module("email_posture")))
        assert diff.resolved == []
        assert len(diff.stale) == 1

    def test_assets_follow_the_same_rule(self) -> None:
        prev = snapshot(module("subdomains", assets=[asset("a.acme-protocol.xyz")]))
        removed = compute_diff(prev, snapshot(module("subdomains")))
        assert [a.key for a in removed.assets_removed] == ["a.acme-protocol.xyz"]
        kept = compute_diff(prev, snapshot(module("subdomains", ModuleStatus.PARTIAL)))
        assert kept.assets_removed == []
        assert [a.key for a in kept.assets_stale] == ["a.acme-protocol.xyz"]

    def test_asset_change_needs_the_reporting_module_to_have_completed(self) -> None:
        name = "a.acme-protocol.xyz"
        prev = snapshot(
            module("subdomains", assets=[asset(name)]),
            module("dns_resolve", assets=[asset(name, "dns_resolve", resolves=True, cname=None)]),
        )
        changed = snapshot(
            module("subdomains", assets=[asset(name)]),
            module(
                "dns_resolve",
                assets=[asset(name, "dns_resolve", resolves=True, cname="x.github.io")],
            ),
        )
        assert len(compute_diff(prev, changed).assets_changed) == 1

        resolver_failed = snapshot(
            module("subdomains", assets=[asset(name)]),
            module("dns_resolve", ModuleStatus.FAILED),
        )
        assert compute_diff(prev, resolver_failed).assets_changed == []

    def test_a_newly_enabled_module_does_not_flag_every_asset(self) -> None:
        name = "a.acme-protocol.xyz"
        prev = snapshot(module("subdomains", assets=[asset(name)]))
        curr = snapshot(
            module("subdomains", assets=[asset(name)]),
            module("dns_resolve", assets=[asset(name, "dns_resolve", resolves=True)]),
        )
        assert compute_diff(prev, curr).assets_changed == []

    def test_results_are_ordered_most_severe_first(self) -> None:
        low = finding(asset="a.acme-protocol.xyz", severity=Severity.LOW)
        high = finding(asset="b.acme-protocol.xyz", severity=Severity.HIGH)
        diff = compute_diff(
            snapshot(module("tls_certs")), snapshot(module("tls_certs", findings=[low, high]))
        )
        assert [f.severity for f in diff.new] == [Severity.HIGH, Severity.LOW]


class TestChangeSeverity:
    """A change to a watched finding is judged by what the change means."""

    def watched(self, owners: list[str]) -> Finding:
        return finding(
            kind="web3.safe.owners",
            asset="eth:0xsafe",
            module="safe_multisig",
            category=Category.WEB3,
            severity=Severity.INFO,
            state={"owners": owners, "threshold": 2},
        )

    def test_a_changed_signer_is_high_although_the_finding_is_info(self) -> None:
        before = snapshot(module("safe_multisig", findings=[self.watched(["a", "b", "c"])]))
        after = snapshot(module("safe_multisig", findings=[self.watched(["a", "b", "x"])]))
        [change] = compute_diff(before, after).changed
        assert change.after.severity is Severity.INFO
        assert change.severity is Severity.HIGH

    def test_an_ordinary_finding_keeps_its_own_severity(self) -> None:
        before = snapshot(module("tls_certs", findings=[finding(state={"bucket": "30d"})]))
        after = snapshot(module("tls_certs", findings=[finding(state={"bucket": "14d"})]))
        [change] = compute_diff(before, after).changed
        assert change.severity is Severity.MEDIUM

    def test_a_change_never_lowers_severity(self) -> None:
        from perimeterwatch.core.severity import change_severity

        assert change_severity("ssh.host_keys", Severity.CRITICAL) is Severity.CRITICAL
        assert change_severity("no.such.kind", Severity.LOW) is Severity.LOW

    def test_changes_are_ordered_by_what_they_mean(self) -> None:
        cert_a = finding(asset="a.acme-protocol.xyz", state={"bucket": "30d"})
        cert_b = finding(asset="a.acme-protocol.xyz", state={"bucket": "14d"})
        before = snapshot(
            module("tls_certs", findings=[cert_a]),
            module("safe_multisig", findings=[self.watched(["a", "b", "c"])]),
        )
        after = snapshot(
            module("tls_certs", findings=[cert_b]),
            module("safe_multisig", findings=[self.watched(["a", "b", "x"])]),
        )
        kinds = [c.after.kind for c in compute_diff(before, after).changed]
        assert kinds == ["web3.safe.owners", "tls.cert.expiring"]

    def test_an_alert_is_sent_for_a_changed_signer(self) -> None:
        from perimeterwatch.worker.alerts import compose

        before = snapshot(module("safe_multisig", findings=[self.watched(["a", "b", "c"])]))
        after = snapshot(module("safe_multisig", findings=[self.watched(["a", "b", "x"])]))
        diff = compute_diff(before, after)
        message = compose(after, diff, min_severity=int(Severity.HIGH), link="https://x.example/s")
        assert message is not None
        assert "1 changed" in message[0] and message[0].startswith("[high]")

    def test_every_watched_kind_is_informational_until_it_changes(self) -> None:
        from perimeterwatch.core.severity import KINDS

        watched = {k: i for k, i in KINDS.items() if i.change_severity is not None}
        assert len(watched) >= 10
        for kind, info in watched.items():
            assert info.change_severity > info.severity, kind
