"""Compare two scans of the same target.

The rule that matters: an item only counts as resolved or removed when the
module that produced it ran to completion this time. If that module was
skipped, failed or partial, the item is carried as stale. Otherwise a missing
API key would make every finding look fixed.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from parapet.core.models import Asset, Finding, ModuleStatus, ScanSnapshot


class FindingChange(BaseModel):
    before: Finding
    after: Finding


class AssetChange(BaseModel):
    before: Asset
    after: Asset


class ScanDiff(BaseModel):
    baseline: bool = False
    previous_scan_id: UUID | None = None
    current_scan_id: UUID

    new: list[Finding] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)
    changed: list[FindingChange] = Field(default_factory=list)
    stale: list[Finding] = Field(default_factory=list)
    unchanged: int = 0

    assets_new: list[Asset] = Field(default_factory=list)
    assets_removed: list[Asset] = Field(default_factory=list)
    assets_changed: list[AssetChange] = Field(default_factory=list)
    assets_stale: list[Asset] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new
            or self.resolved
            or self.changed
            or self.assets_new
            or self.assets_removed
            or self.assets_changed
        )


def _by_fingerprint[T: (Finding, Asset)](items: list[T]) -> dict[str, T]:
    out: dict[str, T] = {}
    for item in items:
        out.setdefault(item.fingerprint, item)
    return out


def _severity_key(finding: Finding) -> tuple[int, str, str]:
    return (-int(finding.severity), finding.kind, finding.asset_key)


def compute_diff(prev: ScanSnapshot | None, curr: ScanSnapshot) -> ScanDiff:
    if prev is None:
        return ScanDiff(
            baseline=True,
            current_scan_id=curr.scan_id,
            new=sorted(curr.findings, key=_severity_key),
            assets_new=sorted(curr.assets, key=lambda a: (a.type.value, a.key)),
        )

    status = curr.module_status()

    def completed(module: str) -> bool:
        return status.get(module) is ModuleStatus.OK

    diff = ScanDiff(previous_scan_id=prev.scan_id, current_scan_id=curr.scan_id)

    before = _by_fingerprint(prev.findings)
    after = _by_fingerprint(curr.findings)
    for fingerprint, finding in after.items():
        old = before.get(fingerprint)
        if old is None:
            diff.new.append(finding)
        elif old.state_hash != finding.state_hash:
            diff.changed.append(FindingChange(before=old, after=finding))
        else:
            diff.unchanged += 1
    for fingerprint, finding in before.items():
        if fingerprint in after:
            continue
        if completed(finding.module):
            diff.resolved.append(finding)
        else:
            diff.stale.append(finding)

    assets_before = _by_fingerprint(prev.assets)
    assets_after = _by_fingerprint(curr.assets)
    for fingerprint, asset in assets_after.items():
        old_asset = assets_before.get(fingerprint)
        if old_asset is None:
            diff.assets_new.append(asset)
        elif any(
            completed(module) and asset.facets.get(module) != old_hash
            for module, old_hash in old_asset.facets.items()
        ):
            diff.assets_changed.append(AssetChange(before=old_asset, after=asset))
    for fingerprint, asset in assets_before.items():
        if fingerprint in assets_after:
            continue
        if completed(asset.source_module):
            diff.assets_removed.append(asset)
        else:
            diff.assets_stale.append(asset)

    diff.new.sort(key=_severity_key)
    diff.resolved.sort(key=_severity_key)
    diff.stale.sort(key=_severity_key)
    diff.changed.sort(key=lambda c: _severity_key(c.after))
    for assets in (diff.assets_new, diff.assets_removed, diff.assets_stale):
        assets.sort(key=lambda a: (a.type.value, a.key))
    diff.assets_changed.sort(key=lambda c: (c.after.type.value, c.after.key))
    return diff
