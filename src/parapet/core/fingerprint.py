"""Stable fingerprints, so the same issue is recognised across scans.

A fingerprint covers identity only. Anything volatile (timestamps, counts, days
remaining, tool versions) belongs in `state` or `evidence`, never in identity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from parapet.core.models import Asset, Finding, Sensitivity


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def blind_index(key: bytes, value: str) -> str:
    """Keyed hash of a personal identifier, so it can be matched without being stored."""
    return hmac.new(key, value.strip().lower().encode(), hashlib.sha256).hexdigest()


def asset_fingerprint(root_domain: str, asset: Asset) -> str:
    return _sha256(["asset", root_domain, asset.type.value, asset.key.lower()])


def asset_state_hash(asset: Asset) -> str:
    return _sha256(asset.state)


def finding_fingerprint(root_domain: str, finding: Finding, blind_key: bytes) -> str:
    key = finding.asset_key.lower()
    if finding.sensitivity is Sensitivity.PERSONAL:
        key = blind_index(blind_key, key)
    return _sha256(
        [
            "finding",
            root_domain,
            finding.kind,
            finding.asset_type.value,
            key,
            sorted(finding.identity.items()),
        ]
    )


def finding_state_hash(finding: Finding) -> str:
    return _sha256([int(finding.severity), finding.state])
