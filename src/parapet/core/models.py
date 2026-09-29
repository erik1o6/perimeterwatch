"""Normalised data model shared by modules, storage, diffing and reports."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

JsonValue = Any


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScanMode(StrEnum):
    PASSIVE = "passive"  # public records and third-party indexes only
    PROBE = "probe"  # one benign request or handshake per host
    ACTIVE = "active"  # port and misconfiguration scanning

    @property
    def rank(self) -> int:
        return {"passive": 0, "probe": 1, "active": 2}[self.value]


class AuthLevel(StrEnum):
    NONE = "none"
    ACKNOWLEDGED = "acknowledged"
    DNS_VERIFIED = "dns_verified"

    @property
    def rank(self) -> int:
        return {"none": 0, "acknowledged": 1, "dns_verified": 2}[self.value]


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    CANDIDATE = "candidate"


class Sensitivity(StrEnum):
    NORMAL = "normal"
    PERSONAL = "personal"
    SECRET = "secret"  # noqa: S105 - a sensitivity label, not a credential


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    CERTIFICATE = "certificate"
    EMAIL_ADDRESS = "email_address"
    REPOSITORY = "repository"
    GITHUB_ORG = "github_org"
    SAFE = "safe"
    LOOKALIKE_DOMAIN = "lookalike_domain"
    SERVICE = "service"


class Category(StrEnum):
    SURFACE = "surface"
    EMAIL = "email"
    LOOKALIKE = "lookalike"
    TAKEOVER = "takeover"
    SECRETS = "secrets"
    BREACH = "breach"
    WEB3 = "web3"
    VULN = "vuln"


class ModuleStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


class SafeRef(BaseModel):
    chain: str = "eth"
    address: str


class JobBoardRef(BaseModel):
    kind: str  # greenhouse | lever | careers_url
    value: str


class Target(BaseModel):
    root_domain: str
    github_org: str | None = None
    safes: list[SafeRef] = Field(default_factory=list)
    job_board: JobBoardRef | None = None
    staff_emails: list[str] = Field(default_factory=list)


class Authorisation(BaseModel):
    level: AuthLevel = AuthLevel.NONE
    basis: str = "No authorisation on record. Passive sources only."
    checked_at: datetime | None = None


class Asset(BaseModel):
    type: AssetType
    key: str
    # Display only. May hold volatile values such as rotating CDN addresses.
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    # Stable facts whose change should be reported.
    state: dict[str, JsonValue] = Field(default_factory=dict)
    # The module that first reported this asset. Decides when it counts as removed.
    source_module: str = ""
    # Hash of `state` per contributing module, so a module that did not run
    # this time cannot make the asset look changed.
    facets: dict[str, str] = Field(default_factory=dict)
    fingerprint: str = ""
    state_hash: str = ""


class Finding(BaseModel):
    kind: str
    module: str = ""
    category: Category
    title: str
    severity: Severity
    confidence: Confidence = Confidence.LIKELY
    sensitivity: Sensitivity = Sensitivity.NORMAL
    asset_type: AssetType
    asset_key: str
    # Extra stable keys that, with kind and asset, identify this finding across runs.
    identity: dict[str, str] = Field(default_factory=dict)
    # Facts whose change should be reported as a "changed" event.
    state: dict[str, JsonValue] = Field(default_factory=dict)
    # Display only. Must already be redacted by the module.
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    attribution: str | None = None
    severity_note: str | None = None
    fingerprint: str = ""
    state_hash: str = ""


class ModuleResult(BaseModel):
    module: str
    status: ModuleStatus
    skip_reason: str | None = None
    hint: str | None = None
    notes: list[str] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime = Field(default_factory=utcnow)


class ScanSnapshot(BaseModel):
    """Everything one scan produced, as needed for diffing and reporting."""

    scan_id: UUID = Field(default_factory=uuid4)
    target: Target
    mode: ScanMode
    authorisation: Authorisation
    started_at: datetime
    finished_at: datetime | None = None
    modules: list[ModuleResult] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        return [f for m in self.modules for f in m.findings]

    @property
    def assets(self) -> list[Asset]:
        """Assets merged across the modules that reported them."""
        merged: dict[str, Asset] = {}
        for module in self.modules:
            for asset in module.assets:
                existing = merged.get(asset.fingerprint)
                if existing is None:
                    merged[asset.fingerprint] = asset.model_copy(deep=True)
                    continue
                existing.attributes.update(asset.attributes)
                existing.state.update(asset.state)
                existing.facets.update(asset.facets)
        return list(merged.values())

    def module_status(self) -> dict[str, ModuleStatus]:
        return {m.module: m.status for m in self.modules}
