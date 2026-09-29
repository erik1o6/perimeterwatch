"""The interface every scan module implements, and the module registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict

from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Sensitivity,
    Severity,
    Target,
    utcnow,
)
from perimeterwatch.core.severity import adjust, kind_info

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext


class ModuleSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    title: str
    category: Category
    mode: ScanMode
    description: str = ""
    requires_verification: bool = False
    requires_binaries: tuple[str, ...] = ()
    any_of_binaries: tuple[str, ...] = ()
    optional_binaries: tuple[str, ...] = ()
    requires_keys: tuple[str, ...] = ()
    optional_keys: tuple[str, ...] = ()
    # Target fields that must be set, e.g. ("github_org",).
    requires_target: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    contacts: tuple[str, ...] = ()  # what this module talks to, for the methodology section
    default_timeout_s: int = 600


class ScanModule(ABC):
    spec: ClassVar[ModuleSpec]

    @abstractmethod
    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult: ...

    # -- helpers for subclasses -------------------------------------------

    def result(self, status: ModuleStatus = ModuleStatus.OK, **kwargs: Any) -> ModuleResult:
        return ModuleResult(module=self.spec.name, status=status, **kwargs)

    def asset(
        self,
        type_: AssetType,
        key: str,
        *,
        attributes: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
    ) -> Asset:
        return Asset(
            type=type_,
            key=key.lower(),
            attributes=attributes or {},
            state=state or {},
            source_module=self.spec.name,
        )

    def finding(
        self,
        kind: str,
        asset_type: AssetType,
        asset_key: str,
        title: str,
        *,
        identity: dict[str, str] | None = None,
        state: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        confidence: Confidence = Confidence.LIKELY,
        sensitivity: Sensitivity = Sensitivity.NORMAL,
        severity: Severity | None = None,
        severity_steps: int = 0,
        severity_note: str | None = None,
        remediation: str | None = None,
        attribution: str | None = None,
    ) -> Finding:
        info = kind_info(kind)
        base = severity if severity is not None else info.severity
        return Finding(
            kind=kind,
            module=self.spec.name,
            category=info.category,
            title=title,
            severity=adjust(base, severity_steps) if severity_steps else base,
            confidence=confidence,
            sensitivity=sensitivity,
            asset_type=asset_type,
            asset_key=asset_key,
            identity=identity or {},
            state=state or {},
            evidence=evidence or {},
            remediation=remediation or info.remediation,
            references=list(info.references),
            attribution=attribution,
            severity_note=severity_note,
        )


_REGISTRY: dict[str, type[ScanModule]] = {}


def register(cls: type[ScanModule]) -> type[ScanModule]:
    name = cls.spec.name
    if name in _REGISTRY and _REGISTRY[name] is not cls:
        raise ValueError(f"Duplicate module name: {name}")
    _REGISTRY[name] = cls
    return cls


def all_modules() -> dict[str, type[ScanModule]]:
    # Importing the package registers every module.
    import perimeterwatch.modules  # noqa: F401

    return dict(_REGISTRY)


def ordered(names: set[str] | None = None) -> list[type[ScanModule]]:
    """Modules in dependency order. Dependencies of selected modules are included."""
    registry = all_modules()
    wanted = set(registry) if names is None else set(names)
    unknown = wanted - set(registry)
    if unknown:
        raise KeyError(", ".join(sorted(unknown)))

    out: list[type[ScanModule]] = []
    seen: set[str] = set()
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        if name in visiting:
            raise ValueError(f"Dependency cycle at module {name}")
        visiting.add(name)
        for dep in registry[name].spec.depends_on:
            if dep in registry:
                visit(dep)
        visiting.discard(name)
        seen.add(name)
        out.append(registry[name])

    for name in sorted(wanted):
        visit(name)
    return out


def skipped(spec: ModuleSpec, reason: str, hint: str | None = None) -> ModuleResult:
    now = utcnow()
    return ModuleResult(
        module=spec.name,
        status=ModuleStatus.SKIPPED,
        skip_reason=reason,
        hint=hint,
        started_at=now,
        finished_at=now,
    )
