"""What every breach data source must provide.

A provider never returns a password, a password hash, or any other breached
value. The model has no field that could hold one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from parapet.core.context import ScanContext


class ProviderError(Exception):
    """The source could not be used. The message is safe to show."""


class ProviderUnavailable(ProviderError):
    """The source is not set up for this domain, for example no key or no entitlement."""


@dataclass(frozen=True)
class BreachRecord:
    """One address in one breach. Names the breach and what kinds of data it held."""

    email: str
    breach: str
    breach_date: str = ""
    data_classes: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class StealerRecord:
    """One address seen in malware logs, with the sites the captured logins were for."""

    email: str
    sites: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class DomainSummary:
    """Counts only. Safe to show before a domain is verified."""

    source: str
    employees: int = 0
    users: int = 0
    detail: dict[str, int] = field(default_factory=dict)


@dataclass
class ProviderResult:
    breaches: list[BreachRecord] = field(default_factory=list)
    stealer_logs: list[StealerRecord] = field(default_factory=list)
    summary: DomainSummary | None = None
    notes: list[str] = field(default_factory=list)
    attribution: str | None = None


class BreachProvider(Protocol):
    name: str
    # True when results identify people. Such a provider runs only for a verified domain.
    per_person: bool

    def configured(self, ctx: ScanContext) -> str | None:
        """None when ready to run, otherwise the reason it cannot."""
        ...

    async def lookup(self, domain: str, ctx: ScanContext) -> ProviderResult: ...
