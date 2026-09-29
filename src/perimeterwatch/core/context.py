"""What a module is handed when it runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import httpx

from perimeterwatch.clients.dns import DnsClient
from perimeterwatch.config import Settings, secret
from perimeterwatch.core.models import (
    AssetType,
    AuthLevel,
    Authorisation,
    ModuleResult,
    ModuleStatus,
    ScanMode,
)
from perimeterwatch.safety.domains import in_scope
from perimeterwatch.safety.ratelimit import RateLimiter
from perimeterwatch.tools.locate import ToolLocator


class CacheBackend(Protocol):
    def get(self, namespace: str, key: str) -> str | None: ...
    def set(self, namespace: str, key: str, value: str, ttl: timedelta) -> None: ...


class NullCache:
    def get(self, namespace: str, key: str) -> str | None:
        return None

    def set(self, namespace: str, key: str, value: str, ttl: timedelta) -> None:
        return None


class AssetStore:
    """Results of modules that have already finished in this scan."""

    def __init__(self) -> None:
        self._results: dict[str, ModuleResult] = {}

    def add(self, result: ModuleResult) -> None:
        self._results[result.module] = result

    def get(self, module: str) -> ModuleResult | None:
        return self._results.get(module)

    def completed(self, module: str) -> bool:
        result = self._results.get(module)
        return result is not None and result.status in (ModuleStatus.OK, ModuleStatus.PARTIAL)

    def of_type(self, *types: AssetType) -> list[Any]:
        seen: dict[tuple[str, str], Any] = {}
        for result in self._results.values():
            for asset in result.assets:
                if asset.type in types:
                    seen.setdefault((asset.type.value, asset.key), asset)
        return list(seen.values())

    def hostnames(self) -> list[str]:
        return sorted(a.key for a in self.of_type(AssetType.DOMAIN, AssetType.SUBDOMAIN))


@dataclass
class ScanContext:
    settings: Settings
    scan_id: UUID
    tenant_id: UUID
    root_domain: str
    mode_ceiling: ScanMode
    authorisation: Authorisation
    http: httpx.AsyncClient
    dns: DnsClient
    tools: ToolLocator
    limiter: RateLimiter
    workdir: Path
    blind_key: bytes
    log: Any
    cache: CacheBackend = field(default_factory=NullCache)
    assets: AssetStore = field(default_factory=AssetStore)

    def secret(self, name: str) -> str | None:
        return secret(name)

    def in_scope(self, host: str) -> bool:
        return in_scope(host, self.root_domain)

    @property
    def verified(self) -> bool:
        return self.authorisation.level is AuthLevel.DNS_VERIFIED

    def cache_get(self, namespace: str, key: str) -> str | None:
        return self.cache.get(namespace, key)

    def cache_set(self, namespace: str, key: str, value: str, ttl: timedelta) -> None:
        self.cache.set(namespace, key, value, ttl)
