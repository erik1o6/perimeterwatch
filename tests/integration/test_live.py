"""Live checks against domains the maintainer owns. See README.md in this directory."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from parapet.config import Settings
from parapet.core.engine import run_scan
from parapet.core.models import Authorisation, ModuleStatus, ScanMode, Target
from parapet.safety.domains import validate_domain
from parapet.storage.db import open_database
from parapet.storage.repo import TenantRepo

pytestmark = pytest.mark.live
ALLOWLIST = Path(__file__).parent / "targets.toml"
PASSIVE = {"subdomains", "dns_resolve", "email_posture", "takeover"}


def allowed() -> list[dict[str, Any]]:
    if not ALLOWLIST.is_file():
        return []
    return list(tomllib.loads(ALLOWLIST.read_text()).get("domain", []))


def guard(domain: str) -> None:
    """Stop unless the domain is on the allowlist. Every live test calls this first."""
    names = {validate_domain(d["name"]) for d in allowed()}
    if domain not in names:
        pytest.fail(f"{domain} is not in tests/integration/targets.toml. Refusing to scan it.")


def domains(*, probe: bool = False) -> list[str]:
    return [d["name"] for d in allowed() if not probe or d.get("probe")]


async def scan(domain: str, mode: ScanMode, only: set[str], tmp_path: Path) -> Any:
    guard(domain)
    settings = Settings(data_dir=tmp_path / "data")
    database = open_database(settings)
    with database.session() as session:
        tenant = TenantRepo.local(session).tenant_id
    snapshot, _ = await run_scan(
        Target(root_domain=domain),
        settings=settings,
        database=database,
        tenant_id=tenant,
        mode=mode,
        authorisation=Authorisation(),
        only=only,
    )
    return snapshot


def test_guard_refuses_unlisted_domains() -> None:
    with pytest.raises(pytest.fail.Exception):
        guard("not-on-the-list.xyz")


@pytest.mark.parametrize(
    "domain", domains() or [pytest.param("", marks=pytest.mark.skip("no targets.toml"))]
)
async def test_passive_scan(domain: str, tmp_path: Path) -> None:
    snapshot = await scan(domain, ScanMode.PASSIVE, PASSIVE, tmp_path)
    status = snapshot.module_status()
    assert status["email_posture"] in (ModuleStatus.OK, ModuleStatus.PARTIAL)
    assert status["dns_resolve"] in (ModuleStatus.OK, ModuleStatus.PARTIAL)
    assert any(a.key == domain for a in snapshot.assets)


@pytest.mark.parametrize(
    "domain", domains(probe=True) or [pytest.param("", marks=pytest.mark.skip("no probe target"))]
)
async def test_probe_scan(domain: str, tmp_path: Path) -> None:
    snapshot = await scan(domain, ScanMode.PROBE, PASSIVE | {"http_probe", "tls_certs"}, tmp_path)
    assert snapshot.module_status()["tls_certs"] in (ModuleStatus.OK, ModuleStatus.PARTIAL)
