"""Shared fixtures. Nothing here touches the network."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from parapet.clients.dns import DnsAnswer, DnsStatus
from parapet.config import Settings
from parapet.core.context import ScanContext
from parapet.core.models import AuthLevel, Authorisation, ScanMode
from parapet.logging import get_logger
from parapet.safety.ratelimit import RateLimiter
from parapet.storage.db import Database, open_database
from parapet.tools.locate import ToolLocator

ROOT = "acme-protocol.xyz"

# Set in CI to run the storage and web tests against Postgres instead of SQLite.
POSTGRES_URL = os.environ.get("PARAPET_TEST_DATABASE_URL")
sqlite_only = pytest.mark.skipif(bool(POSTGRES_URL), reason="inspects the SQLite file directly")


def fresh_database(settings: Settings) -> Database:
    """An empty, migrated database. On Postgres the schema is wiped first."""
    if POSTGRES_URL:
        from sqlalchemy import create_engine, text

        engine = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    return open_database(settings)


# A credential-shaped value planted in fixtures. It must never reach any output.
CANARY = "ghp_CANARYcanaryCANARYcanaryCANARY0123456"


class FakeDns:
    """Answers from a table. Anything not listed does not exist."""

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None) -> None:
        self.records: dict[tuple[str, str], list[str]] = {}
        self.errors: set[str] = set()
        self.nodata: set[str] = set()
        self.queries: list[tuple[str, str]] = []
        for (name, rdtype), values in (records or {}).items():
            self.add(name, rdtype, values)

    def add(self, name: str, rdtype: str, values: list[str]) -> None:
        self.records[(name.lower(), rdtype.upper())] = values

    async def query(self, name: str, rdtype: str, *, retries: int = 1) -> DnsAnswer:
        name = name.lower().rstrip(".")
        rdtype = rdtype.upper()
        self.queries.append((name, rdtype))
        if name in self.errors:
            return DnsAnswer(name, rdtype, DnsStatus.ERROR, error="Timeout")
        values = self.records.get((name, rdtype))
        if values:
            return DnsAnswer(name, rdtype, DnsStatus.OK, tuple(sorted(values)))
        exists = name in self.nodata or any(n == name for n, _ in self.records)
        return DnsAnswer(name, rdtype, DnsStatus.NODATA if exists else DnsStatus.NXDOMAIN)

    async def addresses(self, name: str) -> tuple[list[str], DnsStatus]:
        a = await self.query(name, "A")
        aaaa = await self.query(name, "AAAA")
        ips = sorted(set(a.records) | set(aaaa.records))
        if ips:
            return ips, DnsStatus.OK
        for status in (DnsStatus.NXDOMAIN, DnsStatus.ERROR):
            if status in (a.status, aaaa.status):
                return [], status
        return [], DnsStatus.NODATA


class MemoryCache:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}

    def get(self, namespace: str, key: str) -> str | None:
        return self.data.get((namespace, key))

    def set(self, namespace: str, key: str, value: str, ttl: Any) -> None:
        self.data[(namespace, key)] = value


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Tests never see the developer's real keys, settings or data."""
    for name in (
        "GITHUB_TOKEN",
        "HIBP_API_KEY",
        "PARAPET_DATA_KEYS",
        "PARAPET_DATABASE_URL",
        "PARAPET_TOOLS_DIR",
        "VIRUSTOTAL_API_KEY",
        "SECURITYTRAILS_API_KEY",
        "CERTSPOTTER_API_KEY",
        "CHAOS_API_KEY",
        "PARAPET_RPC_ETH_MAINNET",
        "PARAPET_ALLOW_PATH_TOOLS",
        "PARAPET_HUDSONROCK_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PARAPET_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)
    from parapet import config

    config._dotenv.cache_clear()
    monkeypatch.setattr(config, "USER_CONFIG", tmp_path / "config" / "config.toml")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_url=POSTGRES_URL,
        per_host_rps=1000,
        lookalike_max_permutations=200,
    )


@pytest.fixture
def database(settings: Settings) -> Iterator[Database]:
    db = fresh_database(settings)
    yield db
    db.engine.dispose()


@pytest.fixture
def dns() -> FakeDns:
    return FakeDns()


@pytest.fixture
def make_ctx(settings: Settings, dns: FakeDns, tmp_path: Path) -> Iterator[Any]:
    clients: list[httpx.AsyncClient] = []

    def factory(
        *,
        root: str = ROOT,
        mode: ScanMode = ScanMode.PASSIVE,
        level: AuthLevel = AuthLevel.NONE,
        handler: Any = None,
        tools_dir: Path | None = None,
    ) -> ScanContext:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise AssertionError(f"Unexpected network request in a test: {request.url}")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler or refuse))
        clients.append(client)
        workdir = tmp_path / f"work-{uuid4().hex[:6]}"
        workdir.mkdir()
        return ScanContext(
            settings=settings,
            scan_id=uuid4(),
            tenant_id=uuid4(),
            root_domain=root,
            mode_ceiling=mode,
            authorisation=Authorisation(level=level, basis="test"),
            http=client,
            dns=dns,  # type: ignore[arg-type]
            tools=ToolLocator(tools_dir or tmp_path / "no-tools"),
            limiter=RateLimiter(1000),
            workdir=workdir,
            blind_key=b"k" * 32,
            log=get_logger("test"),
            cache=MemoryCache(),
        )

    yield factory


FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(*parts: str) -> str:
    return FIXTURES.joinpath(*parts).read_text()
