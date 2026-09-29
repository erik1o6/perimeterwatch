"""Engine and session setup, plus migrations."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from perimeterwatch.config import Settings
from perimeterwatch.storage import types
from perimeterwatch.storage.crypto import DataKeys, load_keys


@dataclass
class Database:
    engine: Engine
    sessions: sessionmaker[Session]
    keys: DataKeys
    url: str

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.sessions() as session:
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise


def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False})
        event.listen(engine, "connect", _sqlite_pragmas)
        return engine
    return create_engine(url, pool_pre_ping=True)


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option(
        "script_location", str(resources.files("perimeterwatch").joinpath("migrations"))
    )
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def migrate(url: str) -> None:
    command.upgrade(alembic_config(url), "head")


def open_database(settings: Settings, *, run_migrations: bool = True) -> Database:
    settings.ensure_data_dir()
    keys = load_keys(settings)
    types.set_keys(keys)
    url = settings.resolved_database_url
    if run_migrations:
        migrate(url)
    engine = make_engine(url)
    if url.startswith("sqlite:///") and ":memory:" not in url:
        _restrict_sqlite_file(url)
    return Database(
        engine=engine,
        sessions=sessionmaker(engine, expire_on_commit=False),
        keys=keys,
        url=url,
    )


def _restrict_sqlite_file(url: str) -> None:
    from pathlib import Path

    path = Path(url.removeprefix("sqlite:///"))
    if path.exists():
        path.chmod(0o600)
