from __future__ import annotations

from typing import Any, Literal

from alembic import context
from sqlalchemy import LargeBinary, engine_from_config, pool

from perimeterwatch.storage.tables import Base
from perimeterwatch.storage.types import EncryptedJSON, EncryptedStr

config = context.config
target_metadata = Base.metadata


def render_item(type_: str, obj: Any, autogen_context: Any) -> str | Literal[False]:
    """Encrypted columns are plain binary as far as the schema is concerned."""
    if type_ == "type" and isinstance(obj, (EncryptedJSON, EncryptedStr)):
        return "sa.LargeBinary()"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_item=render_item,
            # SQLite cannot alter columns in place.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


_ = LargeBinary  # referenced by rendered migrations

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
