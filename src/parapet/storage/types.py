"""Column types that encrypt on write and decrypt on read."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import LargeBinary
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

from parapet.storage.crypto import DataKeys

_keys: DataKeys | None = None


def set_keys(keys: DataKeys) -> None:
    global _keys
    _keys = keys


def get_keys() -> DataKeys:
    if _keys is None:
        raise RuntimeError("Data keys are not loaded. Call storage.db.open_database first.")
    return _keys


class EncryptedJSON(TypeDecorator[Any]):
    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Dialect) -> bytes | None:
        if value is None:
            return None
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        return get_keys().encrypt(raw)

    def process_result_value(self, value: bytes | None, dialect: Dialect) -> Any:
        if value is None:
            return None
        return json.loads(get_keys().decrypt(bytes(value)))


class EncryptedStr(TypeDecorator[str]):
    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> bytes | None:
        if value is None:
            return None
        return get_keys().encrypt(value.encode())

    def process_result_value(self, value: bytes | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return get_keys().decrypt(bytes(value)).decode()
