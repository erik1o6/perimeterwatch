"""Field encryption for anything sensitive that is written to the database.

Keys come from PARAPET_DATA_KEYS (comma separated, newest first). Local CLI use with
no key configured gets a generated key file, readable only by the owner.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from parapet.config import Settings, secret
from parapet.core.errors import ConfigError

KEY_FILE = "data.key"


class DataKeys:
    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise ConfigError("No data encryption key is configured.")
        try:
            self._fernet = MultiFernet([Fernet(k.encode()) for k in keys])
        except (ValueError, TypeError) as exc:
            raise ConfigError(
                "PARAPET_DATA_KEYS holds an invalid key. Generate one with 'parapet db new-key'."
            ) from exc
        # Derived from the oldest key so that rotating in a new key keeps
        # blind indexes, and therefore finding fingerprints, stable.
        self.blind_key = hmac.new(
            keys[-1].encode(), b"parapet/blind-index/v1", hashlib.sha256
        ).digest()
        self.mac_key = hmac.new(
            keys[-1].encode(), b"parapet/record-mac/v1", hashlib.sha256
        ).digest()

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise ConfigError(
                "Stored data could not be decrypted. The data key does not match this database."
            ) from exc

    def rotate(self, token: bytes) -> bytes:
        return self._fernet.rotate(token)

    def mac(self, message: str) -> str:
        return hmac.new(self.mac_key, message.encode(), hashlib.sha256).hexdigest()


def new_key() -> str:
    return Fernet.generate_key().decode()


def load_keys(settings: Settings) -> DataKeys:
    configured = secret("PARAPET_DATA_KEYS")
    if configured:
        return DataKeys([k.strip() for k in configured.split(",") if k.strip()])
    if settings.env != "dev":
        raise ConfigError("PARAPET_DATA_KEYS must be set outside development.")
    return DataKeys([_local_key(settings.ensure_data_dir() / KEY_FILE)])


def _local_key(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    key = new_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key + "\n")
    return key
