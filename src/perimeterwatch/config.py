"""Settings: defaults, then TOML files, then PW_* environment variables.

Secrets never come from TOML. They are read from the environment or `.env` only.
"""

from __future__ import annotations

import os
import re
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

import platformdirs
from dotenv import dotenv_values
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from perimeterwatch.core.errors import ConfigError

_SECRET_KEY_RE = re.compile(r"token|secret|password|passwd|api_?key|data_keys", re.IGNORECASE)

USER_CONFIG = Path(platformdirs.user_config_dir("perimeterwatch")) / "config.toml"
LOCAL_CONFIG = Path("perimeterwatch.toml")

# Secrets the modules may ask for. Names only; values are never logged.
KNOWN_SECRETS = (
    "GITHUB_TOKEN",
    "HIBP_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "SECURITYTRAILS_API_KEY",
    "CERTSPOTTER_API_KEY",
    "CHAOS_API_KEY",
    "PW_RPC_ETH_MAINNET",
    "PW_DATA_KEYS",
    "PW_SMTP_PASSWORD",
)


def _reject_secret_keys(data: dict[str, Any], path: Path, prefix: str = "") -> None:
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if _SECRET_KEY_RE.search(key):
            raise ConfigError(
                f"{path}: '{dotted}' looks like a secret. "
                "Secrets belong in the environment or .env, not in TOML."
            )
        if isinstance(value, dict):
            _reject_secret_keys(value, path, f"{dotted}.")


def config_files() -> list[Path]:
    """Existing config files, lowest priority first."""
    found = []
    for path in (USER_CONFIG, LOCAL_CONFIG):
        if path.is_file():
            with path.open("rb") as fh:
                _reject_secret_keys(tomllib.load(fh), path)
            found.append(path)
    return found


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PW_", extra="ignore")

    env: str = "dev"
    data_dir: Path = Field(
        default_factory=lambda: Path(platformdirs.user_data_dir("perimeterwatch"))
    )
    database_url: str | None = None
    tools_dir: Path | None = None
    allow_path_tools: bool = False

    contact_url: str = "https://perimeterwatch.org"
    abuse_email: str | None = None
    # Addresses that scan traffic leaves from, shown on the public page so that
    # operators of scanned hosts can recognise the scanner in their logs.
    scan_sources: list[str] = Field(default_factory=list)

    retention_days: int = 90
    concurrency: int = 4
    dns_timeout_s: float = 4.0
    http_timeout_s: float = 20.0
    per_host_rps: float = 2.0
    lookalike_max_permutations: int = 6000
    dkim_selectors_extra: list[str] = Field(default_factory=list)

    # Hosts, addresses or networks that must never be contacted, whatever a scan finds.
    # This is how an opt-out request from the operator of a host is honoured.
    never_contact: list[str] = Field(default_factory=list)

    # Data sources for which the operator holds a licence that allows use in a
    # service for other organisations, for example ["virustotal"]. Without an
    # entry here, a hosted deployment does not use the key for such a source.
    licensed_sources: list[str] = Field(default_factory=list)

    breach_providers: list[str] = Field(default_factory=lambda: ["hibp"])
    hudsonrock_enabled: bool = False

    # Hosted service
    base_url: str = "http://127.0.0.1:8000"
    signup_open: bool = True
    # The hosted service scans a domain only once control of it is proved, so
    # nobody can use it to look at an organisation that did not ask.
    scan_requires_verification: bool = True
    max_targets_per_tenant: int = 10
    min_scan_interval_minutes: int = 360
    default_scan_interval_hours: int = 24
    worker_poll_seconds: float = 5.0
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    mail_from: str = "Perimeterwatch <no-reply@localhost>"
    trust_proxy_headers: bool = False
    # Websocket address of a self-hosted certstream server, e.g. ws://certstream:8080/
    # When set, the worker watches new certificates for names imitating verified domains.
    certstream_url: str | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Later files override earlier ones, so reverse for priority order.
        toml = [
            TomlConfigSettingsSource(settings_cls, toml_file=p) for p in reversed(config_files())
        ]
        return (init_settings, env_settings, *toml)

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_dir / 'perimeterwatch.db'}"

    @property
    def resolved_tools_dir(self) -> Path:
        return self.tools_dir or self.data_dir / "tools"

    def ensure_data_dir(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self.data_dir


@lru_cache(maxsize=1)
def _dotenv() -> dict[str, str | None]:
    path = Path(".env")
    return dict(dotenv_values(path)) if path.is_file() else {}


def secret(name: str) -> str | None:
    """Look up a secret by name: process environment first, then `.env`."""
    value = os.environ.get(name) or _dotenv().get(name)
    return value or None


def load_settings(**overrides: Any) -> Settings:
    # PW_* values in .env should count too, without exporting them to child processes.
    env_overrides = {
        k.removeprefix("PW_").lower(): v
        for k, v in _dotenv().items()
        if k.startswith("PW_") and v and k not in os.environ and k != "PW_DATA_KEYS"
    }
    known = set(Settings.model_fields)
    merged: dict[str, Any] = {k: v for k, v in env_overrides.items() if k in known}
    merged.update(overrides)
    return Settings(**merged)
