"""Structured logging with secret scrubbing."""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

from perimeterwatch.config import KNOWN_SECRETS, secret

# Token shapes worth scrubbing even when we do not know the value.
_TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]

REDACTED = "[redacted]"


def scrub(text: str, known_values: tuple[str, ...] = ()) -> str:
    for value in known_values:
        if value and len(value) >= 8:
            text = text.replace(value, REDACTED)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _known_secret_values() -> tuple[str, ...]:
    return tuple(v for v in (secret(name) for name in KNOWN_SECRETS) if v)


def _scrub_processor(
    _logger: Any, _method: str, event: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    known = _known_secret_values()
    for key, value in list(event.items()):
        if isinstance(value, str):
            event[key] = scrub(value, known)
    return event


class _StderrLogger:
    """Writes to whatever stderr is at the time. A failed write never stops a scan."""

    def msg(self, message: str) -> None:
        try:
            print(message, file=sys.stderr, flush=True)
        except (ValueError, OSError):
            pass

    log = debug = info = warn = warning = error = critical = exception = fatal = msg


def configure(verbose: bool = False, json_logs: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")
    # Third-party libraries are noisy at DEBUG and may echo request URLs.
    for noisy in ("httpx", "httpcore", "urllib3", "web3", "checkdmarc", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # dnspython warns whenever one resolver is slow. Lookups fall back to the others.
    logging.getLogger("dns").setLevel(logging.ERROR)
    renderer: Any = (
        structlog.processors.JSONRenderer() if json_logs else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _scrub_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=lambda *args: _StderrLogger(),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
