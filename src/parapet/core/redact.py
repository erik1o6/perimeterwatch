"""Redaction helpers. Modules redact before a value ever reaches a Finding."""

from __future__ import annotations

import hashlib


def secret_prefix(raw: str, keep: int = 4) -> str:
    """First few characters of a secret, enough to recognise it and no more."""
    raw = raw.strip()
    if len(raw) <= keep * 3:
        return "*" * 8
    return raw[:keep] + "*" * 8


def secret_hash_prefix(raw: str, length: int = 8) -> str:
    return hashlib.sha256(raw.strip().encode()).hexdigest()[:length]


def mask_email(address: str) -> str:
    local, sep, domain = address.partition("@")
    if not sep:
        return "***"
    shown = local[0] if local else ""
    return f"{shown}***@{domain}"
