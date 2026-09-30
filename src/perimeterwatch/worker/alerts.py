"""Tell an organisation when something changed.

An alert says that something changed and where to look. It never carries the
detail: no email addresses, no credential fragments, no breach names. Chat
channels and inboxes are not the place for those.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from perimeterwatch.config import Settings
from perimeterwatch.core.diff import ScanDiff
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import Finding, ScanSnapshot, Sensitivity, Severity, utcnow
from perimeterwatch.core.severity import change_severity
from perimeterwatch.safety.domains import validate_email
from perimeterwatch.storage.repo import _aware
from perimeterwatch.storage.tables import AlertChannel, AlertDelivery
from perimeterwatch.web import mail

KINDS = ("email", "slack", "discord", "telegram")
MAX_ATTEMPTS = 5
MAX_LISTED = 8
# Webhooks may only point at these services. An open address field would let
# anyone make the server send requests wherever they like.
WEBHOOK_HOSTS = {
    "slack": ("hooks.slack.com", "/services/"),
    "discord": ("discord.com", "/api/webhooks/"),
}


def validate_config(kind: str, raw: dict[str, str]) -> dict[str, str]:
    if kind == "email":
        return {"to": validate_email(raw.get("to", ""))}
    if kind in WEBHOOK_HOSTS:
        host, prefix = WEBHOOK_HOSTS[kind]
        url = raw.get("url", "").strip()
        parsed = urlparse(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == host
            and parsed.port in (None, 443)
            and not parsed.username
            and parsed.path.startswith(prefix)
            and len(url) <= 400
            and not any(c.isspace() for c in url)
        )
        if not valid:
            raise ValidationError(
                f"That is not a {kind.capitalize()} webhook address. It should start with "
                f"https://{host}{prefix}"
            )
        return {"url": url}
    if kind == "telegram":
        token = raw.get("bot_token", "").strip()
        chat = raw.get("chat_id", "").strip()
        bot_id, _, secret_part = token.partition(":")
        if not (
            bot_id.isdigit()
            and 20 <= len(secret_part) <= 60
            and secret_part.replace("-", "").replace("_", "").isalnum()
        ):
            raise ValidationError("That is not a Telegram bot token.")
        if not chat.lstrip("-").isdigit() or len(chat) > 20:
            raise ValidationError("The Telegram chat ID should be a number.")
        return {"bot_token": token, "chat_id": chat}
    raise ValidationError(f"Unknown alert channel type: {kind}.")


def describe(kind: str, config: dict[str, Any]) -> str:
    """How a channel is shown in the interface. Credentials are never shown back."""
    if kind == "email":
        return str(config.get("to", ""))
    if kind == "telegram":
        return f"chat {config.get('chat_id', '')}"
    return f"{kind.capitalize()} webhook"


def _line(finding: Finding) -> str:
    if finding.sensitivity is not Sensitivity.NORMAL:
        # Say what kind of thing, not who or what.
        if finding.sensitivity is Sensitivity.SECRET:
            label = "A credential in public code"
        elif finding.kind.startswith("breach."):
            label = "A staff address in breach data"
        else:
            label = "A finding that names a person"
        return f"[{finding.severity.label}] {label}"
    return f"[{finding.severity.label}] {finding.title}"


def compose(
    snapshot: ScanSnapshot, diff: ScanDiff, *, min_severity: int, link: str
) -> tuple[str, str] | None:
    """Subject and body, or None when nothing meets the channel's threshold."""
    if diff.baseline:
        new = [f for f in diff.new if f.severity >= min_severity]
        if not new:
            return None
        domain = snapshot.target.root_domain
        lines = [f"First scan of {domain}: {len(new)} finding(s) at or above your alert level.", ""]
        lines += [_line(f) for f in new[:MAX_LISTED]]
        if len(new) > MAX_LISTED:
            lines.append(f"... and {len(new) - MAX_LISTED} more")
        lines += ["", f"Full report: {link}"]
        return f"{domain}: first scan, {len(new)} finding(s)", "\n".join(lines)

    new = [f for f in diff.new if f.severity >= min_severity]
    # A change to a watched finding is judged by what the change means, not by
    # the finding's everyday severity. A new signer on a Safe is not "info".
    changed = [
        c.after.model_copy(update={"severity": change_severity(c.after.kind, c.after.severity)})
        for c in diff.changed
    ]
    changed = [f for f in changed if f.severity >= min_severity]
    resolved = [f for f in diff.resolved if f.severity >= min_severity]
    if not (new or changed or resolved):
        return None
    domain = snapshot.target.root_domain
    worst = max((f.severity for f in [*new, *changed]), default=Severity.INFO)
    lines = [f"Changes for {domain} since the last scan:", ""]
    for title, items in (("New", new), ("Changed", changed), ("Resolved", resolved)):
        if not items:
            continue
        lines.append(f"{title} ({len(items)})")
        lines += [f"  {_line(f)}" for f in items[:MAX_LISTED]]
        if len(items) > MAX_LISTED:
            lines.append(f"  ... and {len(items) - MAX_LISTED} more")
        lines.append("")
    lines.append(f"Details: {link}")
    parts = []
    if new:
        parts.append(f"{len(new)} new")
    if changed:
        parts.append(f"{len(changed)} changed")
    if resolved:
        parts.append(f"{len(resolved)} resolved")
    prefix = f"[{worst.label}] " if new or changed else ""
    return f"{prefix}{domain}: {', '.join(parts)}", "\n".join(lines)


def queue_alerts(
    db: Session,
    settings: Settings,
    *,
    tenant_id: Any,
    scan_id: Any,
    snapshot: ScanSnapshot,
    diff: ScanDiff,
) -> int:
    link = f"{settings.base_url.rstrip('/')}/scans/{scan_id}"
    channels = db.scalars(
        select(AlertChannel).where(
            AlertChannel.tenant_id == tenant_id, AlertChannel.enabled.is_(True)
        )
    )
    queued = 0
    for channel in channels:
        message = compose(snapshot, diff, min_severity=channel.min_severity, link=link)
        if message is None:
            continue
        db.add(
            AlertDelivery(
                tenant_id=tenant_id,
                channel_id=channel.id,
                scan_id=scan_id,
                subject=message[0][:300],
                body=message[1],
            )
        )
        queued += 1
    db.flush()
    return queued


def queue_notice(db: Session, *, tenant_id: Any, subject: str, body: str) -> int:
    """A message to every enabled channel of a tenant, for events other than scans."""
    queued = 0
    for channel in db.scalars(
        select(AlertChannel).where(
            AlertChannel.tenant_id == tenant_id, AlertChannel.enabled.is_(True)
        )
    ):
        db.add(
            AlertDelivery(
                tenant_id=tenant_id, channel_id=channel.id, subject=subject[:300], body=body
            )
        )
        queued += 1
    db.flush()
    return queued


class DeliveryError(Exception):
    pass


async def _post(client: httpx.AsyncClient, url: str, payload: dict[str, Any]) -> None:
    try:
        response = await client.post(url, json=payload, timeout=15)
    except httpx.TransportError as exc:
        raise DeliveryError(f"could not connect ({type(exc).__name__})") from exc
    if response.status_code >= 300:
        raise DeliveryError(f"answered HTTP {response.status_code}")


async def deliver_one(
    settings: Settings, client: httpx.AsyncClient, kind: str, config: dict[str, Any],
    subject: str, body: str,
) -> None:  # fmt: skip
    config = validate_config(kind, {k: str(v) for k, v in config.items()})
    text = f"{subject}\n\n{body}"
    if kind == "email":
        try:
            await asyncio.to_thread(mail.send, settings, config["to"], subject, body)
        except mail.MailError as exc:
            raise DeliveryError(str(exc)) from exc
    elif kind == "slack":
        await _post(client, config["url"], {"text": text})
    elif kind == "discord":
        await _post(
            client, config["url"], {"content": text[:1900], "allowed_mentions": {"parse": []}}
        )
    elif kind == "telegram":
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        await _post(
            client, url,
            {"chat_id": config["chat_id"], "text": text[:4000], "disable_web_page_preview": True},
        )  # fmt: skip


async def deliver_pending(db: Session, settings: Settings, client: httpx.AsyncClient) -> int:
    now = utcnow()
    sent = 0
    pending = db.scalars(
        select(AlertDelivery)
        .where(AlertDelivery.status == "pending", AlertDelivery.next_attempt_at <= now)
        .order_by(AlertDelivery.created_at)
        .limit(50)
    )
    for delivery in list(pending):
        channel = db.get(AlertChannel, delivery.channel_id)
        if channel is None or not channel.enabled or channel.tenant_id != delivery.tenant_id:
            delivery.status = "failed"
            delivery.last_error = "channel removed or switched off"
            continue
        delivery.attempts += 1
        try:
            await deliver_one(
                settings, client, channel.kind, channel.config, delivery.subject, delivery.body
            )
        except (DeliveryError, ValidationError) as exc:
            # The address may hold a credential, so only the short reason is kept.
            delivery.last_error = str(exc)[:300]
            if delivery.attempts >= MAX_ATTEMPTS:
                delivery.status = "failed"
            else:
                delivery.next_attempt_at = utcnow() + timedelta(minutes=2**delivery.attempts)
        else:
            delivery.status = "sent"
            delivery.sent_at = utcnow()
            delivery.last_error = None
            sent += 1
    db.flush()
    return sent


def last_delivery(db: Session, channel: AlertChannel) -> AlertDelivery | None:
    return db.scalars(
        select(AlertDelivery)
        .where(AlertDelivery.channel_id == channel.id)
        .order_by(AlertDelivery.created_at.desc())
    ).first()


__all__ = ["KINDS", "compose", "deliver_pending", "describe", "queue_alerts", "validate_config"]
_ = _aware
