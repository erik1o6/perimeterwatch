"""Outgoing email over SMTP."""

from __future__ import annotations

import smtplib
import ssl
import sys
from email.message import EmailMessage

from parapet.config import Settings, secret
from parapet.core.errors import ConfigError


class MailError(Exception):
    pass


def _clean_header(value: str) -> str:
    # A line break in a header would let the text add headers of its own.
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())[:300]


def build(settings: Settings, to: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = _clean_header(settings.mail_from)
    message["To"] = _clean_header(to)
    message["Subject"] = _clean_header(subject)
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body)
    return message


def send(settings: Settings, to: str, subject: str, body: str) -> None:
    message = build(settings, to, subject, body)
    if not settings.smtp_host:
        if settings.env != "dev":
            raise ConfigError("PARAPET_SMTP_HOST must be set outside development.")
        # Development only: show the message instead of sending it.
        print(f"\n--- email to {to} ---\n{subject}\n\n{body}\n---\n", file=sys.stderr, flush=True)
        return
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            password = secret("PARAPET_SMTP_PASSWORD")
            if settings.smtp_user and password:
                smtp.login(settings.smtp_user, password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailError(f"Mail could not be sent ({type(exc).__name__}).") from exc
