"""Product naming in one place, so a rename touches one file."""

from perimeterwatch import __version__

PRODUCT_NAME = "Perimeterwatch"
CLI_NAME = "pwatch"
VERIFY_LABEL = "_perimeterwatch-verify"
VERIFY_PREFIX = "pw-verify="


def user_agent(contact_url: str, abuse_email: str | None) -> str:
    """Identifiable User-Agent sent with every outbound request."""
    parts = [f"+{contact_url}"]
    if abuse_email:
        parts.append(f"abuse: {abuse_email}")
    return f"perimeterwatch/{__version__} ({'; '.join(parts)})"
