"""Product naming in one place, so a rename touches one file."""

from parapet import __version__

PRODUCT_NAME = "Parapet"
CLI_NAME = "parapet"
VERIFY_LABEL = "_parapet-verify"
VERIFY_PREFIX = "parapet-verify="


def user_agent(contact_url: str, abuse_email: str | None) -> str:
    """Identifiable User-Agent sent with every outbound request."""
    parts = [f"+{contact_url}"]
    if abuse_email:
        parts.append(f"abuse: {abuse_email}")
    return f"parapet/{__version__} ({'; '.join(parts)})"
