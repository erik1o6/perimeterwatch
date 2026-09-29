class PerimeterwatchError(Exception):
    """Base class for errors shown to the user without a traceback."""

    exit_code = 1


class ConfigError(PerimeterwatchError):
    exit_code = 2


class ValidationError(PerimeterwatchError):
    """User-supplied input failed validation."""

    exit_code = 2


class AuthorisationError(PerimeterwatchError):
    """The requested scan mode needs authorisation that is not in place."""

    exit_code = 4


class ToolError(PerimeterwatchError):
    """An external binary is missing, failed, or produced unusable output."""


class UnsafeTargetError(PerimeterwatchError):
    """A host resolves to an address that must never be contacted."""
