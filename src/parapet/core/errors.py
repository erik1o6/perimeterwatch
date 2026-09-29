class ParapetError(Exception):
    """Base class for errors shown to the user without a traceback."""

    exit_code = 1


class ConfigError(ParapetError):
    exit_code = 2


class ValidationError(ParapetError):
    """User-supplied input failed validation."""

    exit_code = 2


class AuthorisationError(ParapetError):
    """The requested scan mode needs authorisation that is not in place."""

    exit_code = 4


class ToolError(ParapetError):
    """An external binary is missing, failed, or produced unusable output."""


class UnsafeTargetError(ParapetError):
    """A host resolves to an address that must never be contacted."""
