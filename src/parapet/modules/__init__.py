"""Scan modules. Importing this package registers each one."""

from parapet.modules import (  # noqa: F401
    breaches,
    dns_resolve,
    email_posture,
    github_org,
    github_secrets,
    http_probe,
    jobs_stack,
    lookalikes,
    nuclei_safe,
    ports,
    safe_multisig,
    subdomains,
    takeover,
    tls_certs,
)
