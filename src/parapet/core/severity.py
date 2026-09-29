"""The single table of finding kinds: default severity, remediation, references.

Modules may move a severity one step up or down, recording why in
`severity_note`. Keeping the defaults here makes the rating rules auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from parapet.core.models import Category, Severity


@dataclass(frozen=True)
class KindInfo:
    category: Category
    severity: Severity
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)


S = Severity
C = Category

_RFC7208 = "https://www.rfc-editor.org/rfc/rfc7208"
_RFC7489 = "https://www.rfc-editor.org/rfc/rfc7489"
_RFC8461 = "https://www.rfc-editor.org/rfc/rfc8461"
_SEAL_DNS = "https://frameworks.securityalliance.org/"
_SEAL_911 = "https://securityalliance.org/our-work/seal-911"

KINDS: dict[str, KindInfo] = {
    # --- email ---------------------------------------------------------
    "email.spf.missing": KindInfo(
        C.EMAIL,
        S.MEDIUM,
        "Publish an SPF record listing the services allowed to send mail for this domain, "
        "ending in '-all'. If the domain sends no mail, publish 'v=spf1 -all'.",
        (_RFC7208,),
    ),
    "email.spf.invalid": KindInfo(
        C.EMAIL,
        S.MEDIUM,
        "Fix the SPF record so it parses. A broken record is treated by receivers as "
        "no record at all.",
        (_RFC7208,),
    ),
    "email.spf.permissive": KindInfo(
        C.EMAIL,
        S.MEDIUM,
        "End the SPF record with '-all' (or '~all' while testing). '+all' and '?all' let "
        "anyone send as this domain.",
        (_RFC7208,),
    ),
    "email.spf.softfail": KindInfo(
        C.EMAIL,
        S.LOW,
        "Once legitimate senders are confirmed, change '~all' to '-all'.",
        (_RFC7208,),
    ),
    "email.dmarc.missing": KindInfo(
        C.EMAIL,
        S.HIGH,
        "Publish a DMARC record at _dmarc.<domain>. Start with 'p=none' and a reporting "
        "address, review the reports, then move to 'p=quarantine' and 'p=reject'.",
        (_RFC7489,),
    ),
    "email.dmarc.invalid": KindInfo(
        C.EMAIL,
        S.HIGH,
        "Fix the DMARC record so it parses. Receivers ignore an invalid record.",
        (_RFC7489,),
    ),
    "email.dmarc.policy_none": KindInfo(
        C.EMAIL,
        S.MEDIUM,
        "Policy 'p=none' only monitors. After reviewing reports, move to 'p=quarantine' "
        "and then 'p=reject' so spoofed mail is refused.",
        (_RFC7489,),
    ),
    "email.dmarc.partial_enforcement": KindInfo(
        C.EMAIL,
        S.LOW,
        "Raise 'pct' to 100 and make sure the subdomain policy ('sp') is not weaker than "
        "the main policy.",
        (_RFC7489,),
    ),
    "email.dmarc.no_reporting": KindInfo(
        C.EMAIL,
        S.LOW,
        "Add a 'rua' address so you receive aggregate reports of who sends as your domain.",
        (_RFC7489,),
    ),
    "email.dkim.not_found": KindInfo(
        C.EMAIL,
        S.LOW,
        "No DKIM key was found under common selector names. Selectors cannot be listed, so "
        "this may be a false alarm: confirm with your mail provider that DKIM signing is on.",
    ),
    "email.dkim.weak_key": KindInfo(
        C.EMAIL,
        S.MEDIUM,
        "Rotate this DKIM key to at least 2048-bit RSA or to Ed25519.",
    ),
    "email.mta_sts.missing": KindInfo(
        C.EMAIL,
        S.LOW,
        "Publish an MTA-STS policy so sending servers require TLS when delivering to you.",
        (_RFC8461,),
    ),
    "email.mta_sts.not_enforced": KindInfo(
        C.EMAIL,
        S.LOW,
        "The MTA-STS policy is in 'testing' or 'none' mode. Move it to 'enforce'.",
        (_RFC8461,),
    ),
    "email.mta_sts.invalid": KindInfo(
        C.EMAIL,
        S.LOW,
        "The MTA-STS record or policy file could not be validated. Fix it, or remove it.",
        (_RFC8461,),
    ),
    # --- DNS -------------------------------------------------------------
    "dns.dnssec.disabled": KindInfo(
        C.SURFACE,
        S.LOW,
        "Enable DNSSEC at your DNS provider and publish the DS record at your registrar. "
        "It protects against forged DNS answers.",
        (_SEAL_DNS,),
    ),
    "dns.caa.missing": KindInfo(
        C.SURFACE,
        S.LOW,
        "Publish CAA records naming the certificate authorities allowed to issue for this "
        "domain. This limits mis-issuance if a DNS or web account is compromised.",
        ("https://www.rfc-editor.org/rfc/rfc8659",),
    ),
    "dns.private_ip": KindInfo(
        C.SURFACE,
        S.LOW,
        "A public DNS name points to a private or reserved address. This reveals internal "
        "addressing. Remove the record or move it to internal DNS.",
    ),
    "dns.nameserver.single_provider": KindInfo(
        C.SURFACE,
        S.INFO,
        "All nameservers belong to one provider. Consider whether a second DNS provider is "
        "worth the added resilience.",
    ),
    "dns.wildcard": KindInfo(
        C.SURFACE,
        S.INFO,
        "A wildcard record answers for any subdomain. Confirm this is intended: it can hide "
        "typos and widens what a web vulnerability can reach.",
    ),
    # --- surface ---------------------------------------------------------
    "surface.subdomain.sensitive_name": KindInfo(
        C.SURFACE,
        S.LOW,
        "This name suggests an internal, staging or administrative system. Confirm it is "
        "meant to be public, and put it behind access control if not.",
    ),
    "tls.cert.expiring": KindInfo(
        C.SURFACE,
        S.MEDIUM,
        "Renew this certificate and check why automatic renewal did not run.",
    ),
    "tls.cert.expired": KindInfo(
        C.SURFACE,
        S.HIGH,
        "This certificate has expired. Renew it now; users are seeing browser warnings.",
    ),
    "tls.cert.hostname_mismatch": KindInfo(
        C.SURFACE,
        S.MEDIUM,
        "The certificate served does not cover this hostname. Serve a matching certificate.",
    ),
    "tls.cert.self_signed": KindInfo(
        C.SURFACE,
        S.LOW,
        "Replace the self-signed certificate with one from a public certificate authority.",
    ),
    "http.no_https_redirect": KindInfo(
        C.SURFACE,
        S.LOW,
        "Redirect plain HTTP to HTTPS and send a Strict-Transport-Security header.",
    ),
    "http.tech.detected": KindInfo(
        C.SURFACE,
        S.INFO,
        "Informational. Review whether version details need to be public.",
    ),
    # --- takeover ----------------------------------------------------------
    "takeover.cname.dangling": KindInfo(
        C.TAKEOVER,
        S.HIGH,
        "This name points at a hosted service that no longer answers for it. Someone else "
        "may be able to claim that resource and serve content on your name. Delete the DNS "
        "record, or re-create the resource if it is still needed.",
        ("https://github.com/EdOverflow/can-i-take-over-xyz",),
    ),
    "takeover.cname.unresolvable": KindInfo(
        C.TAKEOVER,
        S.MEDIUM,
        "This name is an alias for a target that does not resolve. If the target's domain "
        "can be registered or claimed by someone else, they control your name. Remove the "
        "record if it is unused.",
    ),
    "takeover.ns.dangling": KindInfo(
        C.TAKEOVER,
        S.HIGH,
        "A delegated nameserver does not resolve. If its domain lapses, whoever registers "
        "it can answer for your zone. Fix or remove the delegation.",
    ),
    # --- lookalike ---------------------------------------------------------
    "lookalike.registered": KindInfo(
        C.LOOKALIKE,
        S.LOW,
        "A domain resembling yours is registered. Many are harmless or defensive "
        "registrations. Watch it for mail or web activity.",
    ),
    "lookalike.mail_capable": KindInfo(
        C.LOOKALIKE,
        S.MEDIUM,
        "A domain resembling yours can receive mail, which is what a phishing or "
        "invoice-fraud setup needs. Warn staff, and consider a takedown request through the "
        "registrar. SEAL 911 can help if it is being used against you.",
        (_SEAL_911,),
    ),
    "lookalike.certificate_issued": KindInfo(
        C.LOOKALIKE,
        S.MEDIUM,
        "A certificate was issued for a name containing your brand on a domain you do not "
        "control. This often precedes a phishing site. Check the name and report it if it "
        "imitates you.",
        (_SEAL_911,),
    ),
    # --- secrets -----------------------------------------------------------
    "secrets.exposed": KindInfo(
        C.SECRETS,
        S.HIGH,
        "Treat this credential as compromised. Revoke and replace it first, then remove it "
        "from the repository. Deleting the file is not enough: it stays in git history.",
    ),
    # --- breach ------------------------------------------------------------
    "breach.account": KindInfo(
        C.BREACH,
        S.MEDIUM,
        "Have this person change the password anywhere it was reused, and make sure "
        "phishing-resistant two-factor sign-in is on for their work accounts.",
    ),
    "breach.stealer_log": KindInfo(
        C.BREACH,
        S.HIGH,
        "Credentials for this address appeared in malware logs, which means a device this "
        "person used was infected. Reset their passwords, end their active sessions, rotate "
        "any keys they held, and have the device examined or rebuilt.",
        (_SEAL_911,),
    ),
    "breach.domain_summary": KindInfo(
        C.BREACH,
        S.INFO,
        "Aggregate count only. Verify the domain to see which accounts are affected.",
    ),
    # --- web3 --------------------------------------------------------------
    "web3.safe.low_threshold": KindInfo(
        C.WEB3,
        S.HIGH,
        "This Safe can move funds with a single signature. Raise the threshold so no one "
        "compromised key is enough.",
    ),
    "web3.safe.few_owners": KindInfo(
        C.WEB3,
        S.MEDIUM,
        "This Safe has fewer than three owners, so losing one key may lock funds or leave a "
        "single point of failure. Add owners on separate devices.",
    ),
    "web3.safe.threshold_equals_owners": KindInfo(
        C.WEB3,
        S.LOW,
        "Every owner must sign. Losing any one key locks the Safe. Consider a threshold "
        "below the owner count.",
    ),
    "web3.safe.owners": KindInfo(
        C.WEB3,
        S.INFO,
        "Informational. A change to owners or threshold will be reported as a change; "
        "confirm any change was intended.",
    ),
    "github.org.two_factor_not_required": KindInfo(
        C.WEB3,
        S.HIGH,
        "Require two-factor authentication for every member of the GitHub organisation.",
    ),
    "github.repo.stale_public": KindInfo(
        C.WEB3,
        S.INFO,
        "Public repositories that are no longer maintained can hold old secrets and "
        "vulnerable dependencies. Archive them if unused.",
    ),
    "github.org.profile": KindInfo(C.WEB3, S.INFO, "Informational."),
    "jobs.tech_disclosed": KindInfo(
        C.WEB3,
        S.INFO,
        "Job postings name these technologies. This is normal, but it tells an attacker "
        "which systems you run. Keep security tooling and internal system names out of "
        "postings where you can.",
    ),
    # --- active --------------------------------------------------------------
    "ports.unexpected_open": KindInfo(
        C.VULN,
        S.MEDIUM,
        "This port is reachable from the internet. Close it, or restrict it to known "
        "addresses, unless it is meant to be public.",
    ),
    "ports.open": KindInfo(C.VULN, S.INFO, "Informational."),
    "nuclei.finding": KindInfo(
        C.VULN,
        S.MEDIUM,
        "Review the matched template's description and fix the misconfiguration.",
    ),
}


def kind_info(kind: str) -> KindInfo:
    try:
        return KINDS[kind]
    except KeyError as exc:
        raise KeyError(f"Unknown finding kind {kind!r}. Add it to core/severity.py.") from exc


def adjust(base: Severity, steps: int) -> Severity:
    """Move a severity by at most one step either way."""
    steps = max(-1, min(1, steps))
    return Severity(max(Severity.INFO, min(Severity.CRITICAL, base + steps)))
