# Checks and findings

Generated from the code by `scripts/gen_docs.py`. Do not edit by hand.

## Checks

### Breach exposure (`breaches`)

Work email addresses found in known breaches and malware logs. Details about people are shown only for a verified domain.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: Have I Been Pwned, Hudson Rock (only if switched on)
- Needs: nothing
- Better with: `HIBP_API_KEY`

### DNS resolution and hygiene (`dns_resolve`)

Which discovered names resolve, where they point, and DNS safeguards.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers
- Needs: nothing
- Runs after: `subdomains`

### Email spoofing protection (`email_posture`)

SPF, DMARC, DKIM and MTA-STS records. The MTA-STS policy file is on your web server, so it is read only at probe depth.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers
- Needs: nothing

### GitHub organisation (`github_org`)

Public repositories and organisation settings visible on GitHub.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: GitHub API
- Needs: github org set on the target
- Better with: `GITHUB_TOKEN`

### Secrets in public code (`github_secrets`)

Credentials committed to the organisation's public repositories.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: GitHub (public repositories are downloaded and read)
- Needs: the `trufflehog` tool, `GITHUB_TOKEN`, github org set on the target

### Technology named in job postings (`jobs_stack`)

Systems and tools your own job postings reveal.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: your public job board (Greenhouse or Lever)
- Needs: job board set on the target

### Lookalike domains (`lookalikes`)

Registered domains that resemble yours, and certificates using your name.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers, crt.sh (certificate transparency)
- Needs: nothing

### Safe multisig signers (`safe_multisig`)

Owners and signing threshold of your Safe, read from the chain.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: your Ethereum RPC endpoint
- Needs: `PARAPET_RPC_ETH_MAINNET`, safes set on the target

### Subdomain discovery (`subdomains`)

Hostnames seen in certificate transparency logs and passive DNS sources.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: crt.sh (certificate transparency), subfinder passive sources
- Needs: nothing
- Better with: the `subfinder` tool, `VIRUSTOTAL_API_KEY`, `SECURITYTRAILS_API_KEY`, `CERTSPOTTER_API_KEY`, `CHAOS_API_KEY`, `GITHUB_TOKEN`

### Dangling DNS records (`takeover`)

Names that point at hosted resources or nameservers that no longer exist.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers
- Needs: nothing
- Runs after: `dns_resolve`

### Web servers (`http_probe`)

Which hosts answer on the web, and what software they reveal.

- Depth: Probe. One ordinary request per host.
- Contacts: each discovered host, one web request
- Needs: the `httpx` tool
- Runs after: `dns_resolve`

### TLS certificates (`tls_certs`)

Certificates that are expired, about to expire, or do not match.

- Depth: Probe. One ordinary request per host.
- Contacts: each discovered host, one TLS handshake on port 443
- Needs: nothing
- Better with: the `tlsx` tool
- Runs after: `dns_resolve`

### Exposures and misconfigurations (`nuclei_safe`)

Readable config files, open admin pages and similar, using read-only checks.

- Depth: Active. Runs only with authorisation.
- Contacts: each web server found, read-only requests for known exposures
- Needs: the `nuclei` tool, the `nuclei-templates` tool
- Runs after: `http_probe`

### Open ports (`ports`)

Services reachable from the internet on your own hosts.

- Depth: Active. Runs only with authorisation.
- Contacts: each discovered host, connection attempts on common ports
- Needs: the `naabu` tool
- Runs after: `dns_resolve`

## Findings

Each kind of finding has a default severity. A check may move it one step up or down
and must then say why in the finding itself.

| Kind | Area | Default severity | What to do |
|---|---|---|---|
| `breach.account` | breach | medium | Have this person change the password anywhere it was reused, and make sure phishing-resistant two-factor sign-in is on for their work accounts. |
| `breach.domain_summary` | breach | info | Aggregate count only. Verify the domain to see which accounts are affected. |
| `breach.stealer_log` | breach | high | Credentials for this address appeared in malware logs, which means a device this person used was infected. Reset their passwords, end their active sessions, rotate any keys they held, and have the device examined or rebuilt. |
| `dns.caa.missing` | surface | low | Publish CAA records naming the certificate authorities allowed to issue for this domain. This limits mis-issuance if a DNS or web account is compromised. |
| `dns.dnssec.disabled` | surface | low | Enable DNSSEC at your DNS provider and publish the DS record at your registrar. It protects against forged DNS answers. |
| `dns.nameserver.single_provider` | surface | info | All nameservers belong to one provider. Consider whether a second DNS provider is worth the added resilience. |
| `dns.private_ip` | surface | low | A public DNS name points to a private or reserved address. This reveals internal addressing. Remove the record or move it to internal DNS. |
| `dns.wildcard` | surface | info | A wildcard record answers for any subdomain. Confirm this is intended: it can hide typos and widens what a web vulnerability can reach. |
| `email.dkim.not_found` | email | low | No DKIM key was found under common selector names. Selectors cannot be listed, so this may be a false alarm: confirm with your mail provider that DKIM signing is on. |
| `email.dkim.weak_key` | email | medium | Rotate this DKIM key to at least 2048-bit RSA or to Ed25519. |
| `email.dmarc.invalid` | email | high | Fix the DMARC record so it parses. Receivers ignore an invalid record. |
| `email.dmarc.missing` | email | high | Publish a DMARC record at _dmarc.<domain>. Start with 'p=none' and a reporting address, review the reports, then move to 'p=quarantine' and 'p=reject'. |
| `email.dmarc.no_reporting` | email | low | Add a 'rua' address so you receive aggregate reports of who sends as your domain. |
| `email.dmarc.partial_enforcement` | email | low | Raise 'pct' to 100 and make sure the subdomain policy ('sp') is not weaker than the main policy. |
| `email.dmarc.policy_none` | email | medium | Policy 'p=none' only monitors. After reviewing reports, move to 'p=quarantine' and then 'p=reject' so spoofed mail is refused. |
| `email.mta_sts.invalid` | email | low | The MTA-STS record or policy file could not be validated. Fix it, or remove it. |
| `email.mta_sts.missing` | email | low | Publish an MTA-STS policy so sending servers require TLS when delivering to you. |
| `email.mta_sts.not_enforced` | email | low | The MTA-STS policy is in 'testing' or 'none' mode. Move it to 'enforce'. |
| `email.spf.invalid` | email | medium | Fix the SPF record so it parses. A broken record is treated by receivers as no record at all. |
| `email.spf.missing` | email | medium | Publish an SPF record listing the services allowed to send mail for this domain, ending in '-all'. If the domain sends no mail, publish 'v=spf1 -all'. |
| `email.spf.permissive` | email | medium | End the SPF record with '-all' (or '~all' while testing). '+all' and '?all' let anyone send as this domain. |
| `email.spf.softfail` | email | low | Once legitimate senders are confirmed, change '~all' to '-all'. |
| `github.org.profile` | web3 | info | Informational. |
| `github.org.two_factor_not_required` | web3 | high | Require two-factor authentication for every member of the GitHub organisation. |
| `github.repo.stale_public` | web3 | info | Public repositories that are no longer maintained can hold old secrets and vulnerable dependencies. Archive them if unused. |
| `http.no_https_redirect` | surface | low | Redirect plain HTTP to HTTPS and send a Strict-Transport-Security header. |
| `http.tech.detected` | surface | info | Informational. Review whether version details need to be public. |
| `jobs.tech_disclosed` | web3 | info | Job postings name these technologies. This is normal, but it tells an attacker which systems you run. Keep security tooling and internal system names out of postings where you can. |
| `lookalike.certificate_issued` | lookalike | medium | A certificate was issued for a name containing your brand on a domain you do not control. This often precedes a phishing site. Check the name and report it if it imitates you. |
| `lookalike.mail_capable` | lookalike | medium | A domain resembling yours can receive mail, which is what a phishing or invoice-fraud setup needs. Warn staff, and consider a takedown request through the registrar. SEAL 911 can help if it is being used against you. |
| `lookalike.registered` | lookalike | low | A domain resembling yours is registered. Many are harmless or defensive registrations. Watch it for mail or web activity. |
| `nuclei.finding` | vuln | medium | Review the matched template's description and fix the misconfiguration. |
| `ports.open` | vuln | info | Informational. |
| `ports.unexpected_open` | vuln | medium | This port is reachable from the internet. Close it, or restrict it to known addresses, unless it is meant to be public. |
| `secrets.exposed` | secrets | high | Treat this credential as compromised. Revoke and replace it first, then remove it from the repository. Deleting the file is not enough: it stays in git history. |
| `surface.subdomain.sensitive_name` | surface | low | This name suggests an internal, staging or administrative system. Confirm it is meant to be public, and put it behind access control if not. |
| `takeover.cname.dangling` | takeover | high | This name points at a hosted service that no longer answers for it. Someone else may be able to claim that resource and serve content on your name. Delete the DNS record, or re-create the resource if it is still needed. |
| `takeover.cname.unresolvable` | takeover | medium | This name is an alias for a target that does not resolve. If the target's domain can be registered or claimed by someone else, they control your name. Remove the record if it is unused. |
| `takeover.ns.dangling` | takeover | high | A delegated nameserver does not resolve. If its domain lapses, whoever registers it can answer for your zone. Fix or remove the delegation. |
| `tls.cert.expired` | surface | high | This certificate has expired. Renew it now; users are seeing browser warnings. |
| `tls.cert.expiring` | surface | medium | Renew this certificate and check why automatic renewal did not run. |
| `tls.cert.hostname_mismatch` | surface | medium | The certificate served does not cover this hostname. Serve a matching certificate. |
| `tls.cert.self_signed` | surface | low | Replace the self-signed certificate with one from a public certificate authority. |
| `web3.safe.few_owners` | web3 | medium | This Safe has fewer than three owners, so losing one key may lock funds or leave a single point of failure. Add owners on separate devices. |
| `web3.safe.low_threshold` | web3 | high | This Safe can move funds with a single signature. Raise the threshold so no one compromised key is enough. |
| `web3.safe.owners` | web3 | info | Informational. A change to owners or threshold will be reported as a change; confirm any change was intended. |
| `web3.safe.threshold_equals_owners` | web3 | low | Every owner must sign. Losing any one key locks the Safe. Consider a threshold below the owner count. |
