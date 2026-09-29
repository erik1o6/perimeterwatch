# Checks and findings

Generated from the code by `scripts/gen_docs.py`. Do not edit by hand.

## Checks

### Breach exposure (`breaches`)

Work email addresses found in known breaches and malware logs. Details about people are shown only for a verified domain.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: Have I Been Pwned, Hudson Rock (only if switched on)
- Needs: nothing
- Better with: `HIBP_API_KEY`

### Who controls your contracts (`contract_control`)

The owner, upgrade admin and current implementation of each of your contracts, and whether control sits with a single key, read from the chain.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: your Ethereum RPC endpoint
- Needs: `PARAPET_RPC_ETH_MAINNET`, contracts set on the target

### DNS resolution and hygiene (`dns_resolve`)

Which discovered names resolve, where they point, and DNS safeguards.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers
- Needs: nothing
- Runs after: `subdomains`

### Domain registration (`domain_registration`)

When your domain expires, whether it is locked against transfer, and who its registrar and nameservers are.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: data.iana.org (the list of registration record servers), the registry's public registration record server (RDAP)
- Needs: nothing

### Email spoofing protection (`email_posture`)

SPF, DMARC, DKIM and MTA-STS records. The MTA-STS policy file is on your web server, so it is read only at probe depth.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers
- Needs: nothing

### ENS names (`ens_names`)

Who holds each of your ENS names, which address it points to and when it expires, read from the chain.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: your Ethereum RPC endpoint
- Needs: `PARAPET_RPC_ETH_MAINNET`, ens names set on the target

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
- Better with: the `betterleaks` tool

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

### Published packages (`packages`)

Who can publish your npm and PyPI packages, and whether packages with confusingly similar names exist.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: npm registry, npm download counts, PyPI
- Needs: nothing

### Lookalike domains reported for phishing (`phishing_lists`)

Lookalike domains, and domains using your name, that are on a public phishing blocklist.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: raw.githubusercontent.com (MetaMask eth-phishing-detect blocklist, DBAD licence 1.2)
- Needs: nothing
- Runs after: `lookalikes`

### Repository safeguards (`repo_scorecard`)

Which of your public repositories lack branch protection, code review or safe automation settings, according to OpenSSF Scorecard.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: OpenSSF Scorecard API, GitHub API
- Needs: github org set on the target
- Better with: `GITHUB_TOKEN`
- Runs after: `github_org`

### Safe multisig signers (`safe_multisig`)

Owners and signing threshold of your Safe, read from the chain.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: your Ethereum RPC endpoint
- Needs: `PARAPET_RPC_ETH_MAINNET`, safes set on the target

### Domains trusted by your SPF record (`spf_chain`)

Domains your SPF record allows to send mail for you that no longer exist.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: public DNS resolvers
- Needs: nothing

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

### Sensitive addresses in web archives (`web_archive`)

Addresses on your domain, recorded by web archives, whose names suggest backups, keys, configuration or administration pages.

- Depth: Passive. No connection is made to the organisation's hosts.
- Contacts: web.archive.org (Internet Archive Wayback Machine index)
- Needs: nothing

### Website scripts and security headers (`frontend`)

Which scripts your web pages serve, so that a changed or added script is noticed, and which protective headers are missing.

- Depth: Probe. One ordinary request per host.
- Contacts: each of your web hosts: the front page and the script files that host serves
- Needs: nothing
- Runs after: `http_probe`

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

### TLS versions and cipher suites (`tls_config`)

Old TLS versions and weak cipher suites that your servers still accept.

- Depth: Active. Runs only with authorisation.
- Contacts: each discovered host, repeated TLS handshakes on port 443
- Needs: the `tlsx` tool
- Runs after: `dns_resolve`

### DNS zone transfer (`zone_transfer`)

Whether your nameservers hand a full copy of your DNS zone to anyone.

- Depth: Active. Runs only with authorisation.
- Contacts: the domain's own nameservers, one zone transfer request each
- Needs: nothing

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
| `dns.zone_transfer.allowed` | vuln | high | This nameserver hands a full copy of your DNS zone to anyone who asks, which lists every host you have. Restrict zone transfers to your own secondary nameservers. |
| `domain.registration.details` | surface | info | Informational. A change of registrar or nameservers will be reported as a change. If you did not make it, treat it as a hijack in progress. |
| `domain.registration.expired` | surface | critical | The registration has lapsed. Renew it at once, before someone else registers it. |
| `domain.registration.expiring` | surface | medium | Renew the domain now and turn on automatic renewal. A lapsed domain can be registered by anyone, who then controls your website and email. |
| `domain.registration.unlocked` | surface | medium | Turn on the transfer lock at your registrar, and the registry lock if it is offered. Without it, someone who gets into the registrar account can move the domain away. |
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
| `email.spf.dangling_include` | email | high | Your SPF record trusts a domain that does not exist. Whoever registers it can send mail as you and pass SPF. Remove it from the record. |
| `email.spf.invalid` | email | medium | Fix the SPF record so it parses. A broken record is treated by receivers as no record at all. |
| `email.spf.missing` | email | medium | Publish an SPF record listing the services allowed to send mail for this domain, ending in '-all'. If the domain sends no mail, publish 'v=spf1 -all'. |
| `email.spf.permissive` | email | medium | End the SPF record with '-all' (or '~all' while testing). '+all' and '?all' let anyone send as this domain. |
| `email.spf.softfail` | email | low | Once legitimate senders are confirmed, change '~all' to '-all'. |
| `frontend.script.no_integrity` | supply_chain | low | Add a Subresource Integrity hash to scripts loaded from other sites, or host them yourself. Without it, whoever controls that site controls your page. |
| `frontend.scripts` | supply_chain | info | Informational. A change to the scripts your site serves will be reported as a change. If no release explains it, take the site offline and investigate: this is how wallet-draining code reaches users. |
| `github.org.profile` | web3 | info | Informational. |
| `github.org.two_factor_not_required` | web3 | high | Require two-factor authentication for every member of the GitHub organisation. |
| `github.repo.scorecard` | supply_chain | low | Review the failing checks. Branch protection, workflow permissions and dangerous workflow patterns matter most, because they decide who can change what you ship. |
| `github.repo.stale_public` | web3 | info | Public repositories that are no longer maintained can hold old secrets and vulnerable dependencies. Archive them if unused. |
| `http.headers.missing` | surface | low | Add the missing response headers. Strict-Transport-Security stops downgrade to plain HTTP. Content-Security-Policy limits what an injected script can do. |
| `http.no_https_redirect` | surface | low | Redirect plain HTTP to HTTPS and send a Strict-Transport-Security header. |
| `http.tech.detected` | surface | info | Informational. Review whether version details need to be public. |
| `jobs.tech_disclosed` | web3 | info | Job postings name these technologies. This is normal, but it tells an attacker which systems you run. Keep security tooling and internal system names out of postings where you can. |
| `lookalike.certificate_issued` | lookalike | medium | A certificate was issued for a name containing your brand on a domain you do not control. This often precedes a phishing site. Check the name and report it if it imitates you. |
| `lookalike.mail_capable` | lookalike | medium | A domain resembling yours can receive mail, which is what a phishing or invoice-fraud setup needs. Warn staff, and consider a takedown request through the registrar. SEAL 911 can help if it is being used against you. |
| `lookalike.registered` | lookalike | low | A domain resembling yours is registered. Many are harmless or defensive registrations. Watch it for mail or web activity. |
| `lookalike.reported_phishing` | lookalike | high | This lookalike domain is on a public phishing blocklist. Warn your users, and ask the registrar and host to take it down. SEAL 911 can help. |
| `nuclei.finding` | vuln | medium | Review the matched template's description and fix the misconfiguration. |
| `package.lookalike` | supply_chain | medium | A package with a name close to yours exists. Check what it does. If it imitates yours, report it to the registry and warn your users. |
| `package.maintainers` | supply_chain | info | Informational. A change to who can publish this package will be reported as a change. Confirm any change was intended. |
| `package.missing` | supply_chain | low | This package name is not registered. If your documentation or code refers to it, someone else could register it. Register it or remove the references. |
| `ports.open` | vuln | info | Informational. |
| `ports.unexpected_open` | vuln | medium | This port is reachable from the internet. Close it, or restrict it to known addresses, unless it is meant to be public. |
| `secrets.exposed` | secrets | high | Treat this credential as compromised. Revoke and replace it first, then remove it from the repository. Deleting the file is not enough: it stays in git history. |
| `surface.archive.sensitive_url` | surface | low | Web archives list this address. Check that it no longer answers, or that it is meant to be public. Archives keep addresses long after the pages are gone. |
| `surface.subdomain.sensitive_name` | surface | low | This name suggests an internal, staging or administrative system. Confirm it is meant to be public, and put it behind access control if not. |
| `takeover.cname.dangling` | takeover | high | This name points at a hosted service that no longer answers for it. Someone else may be able to claim that resource and serve content on your name. Delete the DNS record, or re-create the resource if it is still needed. |
| `takeover.cname.unresolvable` | takeover | medium | This name is an alias for a target that does not resolve. If the target's domain can be registered or claimed by someone else, they control your name. Remove the record if it is unused. |
| `takeover.ns.dangling` | takeover | high | A delegated nameserver does not resolve. If its domain lapses, whoever registers it can answer for your zone. Fix or remove the delegation. |
| `tls.cert.expired` | surface | high | This certificate has expired. Renew it now; users are seeing browser warnings. |
| `tls.cert.expiring` | surface | medium | Renew this certificate and check why automatic renewal did not run. |
| `tls.cert.hostname_mismatch` | surface | medium | The certificate served does not cover this hostname. Serve a matching certificate. |
| `tls.cert.self_signed` | surface | low | Replace the self-signed certificate with one from a public certificate authority. |
| `tls.cipher.insecure` | vuln | medium | Remove these cipher suites from the server's configuration. They give little or no protection. |
| `tls.cipher.weak` | vuln | low | Prefer modern cipher suites and remove these when your users' software allows. Mozilla's 'intermediate' TLS configuration is a sound target. |
| `tls.protocol.legacy` | vuln | medium | Switch off SSL 3.0, TLS 1.0 and TLS 1.1 on this server. They have known weaknesses, and no current browser needs them. |
| `web3.contract.control` | web3 | info | Informational. A change of owner, admin or implementation will be reported as a change. If it was not a planned upgrade, treat it as a compromise. |
| `web3.contract.single_key_control` | web3 | medium | This contract is controlled by an ordinary account, not a multisig or timelock. One stolen key is enough to change it. Move control to a multisig. |
| `web3.ens.details` | web3 | info | Informational. A change of owner or of the address the name points to will be reported as a change. |
| `web3.ens.expiring` | web3 | medium | Renew the ENS name. A lapsed name can be registered by anyone, who can then point it at their own address. |
| `web3.safe.few_owners` | web3 | medium | This Safe has fewer than three owners, so losing one key may lock funds or leave a single point of failure. Add owners on separate devices. |
| `web3.safe.low_threshold` | web3 | high | This Safe can move funds with a single signature. Raise the threshold so no one compromised key is enough. |
| `web3.safe.owners` | web3 | info | Informational. A change to owners or threshold will be reported as a change; confirm any change was intended. |
| `web3.safe.threshold_equals_owners` | web3 | low | Every owner must sign. Losing any one key locks the Safe. Consider a threshold below the owner count. |
