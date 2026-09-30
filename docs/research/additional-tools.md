# Additional tools and data sources

Research date: 30 September 2026.

This document records which further checks were considered for Perimeterwatch, which were
built, which wait for a decision, and which were rejected and why. It covers three areas:
web3 signals and threat feeds, public code and build pipelines, and infrastructure, DNS,
mail and web exposure.

> **How far to trust this document.** Quotations from terms of service were collected with
> a tool that may shorten text. Read the linked page yourself before you rely on a
> quotation in code, in a contract or in a legal document. Version numbers are those seen
> on the research date. Section 5 lists what was not verified.

## 1. Main conclusions

1. **No free plan of a third-party scan database permits use in a hosted service for
   other organisations.** 23 sources of scan data, passive DNS and reverse-IP data were
   examined. None has terms that clearly permit it, and most forbid it in plain words.
   Historical DNS, internet-wide scan data and reverse-IP lookups stay out unless a
   supplier agrees in writing.
2. **The most useful additions need no new tool.** They use libraries already installed
   and data that existing modules already collect.
3. **Change is the signal.** For several new checks the first result is only a record
   (a Safe's modules, a content hash, a list of outside services). The finding that
   matters is the change between two scans.
4. **Two widely used scanners were rejected because their release channels were
   compromised in March 2026** (Trivy and KICS). A tool that scans other organisations
   must not bring that risk with it.

## 2. Built

These needed no new tool, no key and no decision. Every finding kind is described in
`docs/modules.md`.

| Addition | Module | Depth | What the organisation learns |
|---|---|---|---|
| Safe modules, guard, fallback handler, singleton | `safe_modules` | passive | A module can move funds without an owner's signature. A new module, guard or handler since the last scan is reported at high severity |
| ENS content hash and DNSLink | `frontend_pointers` | passive | The content that a decentralised frontend points to has changed. The content itself is never fetched |
| More phishing lists | `phishing_lists` | passive | A lookalike domain is on a public blocklist. New: the organisation's own domain is on a blocklist, so wallets warn its users |
| Security contact | `security_contact` | probe | No `security.txt`, or it has expired, or it is invalid (RFC 9116) |
| Package provenance | `packages` | passive | A release was published without a provenance attestation although the previous release had one, or the publishing repository changed |
| DNSSEC quality | `dnssec_quality` | passive | Weak algorithm, signatures close to expiry, a zone that can be listed by walking NSEC records, NSEC3 iterations above 0 |
| Nameserver health | `nameserver_health` | probe | A nameserver that does not answer for the zone, differing zone versions, no answer over TCP, an open resolver, a delegation that differs from the zone |
| Origin beside the CDN | `origin_exposure` | passive | A host is behind a CDN, but another of the organisation's records leads to the origin server directly |
| Outside services | `dependencies` | passive | The list of outside services the domain depends on, and any change to it |
| Registry lock | `domain_registration` | passive | The domain has a registrar lock but shows no status set by the registry |
| TLS reporting record | `email_posture` | passive | An MTA-STS policy is published, but no record says where delivery failures are reported |
| IPv6 in active checks | `ports`, `zone_transfer` | active | A port that is open over IPv6 and closed over IPv4 |
| Keys with restricted terms | `subdomains` | passive | Not a finding. A hosted deployment no longer uses the VirusTotal and SecurityTrails keys unless the operator states a licence in `PW_LICENSED_SOURCES` |

Notes on the sources used:

| Source | Licence | How it is used |
|---|---|---|
| polkadot-js/phishing | Apache-2.0 | Downloaded whole, matched locally. No domain is sent to a third party |
| Phishing.Database | MIT | The same. It has known false positives, so it is matched only against lookalike candidates and the organisation's own domains |
| Safe contracts | LGPL-3.0 | Only the interface and storage slot constants are used. The data is read from the chain |
| npm registry, PyPI integrity API | Public registries | Only the provenance fields are read. The name and email of the person who published are discarded |

Standards behind the DNS and contact checks: RFC 9905 (RSASHA1 must not be used),
RFC 9276 (NSEC3 iterations must be 0), RFC 9824 (compact denial, which is not reported as
walkable), RFC 9116 (`security.txt`).

## 3. Waiting for a decision

Each of these is useful. Each needs a choice that the maintainer must make.

| # | Addition | What it gives | Decision needed |
|---|---|---|---|
| 1 | **zizmor** (MIT, v1.30.1) | Audit of GitHub Actions workflows, offline: for example, a workflow that runs an outsider's code with publishing secrets | A new pinned tool. It needs a checkout of each repository, which the secrets scan does not keep today. The release has no checksums file |
| 2 | **osv-scanner** (Apache-2.0, v2.6.0) | Known-vulnerable and known-malicious dependencies in lock files | Its database changes daily, so it cannot be pinned by a fixed hash. Accepting it means a new rule: dated data snapshots, recorded by hash |
| 3 | **Timelock watch** | Operations queued on a timelock, shortened delays, new role holders | `eth_getLogs` must be added to the list of allowed RPC methods. That list is a safety boundary |
| 4 | **ScamSniffer list** | A third phishing list, specific to wallet drainers | The data is GPL-3.0. It would be fetched at run time and never copied into the repository. Whether that is enough is a legal question. The free list is 7 days behind |
| 5 | **abuse.ch** (URLhaus, ThreatFox) | The organisation's own host is listed as serving malware | Terms allow "not-for-profit purposes" but do not address a hosted service. Ask abuse.ch in writing. A free key is required |
| 6 | **Sourcify** | The implementation behind a proxy has no verified source | No terms or limits are published. Many teams verify on Etherscan only |
| 7 | **SEAL Safe Harbor registry** | Whether the protocol has adopted Safe Harbor on chain | The read function's signature must be confirmed against the contract source first |
| 8 | **Secrets in issues, comments, gists and wikis** | Credentials pasted outside the code | Flags on the existing trufflehog. The cost in GitHub API calls is unknown, and comment authors are personal data |
| 9 | **Web3 build artefacts in repositories** | Committed `.env` files, RPC keys in Hardhat or Foundry configuration, deployment records | A deployer address may be one person's wallet. Decide whether to report it |
| 10 | **Dependency confusion** | A manifest names a package or scope that nobody has registered | Needs the repository checkout from item 1 |
| 11 | **retire.js data** (Apache-2.0) | Known-vulnerable JavaScript libraries on the organisation's pages | A pinned data file and a matcher written for this project. Medium false-positive rate |
| 12 | **endoflife.date data** (MIT) | Software that no longer receives fixes | High false-positive rate: distributions backport fixes |
| 13 | **certspotter** (MPL-2.0) | A certificate was issued for the domain between two scans | No release binaries, so the project must build it. It runs as a daemon and its bandwidth needs are undocumented |
| 14 | **Cookie flags, source maps** | Small checks on pages the frontend check already fetches | None. Not yet built. Medium false-positive rate |
| 15 | **Route origin (RPKI)** | A prefix without a valid ROA | Applies only to organisations with their own address space. Source terms are unclear |

Recommended order: 14, 1 with 10, 3, 8, then the rest as terms are confirmed.

## 4. Rejected

### 4.1 Threat feeds and web3 sources

| Source | Reason |
|---|---|
| OpenPhish community feed | Terms forbid "customer protection" use and display to third parties. <https://openphish.com/terms.html> |
| phishing.army | CC BY-NC 4.0, and it aggregates OpenPhish and PhishTank |
| PhishTank | New registration reported closed. Terms pages conflict |
| Google Safe Browsing API | No commercial use, and a result may be shown only if refreshed within 30 minutes. A stored report breaks that rule. <https://developers.google.com/safe-browsing/terms> |
| Google Web Risk | Needs a billing account |
| Spamhaus public mirrors | Free for an organisation's own use. Queries for many organisations are not addressed. <https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy/> |
| Cloudflare Radar | CC BY-NC 4.0, token required |
| urlscan.io search | Terms for serving third parties not found |
| Chainabuse | Free key allows 10 calls a month |
| CryptoScamDB | Not updated since 2020 |
| SEAL intel feed | Needs a key. No public access terms |
| Phantom blocklist | No licence in the repository |
| Safe Transaction Service | Without a key: 5,000 requests a month, "for exploration only". The chain is read instead |
| Etherscan | Key required. Commercial terms not found |
| App stores, browser extension stores | No official search API, or terms that forbid this use |
| X, Telegram, Discord handles | No free source that permits it without login or scraping |
| Immunefi, HackerOne, audit contest sites | No official open API |

### 4.2 Code and pipeline tools

| Tool | Reason |
|---|---|
| Trivy | Release channel compromised on 19 March 2026. <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23> |
| KICS | Its GitHub Actions were compromised in the same campaign |
| poutine | Not rejected outright. It contacts the network unless told not to, and it is unclear whether one of its rules fetches data. Reconsider after zizmor |
| grype and syft | Sound, but duplicate osv-scanner |
| Gato-X | The same package contains attack commands. Not suitable for a service based on consent |
| actionlint, hadolint, kube-linter, checkov | Report correctness or style, not exposure |
| octoscan | GPL-3.0, no checksums, duplicates zizmor |
| cargo-audit, pip-audit, npm audit, govulncheck | Fetch data or build code at run time. OSV covers their data |
| terrascan | Archived |
| slither, aderyn, solhint | Must compile the project. Their output is what auditors already review |
| confused | Last release in 2022 |
| Public container image scanning | Docker Hub allows 100 pulls per 6 hours without an account. Too few for a shared service |
| GitHub code search for the domain | 10 requests a minute on a shared token. Results are mostly individuals' repositories |
| Comparing deployed bytecode with the repository | Needs running the organisation's build |

### 4.3 Scan data, passive DNS and reverse IP

| Source | Reason |
|---|---|
| Shodan InternetDB | "Free for non-commercial use". Undefined for a non-profit that serves others |
| Censys free | May not be used "for the benefit of any third party" |
| LeakIX | Needs written agreement for external use |
| Netlas | Community plan is for individuals only |
| FOFA | Display outside the source page is forbidden |
| Criminal IP, FullHunt, Driftnet | Free plans are for internal use |
| ONYPHE, ZoomEye, Hunter.how | Terms could not be read, so they are not used |
| SecurityTrails free | "Internal, non-commercial security purposes" only |
| VirusTotal public API | "Must not be used in commercial products or services" |
| CIRCL, Mnemonic, DNSDB Community, Validin | Restricted to partners or to internal use |
| HackerTarget, ViewDNS, RapidDNS | Third-party use forbidden, or paid only |
| Rapid7 Sonar | No free access |

### 4.4 Web and mail checks

| Check or service | Reason |
|---|---|
| Mozilla HTTP Observatory API | Scan history is public, so a customer's hosts would be published. It also gives a grade, which this project avoids |
| Internet.nl API | Terms forbid use behind a third party's service |
| Hardenize, MXToolbox | Paid, or automated use forbidden |
| Open relay test | Needs a mail dialogue that names an outside recipient. It reads as abuse in the server's log and proves little |
| BIMI | Brand display, not security |
| CORS test | Needs a request with an invented Origin header. Evidence from one request is weak |
| robots.txt and sitemap | High noise. The web archive check already finds sensitive paths |
| Mixed content, favicon hash, HSTS preload list | Low value |
| alterx | Generates names to guess. The project does not guess names |
| asnmap, uncover | Need an account, or are front ends to the scan databases above |
| tlsx certificate log mode | Appears to read only old-style logs, which Let's Encrypt closed on 28 February 2026 |

## 5. Not verified

- The exact wording of every quotation from terms of service.
- Whether any supplier treats a free non-profit service as "non-commercial". None says so.
  Only a written answer settles it.
- abuse.ch: a CC0 licence is widely reported but was not found on the pages read.
- The effect of the ScamSniffer data's GPL-3.0 licence on a service that fetches it.
- Sourcify: licence and rate limits.
- Safe Harbor registry: the signature of the read function.
- Safe 1.5 module guard slot: taken from the main branch. Which deployed versions use it
  was not checked.
- Limits on `eth_getLogs` at free RPC providers.
- Command lines and output field names for zizmor and osv-scanner. Neither was installed.
- Whether zizmor and osv-scanner read a configuration file from the scanned repository.
  If they do, the repository could switch findings off.
- Whether the pinned trufflehog keeps its clones when asked to.
- Registry lock statuses in RDAP for country-code domains.
- Overlap between the new `security.txt` check and admitted nuclei templates.
- ssh-audit with IPv6 addresses. The SSH check still uses IPv4 only.
- IPv6 connectivity of the planned server. Without it, IPv6 checks are recorded as not
  run, never as "nothing open".
