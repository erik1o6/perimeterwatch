> Draft for review and editing. Not yet submitted.

# The solution

## What it is

Parapet is software that an organisation points at its own domain. It collects what an outsider can see about that organisation, lists the weak points with instructions for fixing each one, and on later scans reports what has changed.

It is opt-in. The web service scans a domain only once the organisation has proved that it controls it. Nobody is rated, and nothing is published about anyone.

It can be used in two ways, and both are built:

- a command-line program, `parapet`, that an organisation runs on its own machine;
- a web service with a worker that runs scans on a schedule and sends alerts.

The web service has never been deployed. It runs in automated tests on the development machine and nowhere else. No organisation uses it. The grant pays to publish the code, deploy the service, have it reviewed by an independent firm, and get organisations onto it.

## What it checks

Every check in this table is built and works today. The command-line tool and the web service run the same engine.

| Area | What is checked | Where the information comes from | Depth |
|---|---|---|---|
| Hosts | Which subdomains exist | Public certificate records and passive DNS data (subfinder, crt.sh) | Passive |
| DNS | Whether DNSSEC is on, whether a CAA record limits who may issue certificates, wildcard records, names that point at private addresses, names that look like internal systems | DNS records, read through public resolvers | Passive |
| Email | Whether someone else can send email that appears to come from the domain: SPF, DMARC, DKIM, and whether an MTA-STS record exists | DNS records, read through public resolvers | Passive |
| Email, MTA-STS policy | The content of the MTA-STS policy file | One request to the organisation's own web server | Probe |
| Lookalike domains | Registered variations of the organisation's name, whether they can receive email, and certificates issued with the brand name in them | DNS and certificate records. Lookalike domains are never contacted. | Passive |
| Dangling records | DNS records that point at a service the organisation no longer uses, which someone else could claim | DNS | Passive |
| Published secrets | Passwords and keys committed to the organisation's public GitHub repositories | GitHub, using trufflehog. The secret itself is never stored and never tested. Only its type, location, first four characters and a short hash are kept. | Passive |
| GitHub settings | Whether two-factor login is required, public repositories that have gone stale | GitHub | Passive |
| Treasury signers | Owners and threshold of the organisation's Safe multisig. Any change to the signers is reported. | Read directly from the chain with two read-only calls per Safe | Passive |
| Job postings | Technologies the organisation names in its own job advertisements | Greenhouse and Lever job boards | Passive |
| Breached staff accounts | Staff email addresses that appear in known breaches and in logs from password-stealing malware. The report shows breach name, date and kinds of data. It never shows a password. | Have I Been Pwned | Passive, and per-person detail only for a verified domain |
| Web servers and certificates | Certificate expiry and mismatch, missing redirect to HTTPS | One ordinary web request and one TLS handshake per host | Probe |
| Open ports | The 100 most common ports, by ordinary connection attempts | The organisation's hosts | Active |
| Exposure checks | Read-only checks for exposed files and misconfiguration | nuclei, limited by the project's own rules to plain GET and HEAD requests | Active |

There are 27 check modules and 74 kinds of finding. Each kind has a default severity and a written fix, held in one table in the code (`src/parapet/core/severity.py`) so that the rating rules can be reviewed.

**The exposure checks.** These use a public collection of check templates, nuclei-templates version 10.4.9. The project reads every template and admits one only if each request in it is a plain GET or HEAD with nothing attached. Of the templates in that version, 2,093 are admitted and 654 are refused. No flag or setting widens these rules.

**Two details of the breach check.**

- If the organisation uploads its staff list, each breach finding says whether the address is on the list. This tells current staff from former staff and from shared mailboxes. Without a list, nothing is claimed either way.
- A malware log records which sites a person had saved logins for. That list can reveal private matters, such as health or beliefs. A finding therefore names only two kinds of site: the organisation's own systems, and a fixed list of services that control code, infrastructure or funds, such as GitHub, Google accounts and Safe. All other sites are reduced to a count.

## Change reporting

The first scan is a baseline. Each later scan is compared with the one before and reports findings that are new, changed or resolved, and hosts that have appeared or disappeared.

A finding is marked as resolved only if the check that produced it ran to completion. If a check was skipped or failed, its earlier findings are carried forward and marked as not re-checked. Without this rule, a missing API key would make every problem look fixed.

## The consent model

There are three depths of scan.

| Depth | What it does | What is needed |
|---|---|---|
| Passive | Consults public records and third-party indexes. It makes no connection to the organisation's hosts; DNS records are read through public resolvers. | In the web service, proof of domain control. In the command-line tool, nothing. |
| Probe | Adds one ordinary web request and one TLS handshake per host, and reads the MTA-STS policy file | As for passive, and the organisation chooses this depth |
| Active | Adds connection attempts to common ports, and the read-only exposure checks | Authorisation, in both |

**Proof of domain control.** The organisation places a DNS TXT record at `_parapet-verify.<domain>`. The record must be seen at the domain's own nameservers, or at two independent public resolvers. It is looked up again at the start of every scan. Removing the record withdraws authorisation. This unlocks active checks and per-person breach detail.

**The web service accepts proof of domain control only, and scans nothing without it.** This is decided and implemented. In the web service:

- no scan of any depth runs for a domain until control of it is proved. This is on by default. It is enforced in three places: a request for a scan is refused, the scheduler skips unverified domains, and the worker checks again when the scan starts and refuses if the DNS record has gone;
- the record is also re-checked every day, and standing is withdrawn after three failed checks;
- only one organisation at a time can hold verification of a domain. When a second organisation proves control, the first loses its standing;
- scheduled scans go no deeper than probe. An active scan runs only when a person asks for it.

**The command-line tool also accepts a recorded statement of authority.** A person types their name, role and organisation and the statement "I am authorised to test <domain>". The statement is stored with a tamper check and expires after 30 days. It unlocks active checks. It never unlocks per-person breach detail. This exists for a person running the tool on their own machine under a contract. The web service ignores such statements.

The command-line tool can also run a passive scan of a domain without verification, because a passive scan reads only public records.

There is no flag that skips these checks.

Other safety rules, all built:

- A host is contacted only if it is under the scanned domain and every address it resolves to is public. One private or reserved address disqualifies the host.
- A do-not-contact list holds hosts, addresses or networks that no scan will contact, whatever domain they appear under. This is how a request to opt out from the operator of a host is honoured.
- Hosts behind a content delivery network are skipped by the port check apart from ports 80 and 443, because those addresses are shared with the network's other customers.
- At most 500 hosts are contacted per scan, and requests are rate limited.
- Web requests made by the engine identify the tool and give a contact address.
- Findings are encrypted before they are written to the database.
- Reports are self-contained HTML with no scripts, and JSON with a published schema.
- The external tools are pinned by version, and each download is accepted only if its sha256 checksum matches the value recorded in the project.
- Old data is deleted automatically by the worker: scans older than the retention period (90 days by default), findings resolved before that, and expired statements of authority. The latest scan of each domain is kept for comparison. The audit log is not pruned.

## The web service

Built and covered by automated tests. Never deployed.

| Feature | Detail |
|---|---|
| Sign-in | By emailed link. There are no passwords. |
| Pages | Rendered on the server, with no JavaScript, so the browser can be told to refuse all scripts. |
| Separation of organisations | Every query is limited to the signed-in organisation. A set of tests tries every route as a different organisation and checks that nothing is shown or changed (`tests/web/test_tenancy.py`). |
| Domain verification | By DNS record, in the interface. |
| Scans | A queue, and scheduled scans: daily, every 3 days, weekly, or on request only. |
| Alerts | By email, Slack, Discord and Telegram. An alert says what kind of thing changed and links to the service. It never carries names, addresses or credentials. |
| Audit log | Records sign-ins, scans, changes, each view of a finding about a person, and each report download. |
| Deployment | Docker Compose files and a CI workflow are written. **Neither has ever been run.** There is no Docker on the development machine, and the CI workflow has not yet been pushed, so the CI workflow has had nothing to run on. |

## What it will not do

| It will not | Reason |
|---|---|
| Scrape LinkedIn or social media | Staff lists are supplied by the organisation. Scraping would collect personal data about people who never agreed to it. |
| Profile individuals | The subject is the organisation. A person appears only as an email address at the organisation's domain. |
| Record every site a person had logins for | It can reveal private matters. Only the organisation's own systems and a fixed list of critical services are named. |
| Hold raw credential databases | The tool asks a breach service whether an address appears. It never holds or shows a breached password, and has no field in which to store one. |
| Test credentials it finds | Logging in with a found credential is unauthorised access, whatever the intention. The option in trufflehog that does this is switched off. |
| Exploit anything | The exposure checks only read. Any template that sends a payload is refused. |
| Contact lookalike domains | They belong to someone else, possibly an attacker, who should not learn that they are being watched. |
| Give an overall score or grade | A single number invites comparison and false comfort. It would also compete with the OPSEC Ratings Coalition. See `06-positioning.md`. |
| Put details in an alert | Alerts travel through email and chat services. They say that something changed and where to look. |

## What exists today and what the grant pays for

| Item | Status today | What the grant adds |
|---|---|---|
| Scanning engine with all checks listed above | Built. | Released as version 1.0 in M1 |
| Command-line tool `parapet` | Built | Maintained |
| Web service and worker | Built and tested. Never deployed. | First deployment in M1. Production use in M2 and M3. |
| Automated tests | 1,422 pass on the development machine | Run in public on every change, in M1 |
| Consent model and safety rules | Built, with a dedicated set of security tests | Reviewed independently in M2 |
| Separation of organisations | Built in the application, with tests | A second barrier in the database (row-level security) in M1. Reviewed independently in M2. |
| Scheduled scans, alerts, automatic retention | Built and tested | Shown working in a real deployment in M1 and M2 |
| HTML and JSON reports, with JSON schema | Built | A sample report on the team's own domain, published in M1 |
| Licence, README, security policy, third-party notices | Written. Apache-2.0. | Published with the repository in M1 |
| Public repository | Published at https://github.com/erik1o6/parapet. The CI workflow is written but not yet pushed or run. | CI running in public, in M1 |
| CI workflow and Docker deployment files | Written, never run | Run, and fixed where they fail, in M1 |
| Inviting colleagues to an organisation | Not built. Each account is its own organisation. | M1 |
| Sign-in with a wallet | Not built | M1 |
| Terms of service, privacy notice and other policies | Drafts exist in `docs/legal/`. No lawyer has reviewed them. | Reviewed by a lawyer in M2 |
| Independent security review | Not done | M2 |
| Integration with another tool or body | Not built | M3 |
| Organisations using it | None **[TODO: correct this if any organisation has already run the tool.]** | M3 |

A second breach source is present in the code and switched off by default: Hudson Rock's free lookup, which gives counts only. Its terms for use by a hosted service are not published, so the hosted service will not use it without written permission from Hudson Rock.

## How a reviewer can check the prototype

These steps work once the repository is published, which is the first item of Milestone 1. Until then the maintainer can show the same steps on a call.

1. Clone the repository: https://github.com/erik1o6/parapet
2. Run `make dev`, then `make test`. The expected result is 1,422 tests passed.
3. Run a passive scan against a domain the reviewer owns and open the HTML report.
4. Or open the published sample report: **[TODO: URL, once published]**.

## Notes for the maintainer (delete before submitting)

- `docs/legal/README.md` is out of date. It says the hosted service does not exist, that the uploaded staff list is not used, that there is no do-not-contact list, that retention is a manual command, that views of findings are not logged, and that passive depth fetches the MTA-STS file. The code has moved past all of these. Update it before a lawyer or reviewer reads it.
