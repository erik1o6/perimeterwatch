> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Legal and policy documents: index

The legal and policy drafts of the hosted Perimeterwatch service live in [`src/perimeterwatch/legal/`](../../src/perimeterwatch/legal/). They ship inside the package, and the service publishes them at https://perimeterwatch.org/legal/. This file is the index. It lists what was decided by default, what is still blank, and the open questions for the lawyer.

## Status on 30 September 2026

The hosted service is live in beta at https://perimeterwatch.org. It is free, and sign-up is open. Only the maintainer's own domains are monitored so far. The same scanning engine is also available as an open-source command-line tool, `pwatch`.

- No lawyer has reviewed these documents. The site says that they are drafts and not yet in force.
- The service has had no independent security review.
- There is no legal entity. The service is run by its maintainer, known publicly as code2142, as an individual, while a non-profit entity is set up.
- No breach data source is switched on. Have I Been Pwned and Hudson Rock are both off.
- No Ethereum RPC provider is configured, so the Safe checks do not run in the hosted service.
- No backups are taken. This is a gap, not a decision.

The drafts describe what the software does today. Nothing here claims that the service meets any law or standard.

## How to read the markers

| Marker | Meaning |
|---|---|
| **[TO DECIDE: ...]** | A fact that has not been decided or is not yet known, such as the name of the entity. |
| **[TO CONFIRM: ...]** | A proposed value that the operator must confirm it can keep. None remain: see "Values adopted by default" below. |
| **[NOT YET BUILT: ...]** | Something the document needs the service to do that the software does not do today. |
| **[LAWYER: ...]** | A point where legal judgement is needed. |

The website styles these markers, so their form must stay exactly as it is.

## The documents

| File | Published at | What it is | Who reads it |
|---|---|---|---|
| [terms-of-service.md](../../src/perimeterwatch/legal/terms-of-service.md) | [/legal/terms-of-service](https://perimeterwatch.org/legal/terms-of-service) | The agreement between the operator and a customer organisation. | Customers |
| [privacy-policy.md](../../src/perimeterwatch/legal/privacy-policy.md) | [/legal/privacy-policy](https://perimeterwatch.org/legal/privacy-policy) | What personal data is handled, why, and what rights people have. | Customers, their staff, the public |
| [dpa-outline.md](../../src/perimeterwatch/legal/dpa-outline.md) | [/legal/dpa-outline](https://perimeterwatch.org/legal/dpa-outline) | Outline of a data processing agreement under GDPR Article 28. | Customers, lawyers |
| [scanning-authorisation-and-aup.md](../../src/perimeterwatch/legal/scanning-authorisation-and-aup.md) | [/legal/scanning-authorisation-and-aup](https://perimeterwatch.org/legal/scanning-authorisation-and-aup) | What domain verification authorises, the three scan depths, prohibited uses, abuse reports. | Customers, operators of scanned hosts |
| [data-retention-policy.md](../../src/perimeterwatch/legal/data-retention-policy.md) | [/legal/data-retention-policy](https://perimeterwatch.org/legal/data-retention-policy) | What is kept, for how long, and how it is deleted. | Customers, lawyers |
| [vulnerability-disclosure.md](../../src/perimeterwatch/legal/vulnerability-disclosure.md) | [/legal/vulnerability-disclosure](https://perimeterwatch.org/legal/vulnerability-disclosure) | How to report a security problem in the service itself. | Security researchers |
| [opt-out.md](../../src/perimeterwatch/legal/opt-out.md) | [/legal/opt-out](https://perimeterwatch.org/legal/opt-out) | How the operator of a host that received traffic can make it stop. | Operators of scanned hosts |
| [legitimate-interest-assessment.md](../../src/perimeterwatch/legal/legitimate-interest-assessment.md) | [/legal/legitimate-interest-assessment](https://perimeterwatch.org/legal/legitimate-interest-assessment) | A template a customer can adapt for its own records. | Customers' privacy or security leads |
| security.txt | [/.well-known/security.txt](https://perimeterwatch.org/.well-known/security.txt) | RFC 9116 file. It was planned to move from this directory to `deploy/security.txt`. In the tree today there is no such file: the service answers `/.well-known/security.txt` itself, from the setting `PW_SECURITY_EMAIL`, with a link to the disclosure policy. | Security researchers, automated tools |
| [../../SECURITY.md](../../SECURITY.md) | | How to report a vulnerability in the open-source software. It still holds placeholders of its own. | Developers, researchers |

Links between the documents are relative links to the `.md` file name. The site rewrites them. Links to other files in the repository are full GitHub links.

Related technical documents, which these drafts rely on: [docs/architecture.md](../architecture.md), [docs/operations.md](../operations.md), [docs/modules.md](../modules.md), [docs/hosting-perimeterwatch-org.md](../hosting-perimeterwatch-org.md), [deploy/env.reference.md](../../deploy/env.reference.md), [deploy/cloud-init.yml](../../deploy/cloud-init.yml).

## Facts filled in on 30 September 2026

| Fact | Value |
|---|---|
| Service address | https://perimeterwatch.org |
| Repository | https://github.com/erik1o6/perimeterwatch |
| Contact addresses | `abuse@`, `security@`, `privacy@`, `legal@`, `support@` and `hello@perimeterwatch.org`. All are forwarded to the maintainer. |
| Contact URL and abuse address in the User-Agent | https://perimeterwatch.org and abuse@perimeterwatch.org |
| Addresses that scan traffic comes from | `162.55.43.236` and `2a01:4f8:c016:78c3::1`, published on the home page |
| Hosting | One server at Hetzner Online GmbH, Falkenstein, Germany. The database is on that server. All stored data is in Germany. |
| Outbound email | Resend, region eu-west-1 (Ireland), which sends through Amazon SES |
| DNS and inbound mail forwarding | Cloudflare, Inc. |
| TLS certificates | Let's Encrypt |
| Source code hosting | GitHub |
| Ethereum RPC provider | None configured |
| Breach data sources | None switched on |
| Encryption for security reports | None. No PGP key exists. Reports go by plain email. |
| Private vulnerability reporting on GitHub | Not switched on (checked through the GitHub API on 30 September 2026) |
| Service logs | Limited by size: five files of 20 MB for each container, set in `deploy/cloud-init.yml` |

## Values adopted by default on 30 September 2026

Nobody has approved these yet. Each was written into the documents so that they read as complete drafts. The owner should review each one and change what does not fit. The aim was that one maintainer can keep them.

### Proposed values that were marked TO CONFIRM

| Document | Item | Value adopted | Note |
|---|---|---|---|
| terms-of-service | Domains per account | 10 | The software's default (`PW_MAX_TARGETS_PER_TENANT`). |
| scanning-authorisation-and-aup | Acknowledge an abuse report | 2 working days | As proposed. |
| scanning-authorisation-and-aup | Check the audit log for matching scans | 2 working days | As proposed. |
| scanning-authorisation-and-aup | Add a host to the do-not-contact list while traffic continues | 2 working days | The draft proposed 1. One person cannot promise a next-day response. |
| scanning-authorisation-and-aup | Tell the reporter the outcome | 10 working days | As proposed. |
| opt-out | Acknowledge a request | 2 working days | The draft proposed 1. Same reason. |
| opt-out | Add the entry and restart the worker | 2 working days | The draft proposed 1. Same reason. |
| opt-out | Confirm in writing | 3 working days | As proposed. |
| opt-out | Find which customer's scan reached the host | 3 working days | As proposed. |
| opt-out | Tell the customer that its DNS points at someone else's host | 3 working days | As proposed. |
| opt-out | When to write to legal@ if there is no reply | After 5 working days | As proposed. |
| vulnerability-disclosure | Acknowledge a report | 3 working days | As proposed. |
| vulnerability-disclosure | First assessment | 10 working days | As proposed. |
| vulnerability-disclosure | Progress updates | Every 14 days until closed | As proposed. |
| vulnerability-disclosure | Fix for a problem that exposes customer or personal data | 30 days | As proposed. |
| vulnerability-disclosure | Fix for other problems | 90 days | As proposed. |
| vulnerability-disclosure | Time before publication | 90 days | As proposed. |

The three documents say that these are targets, not guarantees, and that the service is run by one person.

### Operator choices that were marked TO DECIDE

| Document | Item | Value adopted | Reasoning |
|---|---|---|---|
| data-retention-policy, privacy-policy, dpa-outline | Retention period | 90 days, one setting for the whole service, not changeable by a customer | This is what the software does (`PW_RETENTION_DAYS=90`). |
| privacy-policy, data-retention-policy, dpa-outline | Audit log retention | 12 months | Long enough to look into a late abuse report, short enough not to keep network addresses for ever. The software does not enforce it yet. |
| data-retention-policy | Alert notices that do not belong to a scan | The retention period | Same rule as other alerts. The software does not enforce it yet. |
| data-retention-policy, terms-of-service, dpa-outline | Closing an account or deleting an organisation | By hand, within 30 days of a request from the account's address. No waiting period. | One person can keep a 30-day limit. A waiting period would need software that does not exist. |
| data-retention-policy | Time to download reports when the operator closes an account | 30 days, not where the account is closed for a serious breach | Matches the notice period. |
| data-retention-policy, scanning-authorisation-and-aup, opt-out, vulnerability-disclosure, privacy-policy | Abuse reports, opt-out requests, security reports, privacy requests | 12 months after the matter is closed | Matches the audit log period. Do-not-contact entries stay for as long as the block. |
| data-retention-policy, dpa-outline | Backups | None today. At most 30 days once backups exist. | Short, so that deleted data does not linger. |
| data-retention-policy, dpa-outline | Key rotation | At least once a year, and at once if a key may have been exposed. The maintainer holds the keys. | A modest schedule that one person can keep. |
| data-retention-policy | Review of the policy | Every 12 months, and when a new category of data is added | Usual interval. |
| privacy-policy | Notice of a change to how staff data is used | 30 days. Switching on a breach data source counts as such a change. | Gives a customer time to tell its staff. |
| terms-of-service | Notice to end the agreement | 30 days | Usual for a free service. |
| terms-of-service | Notice of a change that reduces the customer's rights | 30 days | Same. |
| terms-of-service, dpa-outline | Notice before a new sub-processor | 30 days | Same. |
| privacy-policy, dpa-outline | Who on the operator's side has access | Only the people who run the service. Today that is the maintainer. | Describes the present position as a rule. |
| dpa-outline | Notice of a personal data breach to the controller | 72 hours at the latest | The draft gave 48 hours as an example. 72 is what one person can keep. The lawyer should check it against the controller's own 72-hour duty. See open question 43. |
| dpa-outline | Audit conditions | 30 days' written notice, at most once in twelve months unless there was a breach, each side pays its own costs, confidentiality, done in writing and by inspection of code and configuration | One server and one person: there are no premises to visit. |
| dpa-outline | Independent security review | Planned, no date. A summary of the result will be made available to controllers. | The home page lists the review as waiting for funding. |
| vulnerability-disclosure | Languages | English | The only language the documents are written in. |
| vulnerability-disclosure | Rewards | None | The service is free. |
| vulnerability-disclosure | Host names in scope | `perimeterwatch.org` only | The only host the service runs on. |

## Blanks still to fill

These need the owner. Each has a marker in the documents.

### They depend on the legal entity

1. Legal name of the entity.
2. Legal form of the entity (the service is intended to be non-profit) and its registration details.
3. Jurisdiction where the entity is established.
4. Registered postal address.
5. Governing law, and the courts or arbitration body for disputes.
6. Liability cap amount.
7. Whether a data protection officer is needed, and who.
8. Whether a representative in the EU or the UK is needed, and who.
9. Supervisory authority to name in the privacy policy.
10. Whether any cost recovery or donation model will apply.

### They are facts only the owner knows

11. The provider of the mailbox that the contact addresses are forwarded to (privacy policy 3.5).
12. Which subfinder sources with a key are switched on (privacy policy section 9).
13. How long Resend keeps a record of each message on the plan in use (data retention policy).
14. Monitoring of the service, and a written incident procedure with names and contact details (data processing agreement, Annex A.7).
15. The arrangement with Have I Been Pwned, before any breach data source is switched on (open question 8).

### To check, although no marker remains

16. Whether the server's disk is encrypted. The documents say that the deployment files set up no disk encryption.
17. Whether contracts, including data processing terms, are in place with Hetzner, Resend and Cloudflare.
18. Whether sign-up stays open to any email address (`PW_SIGNUP_OPEN`) while the documents are not in force. See open question 40.
19. The placeholders in [SECURITY.md](../../SECURITY.md): contact address, private reporting, encryption key, response time and supported versions.
20. Each value in "Values adopted by default" above.

## Open questions for the lawyer

Numbers are stable. The documents cite them as "README open question N". Question 16 is closed. Question 18 is closed for the hosted service. Questions 30 to 38 were added in the second version. Questions 39 to 44 were added on 30 September 2026.

### Roles and legal basis

1. **Is the operator really only a processor?** The design says each customer is the controller for data about its own staff and the operator is its processor. But the operator chooses the data sources, the fields collected, which website names are kept from malware logs, and the retention period. A regulator could see the operator as a joint controller or a separate controller for some processing. Which is it, and does the answer differ between breach data, uploaded staff lists and public technical data? See also question 39.
2. **Legitimate interests for breach exposure data.** The customer is expected to rely on GDPR Article 6(1)(f), supported by Recital 49. Is that sound for each customer jurisdiction? Does employment law in any target country require more, for example consultation with a works council or staff representatives?
3. **Sensitive facts in breach data (changed).** The earlier risk was that up to 50 website names per person were stored from malware logs. That has been reduced. Website names are now stored only if they are the organisation's own systems or appear on a fixed list of 19 services that control code, infrastructure or funds. All other sites are reduced to a count, and their names are never stored. The risk that remains:
   - **Breach names are stored in full.** The name of a breach can itself reveal something sensitive, for example a breach of a dating, health or political site where someone signed up with a work address. This is now the main route by which special category data (GDPR Article 9) could reach an employer. The software does not filter breach names.
   - The full list of sites is still received from Have I Been Pwned and handled in memory during the scan, before it is reduced.
   - The count of other sites is stored. A large count tells the employer that a device was used widely for other things.
   - Some services on the fixed list are also used privately (Google accounts, Discord, Telegram, X, Slack). A finding shows that the person had a login there.
   - A malware log finding implies that a device was infected. It may be a personal device.
   Is the remaining processing acceptable? Should breaches that Have I Been Pwned marks as sensitive be left out or shown without their name? No breach data source is switched on today, so this must be answered before one is.
4. **Notice to staff.** Breach data is not collected from the person. GDPR Article 14 requires the controller to inform them. What must the customer tell its staff, when, and should the terms require it?
5. **Data protection impact assessment.** Is an assessment under GDPR Article 35 required for the operator, for the customer, or both?
6. **Blockchain addresses.** Safe owner addresses are read from the public chain and stored without field encryption. Are they personal data in this context? No RPC provider is configured today, so none are read in the hosted service yet.
7. **Former staff and shared mailboxes.** Have I Been Pwned returns every address at the domain. If the organisation supplied a staff list, each finding now says whether the address is on it. Addresses not on the list are still shown. Does the customer's legal basis cover former staff?

### Third-party data and terms

8. **Have I Been Pwned terms.** Unresolved, and recorded as unresolved in `docs/operations.md`. No key is configured in the hosted service today, so the check does not run. The software uses one key for all customers. Have I Been Pwned answers a domain search only for a domain verified inside the account that owns the key. So with one key, breach findings would work only for domains the operator has verified in its own Have I Been Pwned account. Is a hosted service allowed to show results to customers at all? Which arrangement is permitted: one key per customer, or an agreement with Have I Been Pwned? Is the attribution wording sufficient for CC BY 4.0?
9. **Hudson Rock.** Off. No terms are published for the endpoint. Keep it off until written permission exists.
10. **Other sources.** Do the terms of crt.sh, the subfinder sources, the GitHub API, Greenhouse and Lever allow automated use by a hosted service acting for third parties? The same question now applies to the registries' registration record servers (RDAP), the Internet Archive's index, OpenSSF Scorecard, the three phishing blocklists (MetaMask eth-phishing-detect under the DBAD licence, polkadot-js/phishing under Apache-2.0, Phishing.Database under MIT), and, for the command-line tool, npm and PyPI. The software does not use a VirusTotal or SecurityTrails key in a hosted service unless the operator states that its plan allows it.
11. **Cloning public repositories.** The secret scan downloads the organisation's public repositories to a temporary directory and deletes them after the scan. Two scanning tools read them. Any licence or terms issue?
12. **Credentials found that belong to someone else.** Is there any duty to notify anyone other than the customer?

### Scanning and computer misuse law

13. **Does DNS control equal legal authority?** A person who can edit DNS may not have authority to approve security testing. Is the warranty in the terms enough?
14. **Computer misuse laws.** Review probe and active depth against the laws of likely customer and host jurisdictions, for example the UK Computer Misuse Act 1990, the US Computer Fraud and Abuse Act, and national laws implementing EU Directive 2013/40/EU. Active depth now also covers TLS version checks, a reading of what SSH servers offer, zone transfer requests and storage bucket permission checks. The server is in Germany.
15. **Third-party infrastructure.** Hosts under a verified domain often sit on a CDN, cloud or SaaS provider. The engine limits port checks on CDN addresses to ports 80 and 443 but does not exclude them, and does not detect other shared platforms. Who carries the risk if a provider's terms forbid this traffic? See also question 41.
16. **Closed.** Passive depth no longer makes any connection to the organisation's hosts. The MTA-STS policy file is read at probe depth or deeper only.
17. **The typed acknowledgement in the command-line tool.** It lets a user of the command-line tool run active checks without proving domain control. The hosted service ignores it. Does publishing a tool with this feature create liability for the project or its maintainers?
18. **Scans before verification (reworded, closed for the hosted service).** The hosted service now scans a domain only once control of it is proved. This is checked when a scan is requested, by the scheduler, and again when the scan starts. It is a setting (`PW_SCAN_REQUIRES_VERIFICATION`, default on), so the operator could switch it off. What remains: should the terms forbid switching it off? The command-line tool can still run a passive scan of any domain without verification. It makes no connection to that domain's hosts. Does publishing it raise any issue? Sign-up is still open to any email address, but an account can do nothing to a domain it has not verified, apart from adding it to its list.

### Contract and liability

19. **Disclaimers and liability cap.** Are the no-warranty and limitation clauses enforceable for a free, non-profit, business-to-business service in the chosen jurisdiction? No cap amount is set.
20. **Regulated customers.** Some crypto organisations are regulated, for example crypto-asset service providers under MiCA, which fall within the EU Digital Operational Resilience Act (DORA). Will the service accept them, and on what terms?
21. **Sanctions and export controls.** Must the operator screen customers?
22. **Who signs for a DAO.** If the customer has no legal personality, who is the contracting party and the controller?
23. **Findings that suggest a crime or an ongoing compromise.** Is there any duty to report to anyone other than the customer?
24. **Open-source licence.** The software is licensed under Apache-2.0. Confirm that the hosted terms do not conflict with it.

### Retention, deletion and rights

25. **Audit log and erasure.** The audit log is never pruned. The period now chosen is 12 months, but the software does not enforce it. When a domain is deleted, the log keeps an entry with the domain name. Entries made through the web service record the account user's email address, network address and browser identification. How long may the log be kept, and how are erasure requests handled against it?
26. **Current finding state (changed).** Resolved findings are now deleted once they have been resolved for longer than the retention period. Findings that are open, accepted or "not re-checked" are kept until the domain is deleted. See also question 30.
27. **Safe harbour wording.** Does the operator have the authority to make the promises in the vulnerability disclosure policy? Today they are made by an individual. See question 39.
28. **International transfers.** The providers are now known. Stored data is in Germany, at Hetzner Online GmbH. Resend is a US company and sends from Ireland through Amazon SES. Cloudflare, Inc. is a US company and handles mail sent to the contact addresses. The provider of the mailbox that mail is forwarded to is not yet named. Slack, Discord and Telegram are possible recipients of alert text. Which transfer tools are needed for each?
29. **Requests from staff of a customer.** The operator passes requests to the customer. What should the operator do if the customer does not respond or no longer exists? The service still cannot delete or export the records about one person.

### Questions added in the second version

30. **Findings about people after verification is lost (reworded, partly closed).** The hosted service now withholds them. If the domain is not currently verified, opening a finding about a person is refused, and so is downloading a report with personal details shown. This also applies when a second organisation proves control of the domain and the first is displaced. What remains: (a) the stored rows still exist, encrypted, in the first organisation's account; (b) because the breach check no longer runs for that organisation, those findings are never marked resolved, so the retention run never deletes them. They stay until the domain is deleted; (c) lists, scan pages and masked reports still show a masked entry for each such finding, with the first letter of the address, the domain and the name of the breach; (d) findings about credentials in public code are not withheld, because they do not depend on verification. Must the stored rows be deleted when verification is lost, and after how long? Is the masked entry acceptable?
31. **Two organisations, one domain.** If a second organisation proves control of a domain, the first loses its verification. It is told through its alert channels, so an organisation with no alert channel is not told. There is no dispute process. What should happen when both have a real claim, for example an organisation and a security firm it has hired?
32. **No record of acceptance of the terms (changed).** Every page of the service now links to the documents in its footer, and the documents are published at `/legal`. The sign-in page still does not ask a new user to accept the terms or the privacy policy, and nothing records that a user accepted them. How must acceptance be obtained and recorded? See also question 40.
33. **No check of who the account holder is.** An account is created for any email address that can receive the sign-in link. The organisation's name is taken from the domain of that address. Nothing checks that the person acts for an organisation. Is that enough for the warranties in the terms to bind anyone?
34. **Alert providers.** A customer can send alerts to an email address, a Slack or Discord webhook, or a Telegram bot. The customer chooses the channel and supplies its credentials. Alert text holds the domain name, the titles of findings that are not about a person or a credential (these can include host names), counts, and a link. It never holds a person's name or address, a credential or a breach name. Are these providers sub-processors of the operator, or recipients chosen by the controller?
35. **Sign-in data about people without an account.** A sign-in link request stores the email address typed and the requester's network address, even when no account exists. The record is deleted one day after the link expires. Legal basis and notice?
36. **Cookies.** The service sets two cookies: a session cookie at sign-in, and an anti-forgery cookie. The anti-forgery cookie is set on the first visit to any page, including the public home page and the legal pages, and lasts one day. Both are needed for the service to work. No analytics or third-party resources are used. Confirm that no consent is needed under the rules that apply.
37. **Automatic scans (reworded).** A verified domain is scanned every 24 hours by default, at probe depth. A domain that is not verified is never scanned by the hosted service. Verification is re-checked before each scan and once a day. Is standing authorisation through a DNS record enough for repeated probe traffic?
38. **Closing an account.** There is no function to close an account, remove a user or delete an organisation. An account user who asks for erasure can only be served by work on the database. The documents now say this is done by hand within 30 days. What must be built?

### Questions added on 30 September 2026

39. **The operator is an individual.** No legal entity exists. The maintainer runs the service under a pseudonym. Who is the contracting party, the controller and the processor today? What is the maintainer's personal exposure? Can an individual give the safe harbour and sign a data processing agreement? What must happen to accounts and data when the entity takes over?
40. **A live service whose documents are not in force.** Sign-up is open, and the site says that the legal documents are drafts and not yet in force. What governs the use of the service today? Should sign-up be closed (`PW_SIGNUP_OPEN=false`) or a short interim notice be shown until the documents have been reviewed?
41. **Contact with systems outside the domain name.** At probe depth the service sends ordinary DNS questions to the domain's nameservers and to one nameserver of the parent zone. At active depth it asks each nameserver once for a zone transfer, and asks Amazon S3, Google Cloud Storage or DigitalOcean Spaces about a bucket that the domain's DNS points at. These systems usually belong to a provider, not to the customer. The check of the verification record also sends a DNS question to the nameservers, before the domain is verified. Does the customer's authorisation cover this, and what of the providers' terms? The do-not-contact list does not yet cover the bucket check or the verification lookup.
42. **New kinds of stored data.** The contact addresses in a customer's security.txt file are stored, and treated as a finding about a person when the address does not look like a role address. With the command-line tool, account names of package maintainers and the addresses of contract owners and ENS name holders are stored. Are these personal data here, and does the split of roles in question 1 hold for them?
43. **Response times adopted by default.** The documents now promise targets for abuse reports, opt-out requests and vulnerability reports, and notice of a personal data breach to the controller within 72 hours. Are these acceptable, given that controllers have their own 72-hour duty and the service is run by one person?
44. **Server logs.** The proxy logs every request with the network address and the address requested. The logs are limited by size, not by time. The token in the address of a sign-in link is removed before the address is logged. Legal basis and a retention period.

## What must be decided or built

Sign-up is open today. Only the maintainer's own domains are monitored so far. The list below was written as the list of things to settle before any outside organisation is onboarded.

### Decisions

- [ ] The operating entity exists, with a name, jurisdiction and address.
- [ ] Governing law is chosen.
- [x] All contact addresses exist. They are forwarded to the maintainer.
- [x] Hosting and email providers are chosen. No RPC provider is configured.
- [ ] Contracts with the providers are in place.
- [ ] The Have I Been Pwned question (open question 8) is answered in writing.
- [x] Hudson Rock stays off.
- [ ] Whether sign-up stays open, and a rule that `PW_SCAN_REQUIRES_VERIFICATION` is never switched off (open questions 18 and 40).
- [ ] The values adopted by default, including retention periods for the audit log, backups and account data, are reviewed by the owner.
- [ ] A lawyer has reviewed every document.
- [ ] An independent security review of the service has been done.
- [x] The scanner's outbound addresses are fixed and published.
- [ ] A written procedure exists for a breach of the service itself, with names and contact details.
- [ ] Backups are taken, encrypted, and a restore has been tested.
- [x] `/.well-known/security.txt` is served.

### Built since the first draft

- [x] Hosted service: sign-in by emailed link, organisations, roles, web pages, worker.
- [x] Automatic retention, run by the worker at most every six hours.
- [x] Deletion of resolved findings and expired statements of authority by the retention run.
- [x] Do-not-contact list (`PW_NEVER_CONTACT`), honoured by the web probe, TLS handshake, front page and script requests, security.txt request, MTA-STS policy request, port check, exposure checks, TLS version check, SSH check, and the DNS questions and zone transfer requests to nameservers.
- [x] Audit entries for opening a finding about a person or a credential, and for downloading a report.
- [x] Use of the staff list: findings say whether an address is on it.
- [x] Reduction of malware log site names.
- [x] Passive depth makes no connection to the organisation's hosts.
- [x] The hosted service scans only verified domains, at every depth.
- [x] Findings about people are withheld while the domain is not verified.
- [x] Audit entry for automatic retention runs.
- [x] A public page at `/`, with the scan addresses and how to be left alone.
- [x] The documents are published at `/legal`, and every page links to them in its footer.
- [x] CI check for the draft banner (`.github/workflows/ci.yml`, job "Draft banners").
- [x] 34 checks. The documents were brought up to date with them on 30 September 2026.

### Things the software does not do yet

- [ ] **Deleting stored findings about people when verification is lost.** They are withheld from view but not deleted. See open question 30.
- [ ] **Staff list upload in the hosted service.** Only the command-line tool can load a staff list. The web pages have no upload.
- [ ] **Settings for packages, contracts and ENS names in the hosted service.** Only the command-line tool offers them, so those three checks do not run in the hosted service.
- [ ] **Masked entries for withheld findings.** Lists and masked reports still show the breach name and a masked address. See open question 30.
- [ ] **Filtering of breach names.** See open question 3.
- [ ] **Deleting the records about one person**, and excluding one address from future scans.
- [ ] **Export of all of a customer's data.** Reports can be downloaded per scan, as HTML or JSON.
- [ ] **Closing an account, removing a user, deleting an organisation.**
- [ ] **Suspending a domain or an account.** Done by hand in the database.
- [ ] **Inviting colleagues.** Roles exist (owner, member, viewer), but each account has one user, who is the owner.
- [ ] **Asking a new user to accept the terms, and recording it.** The pages link to the documents, and nothing more.
- [ ] **Notices to an organisation with no alert channel.** Loss of verification is announced through alert channels only. The account's own email address is not used unless it was added as a channel.
- [ ] **A separate security contact for each customer.** Breach notices would go to the account owner's address.
- [ ] **Retention of open findings.** Only resolved findings are pruned.
- [ ] **Append-only enforcement.** No page or function edits or removes audit entries, but nothing in the database prevents it.
- [ ] **Retention of the audit log and of alert delivery records that do not belong to a scan.** Periods are chosen, and nothing deletes after them.
- [ ] **Per-organisation encryption keys.** One set of keys protects all customers' data.
- [ ] **Database row-level security.** Separation between customers is enforced in the application only.
- [ ] **Wallet sign-in.**
- [ ] **Identification on all traffic.** HTTP requests made by the engine itself, the web probe and the exposure checks carry the identifying User-Agent. TLS handshakes, port checks, SSH connections and DNS queries cannot carry one. The subdomain tool, the repository scanners and the storage bucket tool use their own.
- [ ] **Backups.** None are taken.

## Known differences between the original design brief and the code

The drafts follow the code.

| Topic | Brief | Code |
|---|---|---|
| Lookalike domains | Found by DNS lookups only. | DNS lookups, a certificate transparency search on crt.sh for the organisation's name, and three public phishing blocklists. Lookalike domains are still never contacted. |
| Contact only with hosts under the domain | No contact with anything outside the domain. | Web requests, TLS handshakes, port checks and SSH connections go only to hosts under the domain. The domain's nameservers, one nameserver of the parent zone and the provider of a storage bucket the domain points at are also contacted. |
| Probe depth | One web request and one TLS handshake per host. | Also the front page and same-host scripts of up to 50 web hosts, the domain's security.txt file, the MTA-STS policy file, and about five DNS questions to each nameserver. |
| Redirects | Never followed. | Not followed by the web probe, the exposure checks or the MTA-STS request. The front page, script and security.txt requests follow a redirect that stays on the same host, at most three times. |
| CDN addresses at active depth | Excluded. | Ports 80 and 443 are still checked on CDN addresses. Other ports are skipped. |
| User-Agent | On all outbound requests. | On HTTP requests from the engine, the web probe and the exposure checks. |
| Audit log | Append-only. | Append-only by convention. Entries survive deletion of a domain. |
| Retention | 90 days by default. | Automatic in the hosted service. The command-line tool needs `pwatch db purge`. The audit log is not pruned. |
| Deleting a domain | Deletes everything stored about it. | Deletes everything except audit log entries. The removal entry records the domain name. |
| Credential findings | Type, file, commit, first four characters, short hash. | Also the line number, the commit date and which scanner found it. Credentials of 12 characters or fewer show no characters at all. |
| Hudson Rock counts | Aggregate counts. | Three counts are read: staff devices, customer devices and third-party devices. |
| TLS handshake | One per host. | One per host on port 443, with one retry if it fails. At active depth, repeated handshakes on up to 50 hosts to list the versions and cipher suites accepted. |
| Verification re-check | Before every active scan. | Before every scan of any depth, and once a day by the worker. |
| Sign-in tokens | Stored only as hashes. | Stored in the database only as hashes. The proxy removes the token from the address of a sign-in link before logging it. |
| Shared cache | 24 hours. | Up to 24 hours. Package provenance records are kept for up to 7 days. |
