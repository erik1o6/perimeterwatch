> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Legal and policy documents: index

These documents are drafts for the hosted Parapet service.

The hosted service has been built. It is not deployed, no outside organisation uses it, and it has had no independent security review. The same scanning engine is also available as an open-source command-line tool, `parapet`.

The drafts describe what the software does today. Nothing here has been reviewed by a lawyer. Nothing here claims that the service meets any law or standard.

## How to read the markers

| Marker | Meaning |
|---|---|
| **[TO DECIDE: ...]** | A fact that has not been decided, such as the entity name or a contact address. |
| **[TO CONFIRM: ...]** | A proposed value, such as a response time, that the operator must confirm it can keep. |
| **[NOT YET BUILT: ...]** | Something the document needs the service to do that the software does not do today. |
| **[LAWYER: ...]** | A point where legal judgement is needed. |

## The documents

| File | What it is | Who reads it |
|---|---|---|
| [terms-of-service.md](terms-of-service.md) | The agreement between the operator and a customer organisation. | Customers |
| [privacy-policy.md](privacy-policy.md) | What personal data is handled, why, and what rights people have. | Customers, their staff, the public |
| [dpa-outline.md](dpa-outline.md) | Outline of a data processing agreement under GDPR Article 28. | Customers, lawyers |
| [scanning-authorisation-and-aup.md](scanning-authorisation-and-aup.md) | What domain verification authorises, the three scan depths, prohibited uses, abuse reports. | Customers, operators of scanned hosts |
| [data-retention-policy.md](data-retention-policy.md) | What is kept, for how long, and how it is deleted. | Customers, lawyers |
| [vulnerability-disclosure.md](vulnerability-disclosure.md) | How to report a security problem in the service itself. | Security researchers |
| [security.txt](security.txt) | RFC 9116 file. The bundled proxy serves this exact file at `/.well-known/security.txt`. | Security researchers, automated tools |
| [opt-out.md](opt-out.md) | How the operator of a host that received traffic can make it stop. | Operators of scanned hosts |
| [legitimate-interest-assessment.md](legitimate-interest-assessment.md) | A template a customer can adapt for its own records. | Customers' privacy or security leads |
| [../../SECURITY.md](../../SECURITY.md) | How to report a vulnerability in the open-source software. | Developers, researchers |

Related technical documents, which these drafts rely on: `docs/architecture.md`, `docs/operations.md`, `deploy/env.reference.md`.

## Blanks that must be filled

1. Legal name of the operating entity.
2. Legal form of the entity (the service is intended to be non-profit) and its registration details.
3. Jurisdiction where the entity is established.
4. Governing law and the courts or arbitration body for disputes.
5. Registered postal address.
6. Public URL of the hosted service (`PARAPET_BASE_URL`, `SITE_ADDRESS`).
7. Contact addresses: privacy, security reports, abuse reports, legal notices, general support.
8. The contact URL and abuse address placed in the User-Agent (`PARAPET_CONTACT_URL`, `PARAPET_ABUSE_EMAIL`). Outside development mode the web service refuses to start without an abuse address. The contact URL still defaults to the project's GitHub page.
9. The fixed address or addresses that scan traffic comes from, to be published.
10. Name and location of the hosting provider.
11. Name and location of the email (SMTP) provider.
12. Name and location of the Ethereum RPC provider.
13. Which subfinder sources will be switched on (the engine supports keys for VirusTotal, SecurityTrails, Cert Spotter, Chaos and GitHub).
14. Whose Have I Been Pwned key the service uses (see open question 8).
15. Whether Hudson Rock is ever switched on.
16. Whether sign-up stays open to any email address (`PARAPET_SIGNUP_OPEN`, default open).
17. Data storage region or regions.
18. Transfer mechanism for any transfer outside the EEA or UK, including to alert providers.
19. Whether an EU or UK representative, or a data protection officer, is appointed, and their contact details.
20. Supervisory authority to name in the privacy policy.
21. Liability cap amount.
22. Notice periods: changes to terms, termination, new sub-processors.
23. Backup retention period and how backups are deleted.
24. Retention period for the audit log.
25. Retention period for account data after an account is closed, and for alert delivery records.
26. Response times in the opt-out, abuse and vulnerability disclosure documents (proposed values are marked **[TO CONFIRM]**).
27. Breach notification period offered to customers in the data processing agreement.
28. Who may open an account for an organisation, and how acceptance of the terms is recorded.
29. Supported versions of the software, for SECURITY.md.
30. PGP key or other encryption method for security reports, if any.
31. Languages in which reports are accepted.
32. Who holds the data encryption keys and how often they are rotated.

## Open questions for the lawyer

Numbers are kept from the previous version of this list so that earlier references still work. Question 16 is closed. Question 18 is closed for the hosted service. Questions 30 to 38 were added in the second version.

### Roles and legal basis

1. **Is the operator really only a processor?** The design says each customer is the controller for data about its own staff and the operator is its processor. But the operator chooses the data sources, the fields collected, which website names are kept from malware logs, and the retention defaults. A regulator could see the operator as a joint controller or a separate controller for some processing. Which is it, and does the answer differ between breach data, uploaded staff lists and public technical data?
2. **Legitimate interests for breach exposure data.** The customer is expected to rely on GDPR Article 6(1)(f), supported by Recital 49. Is that sound for each customer jurisdiction? Does employment law in any target country require more, for example consultation with a works council or staff representatives?
3. **Sensitive facts in breach data (changed).** The earlier risk was that up to 50 website names per person were stored from malware logs. That has been reduced. Website names are now stored only if they are the organisation's own systems or appear on a fixed list of 19 services that control code, infrastructure or funds. All other sites are reduced to a count, and their names are never stored. The risk that remains:
   - **Breach names are stored in full.** The name of a breach can itself reveal something sensitive, for example a breach of a dating, health or political site where someone signed up with a work address. This is now the main route by which special category data (GDPR Article 9) could reach an employer. The software does not filter breach names.
   - The full list of sites is still received from Have I Been Pwned and handled in memory during the scan, before it is reduced.
   - The count of other sites is stored. A large count tells the employer that a device was used widely for other things.
   - Some services on the fixed list are also used privately (Google accounts, Discord, Telegram, X, Slack). A finding shows that the person had a login there.
   - A malware log finding implies that a device was infected. It may be a personal device.
   Is the remaining processing acceptable? Should breaches that Have I Been Pwned marks as sensitive be left out or shown without their name?
4. **Notice to staff.** Breach data is not collected from the person. GDPR Article 14 requires the controller to inform them. What must the customer tell its staff, when, and should the terms require it?
5. **Data protection impact assessment.** Is an assessment under GDPR Article 35 required for the operator, for the customer, or both?
6. **Blockchain addresses.** Safe owner addresses are read from the public chain and stored without field encryption. Are they personal data in this context?
7. **Former staff and shared mailboxes.** Have I Been Pwned returns every address at the domain. If the organisation supplied a staff list, each finding now says whether the address is on it. Addresses not on the list are still shown. Does the customer's legal basis cover former staff?

### Third-party data and terms

8. **Have I Been Pwned terms.** Unresolved, and recorded as unresolved in `docs/operations.md`. The service uses one key for all customers. Have I Been Pwned answers a domain search only for a domain verified inside the account that owns the key. So today breach findings work only for domains the operator has verified in its own Have I Been Pwned account. Is a hosted service allowed to show results to customers at all? Which arrangement is permitted: one key per customer, or an agreement with Have I Been Pwned? Is the attribution wording sufficient for CC BY 4.0?
9. **Hudson Rock.** Off by default. No terms are published for the endpoint. Keep it off until written permission exists.
10. **Other sources.** Do the terms of crt.sh, the subfinder sources, the GitHub API, Greenhouse and Lever allow automated use by a hosted service acting for third parties?
11. **Cloning public repositories.** The secret scan downloads the organisation's public repositories to a temporary directory and deletes them after the scan. Any licence or terms issue?
12. **Credentials found that belong to someone else.** Is there any duty to notify anyone other than the customer?

### Scanning and computer misuse law

13. **Does DNS control equal legal authority?** A person who can edit DNS may not have authority to approve security testing. Is the warranty in the terms enough?
14. **Computer misuse laws.** Review probe and active depth against the laws of likely customer and host jurisdictions, for example the UK Computer Misuse Act 1990, the US Computer Fraud and Abuse Act, and national laws implementing EU Directive 2013/40/EU.
15. **Third-party infrastructure.** Hosts under a verified domain often sit on a CDN, cloud or SaaS provider. The engine limits port checks on CDN addresses to ports 80 and 443 but does not exclude them, and does not detect other shared platforms. Who carries the risk if a provider's terms forbid this traffic?
16. **Closed.** Passive depth no longer makes any connection to the organisation's hosts. The MTA-STS policy file is read at probe depth or deeper only.
17. **The typed acknowledgement in the command-line tool.** It lets a user of the command-line tool run active checks without proving domain control. The hosted service ignores it. Does publishing a tool with this feature create liability for the project or its maintainers?
18. **Scans before verification (reworded, closed for the hosted service).** The hosted service now scans a domain only once control of it is proved. This is checked when a scan is requested, by the scheduler, and again when the scan starts. It is a setting (`PARAPET_SCAN_REQUIRES_VERIFICATION`, default on), so the operator could switch it off. What remains: should the terms forbid switching it off? The command-line tool can still run a passive scan of any domain without verification. It makes no connection to that domain's hosts. Does publishing it raise any issue? Sign-up is still open to any email address, but an account can do nothing to a domain it has not verified, apart from adding it to its list.

### Contract and liability

19. **Disclaimers and liability cap.** Are the no-warranty and limitation clauses enforceable for a free, non-profit, business-to-business service in the chosen jurisdiction?
20. **Regulated customers.** Some crypto organisations are regulated, for example crypto-asset service providers under MiCA, which fall within the EU Digital Operational Resilience Act (DORA). Will the service accept them, and on what terms?
21. **Sanctions and export controls.** Must the operator screen customers?
22. **Who signs for a DAO.** If the customer has no legal personality, who is the contracting party and the controller?
23. **Findings that suggest a crime or an ongoing compromise.** Is there any duty to report to anyone other than the customer?
24. **Open-source licence.** The software is licensed under Apache-2.0. Confirm that the hosted terms do not conflict with it.

### Retention, deletion and rights

25. **Audit log and erasure.** The audit log is never pruned. When a domain is deleted, the log keeps an entry with the domain name. Entries made through the web service record the account user's email address, network address and browser identification. How long may the log be kept, and how are erasure requests handled against it?
26. **Current finding state (changed).** Resolved findings are now deleted once they have been resolved for longer than the retention period. Findings that are open, accepted or "not re-checked" are kept until the domain is deleted. See also question 30.
27. **Safe harbour wording.** Does the entity have the authority to make the promises in the vulnerability disclosure policy?
28. **International transfers.** Once providers and regions are chosen, which transfer tools are needed? Slack, Discord and Telegram are now possible recipients of alert text.
29. **Requests from staff of a customer.** The operator passes requests to the customer. What should the operator do if the customer does not respond or no longer exists? The service still cannot delete or export the records about one person.

### New questions

30. **Findings about people after verification is lost (reworded, partly closed).** The hosted service now withholds them. If the domain is not currently verified, opening a finding about a person is refused, and so is downloading a report with personal details shown. This also applies when a second organisation proves control of the domain and the first is displaced. What remains: (a) the stored rows still exist, encrypted, in the first organisation's account; (b) because the breach check no longer runs for that organisation, those findings are never marked resolved, so the retention run never deletes them. They stay until the domain is deleted; (c) lists, scan pages and masked reports still show a masked entry for each such finding, with the first letter of the address, the domain and the name of the breach; (d) findings about credentials in public code are not withheld, because they do not depend on verification. Must the stored rows be deleted when verification is lost, and after how long? Is the masked entry acceptable?
31. **Two organisations, one domain.** If a second organisation proves control of a domain, the first loses its verification. It is told through its alert channels, so an organisation with no alert channel is not told. There is no dispute process. What should happen when both have a real claim, for example an organisation and a security firm it has hired?
32. **No record of acceptance of the terms.** The sign-in page does not show or link to the terms or the privacy policy, and nothing records that a user accepted them. How must acceptance be obtained and recorded?
33. **No check of who the account holder is.** An account is created for any email address that can receive the sign-in link. The organisation's name is taken from the domain of that address. Nothing checks that the person acts for an organisation. Is that enough for the warranties in the terms to bind anyone?
34. **Alert providers.** A customer can send alerts to an email address, a Slack or Discord webhook, or a Telegram bot. The customer chooses the channel and supplies its credentials. Alert text holds the domain name, the titles of findings that are not about a person or a credential (these can include host names), counts, and a link. It never holds a person's name or address, a credential or a breach name. Are these providers sub-processors of the operator, or recipients chosen by the controller?
35. **Sign-in data about people without an account.** A sign-in link request stores the email address typed and the requester's network address, even when no account exists. The record is deleted one day after the link expires. Legal basis and notice?
36. **Cookies.** The service sets two cookies: a session cookie and an anti-forgery cookie. Both are needed for the service to work. No analytics or third-party resources are used. Confirm that no consent is needed under the rules that apply.
37. **Automatic scans (reworded).** A verified domain is scanned every 24 hours by default, at probe depth. A domain that is not verified is never scanned by the hosted service. Verification is re-checked before each scan and once a day. Is standing authorisation through a DNS record enough for repeated probe traffic?
38. **Closing an account.** There is no function to close an account, remove a user or delete an organisation. An account user who asks for erasure can only be served by work on the database. What must be built before launch?

## What must be decided or built before any outside organisation is onboarded

### Decisions

- [ ] The operating entity exists, with a name, jurisdiction and address.
- [ ] Governing law is chosen.
- [ ] All contact addresses exist and are monitored.
- [ ] Hosting, email and RPC providers are chosen, and contracts with them are in place.
- [ ] The Have I Been Pwned question (open question 8) is answered in writing.
- [ ] Hudson Rock stays off, or written permission is held.
- [ ] Whether sign-up stays open, and a rule that `PARAPET_SCAN_REQUIRES_VERIFICATION` is never switched off (open question 18).
- [ ] Retention periods for the audit log, backups and account data.
- [ ] A lawyer has reviewed every document in this directory.
- [ ] An independent security review of the service has been done.
- [ ] The scanner's outbound address is fixed and published.
- [ ] A written procedure exists for a breach of the service itself, with names and contact details.
- [ ] The placeholders in `security.txt` are replaced. The proxy serves the file as it is.

### Built since the first draft

- [x] Hosted service: sign-in by emailed link, organisations, roles, web pages, worker.
- [x] Automatic retention, run by the worker at most every six hours.
- [x] Deletion of resolved findings and expired statements of authority by the retention run.
- [x] Do-not-contact list (`PARAPET_NEVER_CONTACT`), honoured by every check that contacts hosts: web probe, TLS, MTA-STS policy request, port and exposure checks.
- [x] Audit entries for opening a finding about a person or a credential, and for downloading a report.
- [x] Use of the staff list: findings say whether an address is on it.
- [x] Reduction of malware log site names.
- [x] Passive depth makes no connection to the organisation's hosts.
- [x] The hosted service scans only verified domains, at every depth.
- [x] Findings about people are withheld while the domain is not verified.
- [x] Audit entry for automatic retention runs.

### Things the software does not do yet

- [ ] **Deleting stored findings about people when verification is lost.** They are withheld from view but not deleted. See open question 30.
- [ ] **Staff list upload in the hosted service.** Only the command-line tool can load a staff list. The web pages have no upload.
- [ ] **Masked entries for withheld findings.** Lists and masked reports still show the breach name and a masked address. See open question 30.
- [ ] **Filtering of breach names.** See open question 3.
- [ ] **Deleting the records about one person**, and excluding one address from future scans.
- [ ] **Export of all of a customer's data.** Reports can be downloaded per scan, as HTML or JSON.
- [ ] **Closing an account, removing a user, deleting an organisation.**
- [ ] **Inviting colleagues.** Roles exist (owner, member, viewer), but each account has one user, who is the owner.
- [ ] **Showing and recording acceptance of the terms.** The pages do not link to these documents.
- [ ] **Notices to an organisation with no alert channel.** Loss of verification is announced through alert channels only. The account's own email address is not used unless it was added as a channel.
- [ ] **Retention of open findings.** Only resolved findings are pruned.
- [ ] **Append-only enforcement.** No page or function edits or removes audit entries, but nothing in the database prevents it.
- [ ] **Retention of the audit log and of alert delivery records that do not belong to a scan.**
- [ ] **Per-organisation encryption keys.** One set of keys protects all customers' data.
- [ ] **Database row-level security.** Separation between customers is enforced in the application only.
- [ ] **Wallet sign-in.**
- [ ] **Identification on all traffic.** HTTP requests made by the engine itself, the web probe and the exposure checks carry the identifying User-Agent. TLS handshakes, port checks and DNS queries cannot carry one. The subdomain tool and the repository scanner use their own.
- [ ] **CI check** for the draft banner. `security.txt` is plain text, so its banner is a `#` comment. The check must accept that form.

## Known differences between the original design brief and the code

The drafts follow the code.

| Topic | Brief | Code |
|---|---|---|
| Lookalike domains | Found by DNS lookups only. | DNS lookups, plus a certificate transparency search on crt.sh for the organisation's name. Lookalike domains are still never contacted. |
| CDN addresses at active depth | Excluded. | Ports 80 and 443 are still checked on CDN addresses. Other ports are skipped. |
| User-Agent | On all outbound requests. | On HTTP requests from the engine, the web probe and the exposure checks. |
| Audit log | Append-only. | Append-only by convention. Entries survive deletion of a domain. |
| Retention | 90 days by default. | Automatic in the hosted service. The command-line tool needs `parapet db purge`. The audit log is not pruned. |
| Deleting a domain | Deletes everything stored about it. | Deletes everything except audit log entries. The removal entry records the domain name. |
| Credential findings | Type, file, commit, first four characters, short hash. | Also the line number and the commit date. Credentials of 12 characters or fewer show no characters at all. |
| Hudson Rock counts | Aggregate counts. | Three counts are read: staff devices, customer devices and third-party devices. |
| TLS handshake | One per host. | One per host on port 443, with one retry if it fails. |
| Verification re-check | Before every active scan. | Before every scan of any depth, and once a day by the worker. |
