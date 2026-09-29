> Draft for review and editing. Not yet submitted.

# Risks

Each risk is given with what is done about it and what remains unsolved. The unsolved parts are stated so that a reviewer finds them here and not later.

## Summary

| # | Risk | Mitigation in place today | Still unsolved |
|---|---|---|---|
| 1 | Breach data cannot be used by a hosted service in the way planned | Own-key use works in the command-line tool | Terms for a hosted service are unconfirmed |
| 2 | The software is misused for reconnaissance | The web service scans only domains whose control is proved. Active checks and personal detail need authorisation everywhere. | Passive scans of any domain are possible with the command-line tool |
| 3 | The hosted service is itself breached | Encryption of stored findings, no secrets stored, organisations kept apart, alerts carry no detail | No independent review yet. Never deployed. |
| 4 | Single maintainer | Open source, tested, documented | No second maintainer named |
| 5 | Scanning hosts the organisation does not own | Low request volume, read-only, do-not-contact list, limited port checks on content delivery networks | Other shared platforms are not detected |
| 6 | A typed statement of authority is false | The web service does not accept typed statements | Remains possible in the command-line tool |
| 7 | The adoption milestone is missed | Conservative targets, early outreach | Half of the grant is at risk |
| 8 | False comfort from a clean report | The report says what it is not | Readers may still over-trust it |
| 9 | Personal data and legal exposure | Minimal data, organisation supplies staff list, site names in malware logs reduced to a count, views logged | No legal review yet |
| 10 | No funding after the grant | Low running cost | No confirmed plan |
| 11 | The verification record reveals that an organisation uses the service | None | Inherent in DNS verification |

## 1. Breach data for a hosted service

**The risk.** The check for breached staff accounts uses Have I Been Pwned. Its domain search returns results only for domains that have been added and verified in the account that owns the API key. A hosted service with one key cannot search the domains of many organisations unless each domain is verified in that one account, and unless the plan permits use on behalf of others.

**What is known.** Checked on the Have I Been Pwned website on 29 September 2026:

- The Core plans are described as intended for domains the subscriber controls, and do not permit use on behalf of third parties.
- The Pro plans include monitoring of customer domains for managed service providers, bulk enrolment of domains, and access to malware log data. Pro 1 costs $379 per month and covers up to 50 domains.
- Malware log data is not available on Core plans.

Sources: [HIBP subscription page](https://haveibeenpwned.com/Subscription), [HIBP API documentation](https://haveibeenpwned.com/API/v3).

**Mitigation.** Two routes are planned.

1. Each organisation brings its own key. This works today in the command-line tool. The web service today reads one key for the whole service, so a key for each organisation would have to be built. It also needs confirmation that an organisation may use its own key through a third party's service.
2. The service holds a Pro plan and enrols each organisation's domain. This needs confirmation of how each domain is verified and whether a non-profit service qualifies.

**Unsolved.** Neither route is confirmed. An email to Have I Been Pwned is needed. **[TODO: send it before submitting and record the date and the answer here. Questions to ask: (a) may an organisation use its own Core key through a hosted third-party service that it has authorised; (b) does a free, non-profit monitoring service qualify for the customer domain feature of the Pro plans; (c) how is each customer domain verified; (d) is there a rate for non-profit or open-source projects.]**

**If the answer is no.** The breach check is removed from the hosted service and stays in the command-line tool, where each organisation uses its own key. The other checks are unaffected. Milestone 1 has a pass criterion that requires the written answer.

**A second source.** The code includes a lookup against Hudson Rock that returns counts only. It is switched off by default, because Hudson Rock publishes no terms for that endpoint. The hosted service will not use it without written permission.

## 2. Misuse for reconnaissance

**The risk.** An attacker uses the tool to map a target.

**Mitigation.**

- A passive scan reads only records that are already public. The same information is available through existing free tools. Parapet adds convenience and no new capability.
- A probe scan sends one ordinary web request and one TLS handshake per host, which is less than a single visit by a browser.
- Open ports, exposure checks and per-person breach detail require authorisation. Proof of domain control is checked again before every active scan.
- There is no flag that skips authorisation. The tests for this are in `tests/security/`.
- The exposure checks admit only read-only templates. The rules are fixed in code.
- The web service scans a domain only once control of it is proved. A request for a scan is refused, the scheduler skips unverified domains, and the worker checks again when the scan starts. This is built, tested, and on by default.
- The web service accepts proof of domain control only. It ignores typed statements of authority. This is built.
- Only one organisation at a time can hold verification of a domain. This is built.
- A passive scan makes no connection to the organisation's hosts; DNS records are read through public resolvers.

**Unsolved.** The command-line tool. Anyone can run it on their own machine against any domain at passive depth, without verification. The project cannot prevent this. The rule in the web service is a setting, and a person who runs their own copy of the service can switch it off.

The code is open source, so anyone can also alter it to remove the authorisation check for active scans. This cannot be prevented in open-source software. The position of the project is that the passive information is public already, and that a person willing to alter the code could as easily use the underlying tools directly.

## 3. The hosted service becomes a target

**The risk.** The hosted service would hold a list of weak points for many crypto organisations. A breach of the service would hand that list to an attacker.

**Mitigation.**

- Findings are encrypted before they are written to the database. This is built.
- Secrets found in repositories are never stored. Only type, location, first four characters and a short hash are kept. This is built.
- Passwords from breaches are never received or stored. This is built.
- Old scans and resolved findings are deleted automatically after a retention period, 90 days by default. This is built.
- Organisations are kept apart. Every query is limited to the signed-in organisation, and a set of tests tries every route as a different organisation. This is built.
- There are no passwords. Sign-in is by emailed link, and tokens are stored only as hashes. This is built.
- Pages contain no JavaScript, so the browser is told to refuse all scripts. This is built.
- Alerts never carry names, addresses or credentials. A breach of an email or chat account therefore reveals that something changed and not what. This is built.
- Each view of a finding about a person and each report download is written to an audit log. This is built.
- The deployment files put the database on a network with no route to the internet, and give the worker its own network. These files are written and have never been run.
- An independent security review is a pass criterion of Milestone 2. No organisation outside the team is onboarded before it passes. This is a pass criterion of Milestone 1.
- An organisation that does not want its findings held by anyone can run the command-line tool on its own machine.

**Unsolved.**

- The web service has never been deployed and nobody outside the team has reviewed it. Tests written by the author of the code show what the author thought to test.
- Separation of organisations is enforced in the application only. A second barrier in the database (row-level security) is not built. It is a pass criterion of Milestone 1.
- Hostnames, scan history and the audit log are not encrypted in the database. Only finding bodies, staff lists, verification tokens and alert settings are.
- The audit log is never pruned, and nothing in the database prevents an entry being altered.
- Encryption of stored data protects against theft of the database. It does not protect against an attacker who takes over the running service, which holds the keys.
- A review is a snapshot. The service needs a review every year, and the cost after the grant is not yet covered. See risk 10.
- **[TODO: decide whether the design should go further, for example by encrypting each organisation's findings with a key that only the organisation holds. This would limit what the service can do with the data, including sending alerts that describe the finding.]**

## 4. Single maintainer

**The risk.** the maintainer is the only maintainer. If he is unavailable, scans stop, alerts stop, and security fixes are not made.

**Mitigation.**

- The code is licensed under Apache-2.0 and has 543 automated tests. It is not yet published.
- Deployment and operation are documented in `docs/operations.md`, so that another person could run the service.
- External tools are pinned by version and checksum, so the software does not change without a person acting.
- Organisations can export their reports as JSON and run the command-line tool themselves.

**Unsolved.** There is no second maintainer today. **[TODO: state the plan, consistent with the option chosen in `04-team.md`. Also state who has access to the hosting account, the domain and the encryption keys if you are unavailable, and what organisations are told if the service must be shut down.]**

## 5. Hosts on shared infrastructure

**The risk.** A subdomain often points at infrastructure the organisation does not own: a content delivery network, a hosted documentation site, a shop platform. A port scan or exposure check against that host touches a third party's systems. The organisation's authorisation does not cover them.

**Mitigation.**

- Passive scans contact nothing.
- A probe scan sends one ordinary request per host, which is normal use of any public website.
- Active scans use ordinary connection attempts to 100 ports at a limited rate, and read-only requests.
- Every request identifies the tool and gives a contact address for complaints.
- Hosts that resolve to private or reserved addresses are never contacted.
- At most 500 hosts are contacted per scan.
- Hosts behind a content delivery network are skipped by the port check apart from ports 80 and 443.
- A do-not-contact list holds hosts, addresses and networks that no scan will contact, whatever domain they appear under. When the operator of a host asks for scans to stop, the host is added to this list.
- In the web service, scheduled scans go no deeper than probe. An active scan runs only when a person asks for it.

**Unsolved.** Shared platforms other than content delivery networks, such as hosted documentation or shop platforms, are not detected. The exposure checks still run against hosts behind a content delivery network. The do-not-contact list acts after a complaint and not before. Some providers forbid scanning in their terms even at low volume.

## 6. False statements of authority

**The risk.** The command-line tool accepts a typed statement, "I am authorised to test <domain>", as sufficient for active checks. A person can type a false statement.

**Mitigation.** The statement is recorded with name, role, organisation, machine and time, protected against alteration, and expires after 30 days. It never unlocks per-person breach detail. The report states that domain control was not proven.

The web service does not accept typed statements. It accepts proof of domain control only. This is decided and built.

**Unsolved.** In the command-line tool, a record of a false statement does not stop the scan. The person running the tool does so from their own machine and network, and answers for it.

## 7. The adoption milestone is missed

**The risk.** Half of the grant depends on N organisations using the service for 60 consecutive days and fixing problems. Small teams are busy and security work is easy to postpone.

**Mitigation.** Conservative values for N and M. Outreach starts during Milestone 1 so that organisations are waiting when Milestone 2 passes. Onboarding needs one DNS record and no software. See `09-adoption-plan.md`.

**Unsolved.** No organisation has committed yet. **[TODO: correct this if any has.]** The project carries the financial loss if the milestone fails.

## 8. False comfort

**The risk.** An organisation reads a report with few findings and concludes that it is safe.

**Mitigation.** The report states: "It is not a penetration test or an audit, and it gives no overall score. An area with no findings is not proven safe." There is no score to quote.

**Unsolved.** People may still treat a clean report as a clean bill of health, or show it to others as one.

## 9. Personal data and legal exposure

**The risk.** Staff email addresses and their presence in breaches are personal data. Port scanning is treated differently in different countries.

**Mitigation.** The staff list is supplied by the organisation, which has the relationship with its staff. No data about individuals is collected from social media. Per-person detail requires proof of domain control. Reports can be produced with personal details masked. Lists in the web service mask names and addresses, and each view of a finding about a person is logged. For malware logs, only the organisation's own systems and a fixed list of critical services are named. All other sites are reduced to a count, because which sites a person has logins for can reveal private matters.

**Unsolved.** No lawyer has reviewed the project. Draft documents exist in `docs/legal/`, with a list of open questions for a lawyer. Legal review is a pass criterion of Milestone 2. Breach data includes former staff and shared mailboxes. The staff list tells them apart and does not remove them. **[TODO: state the jurisdiction of the entity and of the hosting, since both affect which rules apply.]**

## 10. Funding after the grant

**The risk.** The service stops when the grant ends.

**Mitigation.** Running costs are low in comparison with the build cost. They are listed in `05-milestones-budget.md`. The open-source software continues to work if the hosted service closes, and an organisation can run either form of it itself.

**Unsolved.** **[TODO: there is no confirmed plan. State the intended one.]**

## 11. The verification record is public

**The risk.** The DNS record that proves domain control is visible to anyone. It shows that the organisation uses Parapet. An attacker learns that this organisation is being monitored, and that the hosted service holds data about it.

**Mitigation.** None today.

**Unsolved.** This is a property of verification by DNS, which many services use. An organisation that does not want to reveal its use of the service can run the command-line tool itself. **[TODO: consider whether the record name should be generic. The cost is that the adoption reviewer can then no longer confirm use from the DNS record alone.]**
