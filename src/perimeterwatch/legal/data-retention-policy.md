> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Data retention policy

Status: draft, published for review. The hosted service has been live in beta at https://perimeterwatch.org since 30 September 2026. No lawyer has reviewed this policy, and the service has had no independent security review. The legal documents are drafts under review and are not yet in force. This policy describes what the software does today and marks what is missing.

Last updated: 30 September 2026

"README open question" followed by a number refers to the [list of open questions](https://github.com/erik1o6/perimeterwatch/blob/main/docs/legal/README.md) in the repository.

All stored data is in Germany, on one server at Hetzner Online GmbH in Falkenstein. The database is on that server.

## 1. Terms

- A **scan** is one run of the checks against a domain.
- A **finding** is one result of a scan, such as "this certificate expires in ten days" or "this address appears in that breach".
- **Current finding state** is one record per finding that says whether it is open, accepted, not re-checked or resolved, when it was first seen and when it was last seen. It holds an encrypted copy of the finding.
- The **retention period** is a number of days. It is 90. It is one setting for the whole service. A customer cannot set its own.
- The **retention run** is the job that deletes what is older than the retention period.
- **Cascade** means that when a record is deleted, the database deletes the records that belong to it.

## 2. The rules in short

1. Scans older than the retention period are deleted, with their findings.
2. The most recent completed scan of each domain is always kept, however old it is. Without it, the next scan could not report what changed.
3. A finding that has been resolved for longer than the retention period is deleted from the current finding state.
4. A finding that is open, accepted or not re-checked is kept until the domain is deleted.
5. Deleting a domain deletes everything stored about it, at once, except audit log entries.
6. The audit log is not pruned today. The period we have chosen for it is 12 months.
7. No backups are taken today.

## 3. Table of data categories

### Data about a customer's domain

| Category | What is kept | How long | Why | How it is deleted |
|---|---|---|---|---|
| Domain record | Domain name, GitHub organisation name, wallet addresses, job board name, scan interval, date added | Until the customer deletes the domain | Needed to run scans | Customer deletes the domain |
| Staff list | Work email addresses supplied by the customer. Encrypted. The hosted service holds none today, because only the command-line tool can load one. | Until the customer replaces the list or deletes the domain | To say whether an address in a finding belongs to current staff | Replaced when a new list is loaded. Cascade on domain deletion. |
| Verification record | Token (encrypted), date created, date last verified, date and result of last check, count of failed checks in a row | Until the domain is deleted | Needed to re-check authorisation before each scan and once a day | Cascade on domain deletion |
| Scan record | Depth, authorisation level and its basis, email address of the user who requested it (or "schedule"), times, versions of tools used, error message if it failed | Retention period. The latest completed scan is kept longer. | To show history and compute changes | Retention run. Cascade on domain deletion. |
| Check results per scan | For each check: status, notes, counts, reason if skipped. Notes can name hosts that were not contacted. | Same as the scan | To show which checks ran | Cascade when the scan is deleted |
| Assets per scan | Hostnames, IP addresses, DNS records, certificates, repositories, wallet owner addresses, lookalike domains. Not field-encrypted. | Same as the scan | To compute changes between scans | Cascade when the scan is deleted |
| Findings per scan | Full finding, encrypted. When a breach data source is switched on, this includes breach findings with staff addresses. | Same as the scan | To compute changes and produce reports | Cascade when the scan is deleted |
| Finding history | For each change: new, changed, resolved or reopened, with the kind, severity and date. No personal data in clear. | Same as the scan that produced it | To show when something changed | Cascade when the scan is deleted |
| Current finding state: resolved | One record per finding, with an encrypted copy | Retention period, counted from the date it was resolved | To recognise a finding that comes back | Retention run. Cascade on domain deletion. |
| Current finding state: open, accepted, not re-checked | One record per finding, with an encrypted copy. Can include staff addresses. | Until the finding is resolved and the retention period has passed, or the domain is deleted | To know whether a finding is new | Cascade on domain deletion |
| Alert channels | Kind, label, alert level. The address, webhook address or bot token is encrypted. | Until the customer removes the channel | To send alerts | Customer removes the channel |
| Alert delivery records | Subject and text of each alert, status, number of attempts, short error text. Not encrypted. The text names no person, address, credential or breach. | For an alert about a scan: same as the scan. For other notices, such as loss of verification: the period we have chosen is the retention period, but today they stay until the channel is removed. **[NOT YET BUILT: deleting these notices after the retention period.]** | To retry delivery and show what was sent | Cascade when the scan or the channel is deleted |

### Data about users of the service

| Category | What is kept | How long | Why | How it is deleted |
|---|---|---|---|---|
| Account | Email address, date created, time of last sign-in, role | Life of the account. After a request to close it, it is deleted within 30 days. | Sign-in | **[NOT YET BUILT: closing an account. Done by hand on request.]** |
| Organisation | Name (taken from the domain of the first user's email address), date created | Life of the account | To hold the customer's data apart from others' | **[NOT YET BUILT. Done by hand on request.]** Deleting it cascades to everything the organisation holds, including its audit log. |
| Sign-in link requests | Email address typed, network address, time, hash of the token, time used. Kept even if no account exists for the address. | Until one day after the link expires. A link expires after 15 minutes. | To sign in, and to limit abuse of the form | Housekeeping run |
| Sessions | Hash of the cookie, network address and browser identification at sign-in, times | Until 12 hours without use, or 7 days, or sign-out | To keep a user signed in | Deleted at sign-out, or when next presented after expiry, or by the housekeeping run after 7 days |
| Audit log | Action, user's email address, date, object identifier, network address, browser identification, and a few details such as depth or format. The entry for adding or removing a domain records the domain name. No findings, and no name of any person a finding is about. | The period we have chosen is 12 months. Today the log is not pruned. **[NOT YET BUILT: deletion after 12 months.]** **[LAWYER: see README open question 25.]** | Accountability and investigation of abuse reports | Today, only when the organisation is deleted |

### Other

| Category | What is kept | How long | Why | How it is deleted |
|---|---|---|---|---|
| Shared cache | Answers from slow public sources, stored under a hash of the question asked, with no customer identifier: certificate search results, the web archive's list of matching addresses for a domain, public phishing blocklists, the list of registration record servers, package registry answers, and the public catalogue of breaches. | Up to 24 hours. Package provenance records, which only the command-line tool asks for today: up to 7 days. | To avoid overloading free public services | Housekeeping run |
| Temporary scan files | Downloaded copies of public repositories, target lists for tools, tool settings that include API keys | Only while the scan runs | Needed by the scanning tools | The directory is deleted when the scan ends, whether it succeeded or failed |
| Reports | Not stored by the hosted service. A report is built from the stored scan each time it is downloaded. | Not applicable | | Downloaded copies are the customer's responsibility |
| Do-not-contact list | Host names, addresses or networks that must not be contacted. Held as a setting of the service, not in the database. | Until the operator of the host withdraws the request | To honour opt-out requests | The operator removes the entry |
| Abuse reports, opt-out requests, security reports, privacy requests | The message, our reply, and the action taken. Held outside the service, in the maintainer's mailbox. Mail to our contact addresses is received by Cloudflare and forwarded there. | 12 months after the matter is closed | To show what was done | Deleted by hand |
| Service logs | Operational messages in JSON, from the application, the worker and the proxy. The proxy logs requests, including network addresses and the address requested. Known secrets and common token formats are removed from application logs. The address of a sign-in link contains its token. The proxy removes the token before it writes the address to its log. | Limited by size, not by time: at most five files of 20 MB for each part of the service. | Fault finding | The oldest file is overwritten when the limit is reached |
| Emails sent | Sign-in links and email alerts. A record of each message is held by Resend, the email provider. | **[TO DECIDE: the period for which Resend keeps message records on the plan in use]** | Delivery | By Resend, at the end of that period |
| Backups | None are taken today. This is a gap, not a decision: if the server or its disk is lost, stored data is lost. When backups are introduced, they will cover the database, be encrypted, and be kept apart from the data key, as [docs/operations.md](https://github.com/erik1o6/perimeterwatch/blob/main/docs/operations.md) advises. | None today. When backups exist: at most 30 days. | Recovery | When backups exist: each backup is deleted when it is 30 days old |
| Typed statement of authority (command-line tool only) | Name (encrypted), organisation, role, statement, computer name, login name, dates | Valid for 30 days. Deleted by the retention run once it has been expired for longer than the retention period. | Evidence of who authorised an active scan | Retention run. Cascade on domain deletion. |

## 4. What is never stored

- Passwords, password hashes or any value exposed in a breach.
- The logins captured in a malware log.
- The names of websites in a malware log, other than the organisation's own systems and a fixed list of services that control code, infrastructure or funds. Other sites are counted, and only the count is stored.
- A found credential, beyond its first four characters and a short hash.
- Names and email addresses of people who committed code.
- The records of a DNS zone that a nameserver hands over. Only their number is kept.
- The contents of a script file or a storage bucket. For a script, only a hash is kept.
- Query strings of addresses found in web archives.
- Content fetched from lookalike domains. They are never contacted.
- Registrant details of any domain. Contact details in a registration record are never read.
- Sign-in link tokens and session cookie values, in the database. Only their hashes are stored there.

## 5. The retention run

In the hosted service the worker does this by itself, at most once every six hours. Each time it:

1. removes expired entries from the shared cache;
2. removes sign-in link requests more than one day past expiry, and sessions past their end date;
3. for every organisation that has a domain: deletes scans older than the retention period except the latest completed scan of each domain, deletes findings resolved longer ago than the period, and deletes statements of authority expired longer ago than the period.

Each automatic run writes an audit log entry for each organisation, recorded as done by the system, with the number of scans deleted.

In the command-line tool, nothing runs by itself. The user runs `pwatch db purge`. That command writes an audit log entry with the number of scans deleted.

## 6. Deletion on request

### By the customer

| Request | What happens | When |
|---|---|---|
| Delete a domain | The user types the domain name to confirm. Domain record, staff list, verification record, all scans, all findings, finding history and current finding state are deleted. Audit entries stay. | At once |
| Remove an alert channel | The channel, its stored address or token, and its delivery records are deleted | At once |
| Replace the staff list | The stored list is overwritten | At once. Command-line tool only. **[NOT YET BUILT in the hosted service.]** |
| Delete the account or the organisation | Everything, including the audit log. The request is sent to support@perimeterwatch.org from the account's address. | Within 30 days of the request. There is no waiting period in which the customer can change its mind: once deleted, the data cannot be brought back. **[NOT YET BUILT. Done by hand on request.]** |

### By a member of a customer's staff

The person asks their employer. The employer is the controller and decides. See the [privacy policy](privacy-policy.md), section 13.

The service cannot yet delete the findings about one person only, or leave one address out of future scans. **[NOT YET BUILT.]** Until it can, the customer's option is to delete the domain.

### Limits

- Deletion from the live database is immediate. No backups are taken today, so no copy remains in a backup. Once backups exist, copies will remain in them until each backup expires.
- A finding that is deleted will return at the next scan if the source still reports it.
- Reports that the customer has downloaded are outside the service.
- Alerts already sent to Slack, Discord, Telegram or an inbox are outside the service.

## 7. When verification is lost

If an organisation's verification of a domain is withdrawn, nothing is deleted. The hosted service stops scanning the domain. Findings about people that are already stored are withheld: they cannot be opened, and a report with personal details shown cannot be downloaded. They are never marked resolved, so the retention run does not delete them. They stay, encrypted, until the domain is deleted. Lists still show a masked entry for each.

**[NOT YET BUILT: deleting stored findings about people when verification is lost. LAWYER: see README open question 30.]**

## 8. Deletion on termination

When an account is closed, by the customer or by the operator:

1. Scans stop.
2. If we close the account, the customer may still sign in and download its reports for 30 days, unless we close it for a serious breach of the terms. If the customer asks for closure, it should download its reports first. **[NOT YET BUILT: export of all data.]**
3. All domains and the organisation are deleted. **[NOT YET BUILT: done by hand.]**
4. No backups exist today. Once they do, backups expire within 30 days.
5. The operator keeps: abuse reports about the account, and the minimum record needed to show that the agreement existed and ended. **[LAWYER: what may be kept, and for how long.]**

## 9. Encryption keys

Encryption keys are not customer data, but they affect deletion. If a key is lost, everything encrypted only with that key can no longer be read. Keys can be rotated: a new key is put first in the list and the old key stays in the list for as long as data encrypted with it exists. One set of keys protects all customers' data.

The maintainer holds the keys. The rule we have chosen is to rotate the key at least once a year, and at once if a key may have been exposed.

## 10. Review

This policy is reviewed every 12 months, and whenever a new category of data is added to the software.
