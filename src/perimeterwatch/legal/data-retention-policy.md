> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Data retention policy

Status: draft for the hosted service, which has been built but is not yet deployed. It describes what the software does today and marks what is missing.

## 1. Terms

- A **scan** is one run of the checks against a domain.
- A **finding** is one result of a scan, such as "this address appears in that breach".
- **Current finding state** is one record per finding that says whether it is open, accepted, not re-checked or resolved, when it was first seen and when it was last seen. It holds an encrypted copy of the finding.
- The **retention period** is a number of days. The default is 90. It is one setting for the whole service. **[TO DECIDE: the period, and whether each customer can set its own.]**
- The **retention run** is the job that deletes what is older than the retention period.
- **Cascade** means that when a record is deleted, the database deletes the records that belong to it.

## 2. The rules in short

1. Scans older than the retention period are deleted, with their findings.
2. The most recent completed scan of each domain is always kept, however old it is. Without it, the next scan could not report what changed.
3. A finding that has been resolved for longer than the retention period is deleted from the current finding state.
4. A finding that is open, accepted or not re-checked is kept until the domain is deleted.
5. Deleting a domain deletes everything stored about it, at once, except audit log entries.
6. The audit log is not pruned.

## 3. Table of data categories

### Data about a customer's domain

| Category | What is kept | How long | Why | How it is deleted |
|---|---|---|---|---|
| Domain record | Domain name, GitHub organisation name, wallet addresses, job board name, scan interval, date added | Until the customer deletes the domain | Needed to run scans | Customer deletes the domain |
| Staff list | Work email addresses supplied by the customer. Encrypted. | Until the customer replaces the list or deletes the domain | To say whether an address in a finding belongs to current staff | Replaced when a new list is loaded. Cascade on domain deletion. |
| Verification record | Token (encrypted), date created, date last verified, date and result of last check, count of failed checks in a row | Until the domain is deleted | Needed to re-check authorisation before each scan and once a day | Cascade on domain deletion |
| Scan record | Depth, authorisation level and its basis, email address of the user who requested it (or "schedule"), times, versions of tools used, error message if it failed | Retention period. The latest completed scan is kept longer. | To show history and compute changes | Retention run. Cascade on domain deletion. |
| Check results per scan | For each check: status, notes, counts, reason if skipped. Notes can name hosts that were not contacted. | Same as the scan | To show which checks ran | Cascade when the scan is deleted |
| Assets per scan | Hostnames, IP addresses, DNS records, certificates, repositories, wallet owner addresses, lookalike domains. Not field-encrypted. | Same as the scan | To compute changes between scans | Cascade when the scan is deleted |
| Findings per scan | Full finding, encrypted. Includes breach findings with staff addresses. | Same as the scan | To compute changes and produce reports | Cascade when the scan is deleted |
| Finding history | For each change: new, changed, resolved or reopened, with the kind, severity and date. No personal data in clear. | Same as the scan that produced it | To show when something changed | Cascade when the scan is deleted |
| Current finding state: resolved | One record per finding, with an encrypted copy | Retention period, counted from the date it was resolved | To recognise a finding that comes back | Retention run. Cascade on domain deletion. |
| Current finding state: open, accepted, not re-checked | One record per finding, with an encrypted copy. Can include staff addresses. | Until the finding is resolved and the retention period has passed, or the domain is deleted | To know whether a finding is new | Cascade on domain deletion |
| Alert channels | Kind, label, alert level. The address, webhook address or bot token is encrypted. | Until the customer removes the channel | To send alerts | Customer removes the channel |
| Alert delivery records | Subject and text of each alert, status, number of attempts, short error text. Not encrypted. The text names no person, address, credential or breach. | For an alert about a scan: same as the scan. For other notices, such as loss of verification: until the channel is removed. **[TO DECIDE: a period for these. NOT YET BUILT: deleting them after it.]** | To retry delivery and show what was sent | Cascade when the scan or the channel is deleted |

### Data about users of the service

| Category | What is kept | How long | Why | How it is deleted |
|---|---|---|---|---|
| Account | Email address, date created, time of last sign-in, role | Life of the account, then **[TO DECIDE: period after closure]** | Sign-in | **[NOT YET BUILT: closing an account. Done by hand on request.]** |
| Organisation | Name (taken from the domain of the first user's email address), date created | Life of the account | To hold the customer's data apart from others' | **[NOT YET BUILT. Done by hand on request.]** Deleting it cascades to everything the organisation holds, including its audit log. |
| Sign-in link requests | Email address typed, network address, time, hash of the token, time used. Kept even if no account exists for the address. | Until one day after the link expires. A link expires after 15 minutes. | To sign in, and to limit abuse of the form | Housekeeping run |
| Sessions | Hash of the cookie, network address and browser identification at sign-in, times | Until 12 hours without use, or 7 days, or sign-out | To keep a user signed in | Deleted at sign-out, or when next presented after expiry, or by the housekeeping run after 7 days |
| Audit log | Action, user's email address, date, object identifier, network address, browser identification, and a few details such as depth or format. The entry for adding or removing a domain records the domain name. No findings, and no name of any person a finding is about. | Not pruned. **[TO DECIDE: audit log retention period. NOT YET BUILT: deletion after that period.]** | Accountability and investigation of abuse reports | Only when the organisation is deleted |

### Other

| Category | What is kept | How long | Why | How it is deleted |
|---|---|---|---|---|
| Shared cache | Answers from slow public sources: certificate search results and the public catalogue of breaches. Not tied to a customer. | 24 hours | To avoid overloading free public services | Housekeeping run |
| Temporary scan files | Downloaded copies of public repositories, target lists for tools, tool settings that include API keys | Only while the scan runs | Needed by the scanning tools | The directory is deleted when the scan ends, whether it succeeded or failed |
| Reports | Not stored by the hosted service. A report is built from the stored scan each time it is downloaded. | Not applicable | | Downloaded copies are the customer's responsibility |
| Do-not-contact list | Host names, addresses or networks that must not be contacted. Held as a setting of the service, not in the database. | Until the operator of the host withdraws the request | To honour opt-out requests | Operator staff remove the entry |
| Abuse reports, opt-out requests, security reports | The message, our reply, and the action taken. Held outside the service. | **[TO DECIDE]** | To show what was done | **[TO DECIDE]** |
| Service logs | Operational messages in JSON, from the application, the worker and the proxy. The proxy logs requests, including network addresses. Known secrets and common token formats are removed from application logs. | **[TO DECIDE]** | Fault finding | **[TO DECIDE]** |
| Emails sent | Held by the email provider | **[TO DECIDE: depends on provider]** | Delivery | **[TO DECIDE]** |
| Backups | **[TO DECIDE: what is backed up. `docs/operations.md` advises backing up the database volume, encrypting the backup, and keeping the data key apart from it.]** | **[TO DECIDE: backup retention period]** | Recovery | **[TO DECIDE]** |
| Typed statement of authority (command-line tool only) | Name (encrypted), organisation, role, statement, computer name, login name, dates | Valid for 30 days. Deleted by the retention run once it has been expired for longer than the retention period. | Evidence of who authorised an active scan | Retention run. Cascade on domain deletion. |

## 4. What is never stored

- Passwords, password hashes or any value exposed in a breach.
- The logins captured in a malware log.
- The names of websites in a malware log, other than the organisation's own systems and a fixed list of services that control code, infrastructure or funds. Other sites are counted, and only the count is stored.
- A found credential, beyond its first four characters and a short hash.
- Email addresses of people who committed code.
- Content fetched from lookalike domains. They are never contacted.
- Registrant details of any domain.
- Sign-in link tokens and session cookie values. Only their hashes are stored.

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
| Delete the account or the organisation | Everything, including the audit log | **[NOT YET BUILT. Done by hand on request. TO DECIDE: at once, or after a short period in which the customer can change its mind.]** |

### By a member of a customer's staff

The person asks their employer. The employer is the controller and decides. See the [privacy policy](privacy-policy.md), section 13.

The service cannot yet delete the findings about one person only, or leave one address out of future scans. **[NOT YET BUILT.]** Until it can, the customer's option is to delete the domain.

### Limits

- Deletion from the live database is immediate. Copies in backups remain until the backup expires.
- A finding that is deleted will return at the next scan if the source still reports it.
- Reports that the customer has downloaded are outside the service.
- Alerts already sent to Slack, Discord, Telegram or an inbox are outside the service.

## 7. When verification is lost

If an organisation's verification of a domain is withdrawn, nothing is deleted. The hosted service stops scanning the domain. Findings about people that are already stored are withheld: they cannot be opened, and a report with personal details shown cannot be downloaded. They are never marked resolved, so the retention run does not delete them. They stay, encrypted, until the domain is deleted. Lists still show a masked entry for each.

**[NOT YET BUILT: deleting stored findings about people when verification is lost. LAWYER: see README open question 30.]**

## 8. Deletion on termination

When an account is closed, by the customer or by the operator:

1. Scans stop.
2. The customer may download its reports for **[TO DECIDE: export period]**. **[NOT YET BUILT: export of all data.]**
3. All domains and the organisation are deleted. **[NOT YET BUILT: done by hand.]**
4. Backups expire within **[TO DECIDE: backup retention period]**.
5. The operator keeps: abuse reports about the account, and the minimum record needed to show that the agreement existed and ended. **[LAWYER: what may be kept, and for how long.]**

## 9. Encryption keys

Encryption keys are not customer data, but they affect deletion. If a key is lost, everything encrypted only with that key can no longer be read. Keys can be rotated: a new key is put first in the list and the old key stays in the list for as long as data encrypted with it exists. One set of keys protects all customers' data. **[TO DECIDE: rotation schedule and who holds the keys.]**

## 10. Review

This policy is reviewed **[TO DECIDE: review interval]** and whenever a new category of data is added to the software.
